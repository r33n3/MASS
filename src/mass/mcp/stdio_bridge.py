"""MCP stdio-to-HTTP bridge.

Spawns an MCP server subprocess (stdio transport) and exposes it as an
HTTP endpoint so MCPClient.http() can connect to local MCP packages
without needing the runtime installed in the sandbox environment.

Usage:
    bridge = StdioBridge(command="node", args=["server.js"])
    url = await bridge.start()   # http://127.0.0.1:<port>
    # ... use MCPClient.http(base_url=url) ...
    await bridge.stop()

Or as a context manager:
    async with StdioBridge("node", ["server.js"]) as bridge:
        client = MCPClient.http(base_url=bridge.url)
"""

from __future__ import annotations

import asyncio
import glob
import io
import json
import logging
import os
import platform
import shutil
import stat
import tarfile
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Auto-download config ─────────────────────────────────────────────

# Node.js LTS version to download when not found on the system.
# v24 is current LTS (Krypton) with NODE_MODULE_VERSION=137.
_NODE_VERSION = "v24.13.1"
_NODE_BASE_URL = f"https://nodejs.org/dist/{_NODE_VERSION}"

# Where to cache downloaded runtimes
_RUNTIMES_DIR = Path(os.environ.get("MASS_DATA_DIR", "data")) / "runtimes"

# ── Runtime resolution ───────────────────────────────────────────────

# Common install locations by runtime and platform
_WINDOWS_SEARCH_PATHS: dict[str, list[str]] = {
    "node": [
        r"C:\Program Files\nodejs\node.exe",
        r"C:\Program Files (x86)\nodejs\node.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\nodejs\node.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\nodejs\node.exe"),
        # nvm-windows
        os.path.expandvars(r"%APPDATA%\nvm\*\node.exe"),
        # fnm
        os.path.expandvars(r"%LOCALAPPDATA%\fnm_multishells\*\node.exe"),
        # Volta
        os.path.expandvars(r"%LOCALAPPDATA%\Volta\tools\image\node\*\node.exe"),
    ],
    "python": [
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python3*\python.exe"),
        r"C:\Python3*\python.exe",
    ],
    "python3": [
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python3*\python.exe"),
        r"C:\Python3*\python.exe",
    ],
}

_UNIX_SEARCH_PATHS: dict[str, list[str]] = {
    "node": [
        "/usr/local/bin/node",
        "/usr/bin/node",
        os.path.expanduser("~/.nvm/versions/node/*/bin/node"),
        os.path.expanduser("~/.fnm/node-versions/*/installation/bin/node"),
        "/opt/homebrew/bin/node",
    ],
    "python3": [
        "/usr/local/bin/python3",
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
    ],
    "python": [
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ],
}


def resolve_runtime(command: str) -> str:
    """Find the actual executable path for a command.

    Search order:
    1. shutil.which() — already in PATH
    2. Absolute path — user provided full path
    3. Platform-specific install locations (nvm, fnm, Volta, etc.)
    4. MASS cached runtime — previously auto-downloaded
    5. Auto-download — fetch portable Node.js from nodejs.org (node only)

    Returns the resolved path or raises RuntimeError.
    """
    # 1. Already in PATH
    found = shutil.which(command)
    if found:
        return found

    # 2. Absolute path provided
    if os.path.isabs(command) and os.path.isfile(command):
        return command

    # 3. Platform-specific search
    is_windows = platform.system() == "Windows"
    search_map = _WINDOWS_SEARCH_PATHS if is_windows else _UNIX_SEARCH_PATHS
    cmd_key = command.lower().replace(".exe", "")

    candidates = search_map.get(cmd_key, [])
    searched: list[str] = []

    for pattern in candidates:
        matches = glob.glob(pattern)
        if matches:
            matches.sort(reverse=True)
            for match in matches:
                if os.path.isfile(match) and os.access(match, os.X_OK):
                    logger.info("resolve_runtime: %s → %s", command, match)
                    return match
        searched.append(pattern)

    if is_windows and not command.endswith(".exe"):
        found = shutil.which(command + ".exe")
        if found:
            return found

    # 4. Check MASS cached runtimes
    cached = _get_cached_runtime(cmd_key)
    if cached:
        logger.info("resolve_runtime: %s → %s (cached)", command, cached)
        return cached

    # 5. Auto-download (node only)
    if cmd_key == "node":
        logger.info("resolve_runtime: node not found, auto-downloading Node.js %s", _NODE_VERSION)
        downloaded = _download_node()
        if downloaded:
            return downloaded

    searched_str = "\n  ".join(searched) if searched else "(no known paths for this runtime)"
    raise RuntimeError(
        f"Could not find '{command}' executable. "
        f"Searched PATH and:\n  {searched_str}\n"
        f"Install the runtime or provide the full path in the 'command' field."
    )


def _get_cached_runtime(cmd_key: str) -> str | None:
    """Check if a runtime was previously downloaded to the MASS cache."""
    is_windows = platform.system() == "Windows"
    exe = f"{cmd_key}.exe" if is_windows else cmd_key

    # Look for node in the cached runtimes directory
    runtime_dir = _RUNTIMES_DIR / cmd_key
    if not runtime_dir.exists():
        return None

    if is_windows:
        candidate = runtime_dir / exe
    else:
        candidate = runtime_dir / "bin" / exe

    if candidate.is_file() and os.access(str(candidate), os.X_OK):
        return str(candidate)

    return None


def _download_node() -> str | None:
    """Download a portable Node.js binary and cache it.

    Downloads from nodejs.org, extracts the binary, and stores it in
    data/runtimes/node/. Returns the path to the node executable.
    """
    sys = platform.system()
    arch = platform.machine().lower()

    # Map platform/arch to Node.js download naming
    if sys == "Windows":
        arch_name = "x64" if arch in ("amd64", "x86_64", "x64") else "arm64"
        archive_name = f"node-{_NODE_VERSION}-win-{arch_name}"
        url = f"{_NODE_BASE_URL}/{archive_name}.zip"
        exe_path = "node.exe"
    elif sys == "Darwin":
        arch_name = "arm64" if arch == "arm64" else "x64"
        archive_name = f"node-{_NODE_VERSION}-darwin-{arch_name}"
        url = f"{_NODE_BASE_URL}/{archive_name}.tar.gz"
        exe_path = "bin/node"
    elif sys == "Linux":
        arch_name = "arm64" if arch == "aarch64" else "x64"
        archive_name = f"node-{_NODE_VERSION}-linux-{arch_name}"
        url = f"{_NODE_BASE_URL}/{archive_name}.tar.xz"
        exe_path = "bin/node"
    else:
        logger.warning("Auto-download not supported for platform: %s", sys)
        return None

    dest_dir = _RUNTIMES_DIR / "node"

    # Check if already downloaded
    if sys == "Windows":
        node_bin = dest_dir / exe_path
    else:
        node_bin = dest_dir / exe_path

    if node_bin.is_file():
        return str(node_bin)

    # Download
    logger.info("Downloading Node.js %s from %s", _NODE_VERSION, url)
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)

        req = urllib.request.Request(url, headers={"User-Agent": "MASS/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()

        logger.info(
            "Downloaded %.1f MB, extracting to %s",
            len(data) / (1024 * 1024),
            dest_dir,
        )

        # Extract
        if url.endswith(".zip"):
            _extract_zip(data, archive_name, dest_dir)
        elif url.endswith(".tar.gz"):
            _extract_tar(data, archive_name, dest_dir, mode="r:gz")
        elif url.endswith(".tar.xz"):
            _extract_tar(data, archive_name, dest_dir, mode="r:xz")

        # Verify
        if node_bin.is_file():
            # Ensure executable permission on Unix
            if sys != "Windows":
                node_bin.chmod(node_bin.stat().st_mode | stat.S_IEXEC)
            logger.info("Node.js %s installed to %s", _NODE_VERSION, node_bin)
            return str(node_bin)

        logger.error("Node binary not found after extraction at %s", node_bin)
        return None

    except Exception as e:
        logger.error("Failed to download Node.js: %s", e)
        # Clean up partial download
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        return None


def _extract_zip(data: bytes, archive_name: str, dest_dir: Path) -> None:
    """Extract Node.js from a zip archive (Windows)."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.namelist():
            # Strip the top-level directory (e.g., node-v22.14.0-win-x64/)
            if member.startswith(archive_name + "/"):
                rel_path = member[len(archive_name) + 1:]
                if not rel_path:
                    continue
                target = dest_dir / rel_path
                if member.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())


def _extract_tar(
    data: bytes, archive_name: str, dest_dir: Path, mode: str = "r:gz"
) -> None:
    """Extract Node.js from a tar.gz or tar.xz archive (Linux/macOS)."""
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
        for member in tf.getmembers():
            if member.name.startswith(archive_name + "/"):
                rel_path = member.name[len(archive_name) + 1:]
                if not rel_path:
                    continue
                member_copy = tarfile.TarInfo(name=rel_path)
                member_copy.size = member.size
                member_copy.mode = member.mode
                target = dest_dir / rel_path
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    extracted = tf.extractfile(member)
                    if extracted:
                        with open(target, "wb") as dst:
                            dst.write(extracted.read())
                        # Preserve executable permission
                        if member.mode & stat.S_IEXEC:
                            target.chmod(target.stat().st_mode | stat.S_IEXEC)


# ── StdioBridge ──────────────────────────────────────────────────────

class StdioBridge:
    """Bridge an MCP stdio server to HTTP.

    Spawns the subprocess, runs the MCP handshake, and starts a minimal
    HTTP server that forwards JSON-RPC requests to stdin/stdout.
    """

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ):
        self.command = command
        self.args = args or []
        self.env = env
        self.cwd = cwd

        self._process: asyncio.subprocess.Process | None = None
        self._server: asyncio.Server | None = None
        self._port: int | None = None
        self._lock = asyncio.Lock()
        self._session_id = str(uuid.uuid4())
        self._init_result: dict[str, Any] = {}
        self._request_id = 0
        self._started = False

    @property
    def url(self) -> str:
        """Bridge HTTP URL."""
        if self._port is None:
            raise RuntimeError("Bridge not started")
        return f"http://127.0.0.1:{self._port}"

    # ── Lifecycle ─────────────────────────────────────────────────

    # Allowed runtime commands for subprocess execution
    _ALLOWED_COMMANDS = frozenset({
        "node", "npx", "python", "python3", "uvx", "deno", "bun",
        "node.exe", "npx.exe", "python.exe", "python3.exe", "deno.exe", "bun.exe",
    })

    async def start(self) -> str:
        """Start the bridge. Returns the HTTP URL."""
        # Security: only allow known runtime commands to prevent command injection
        cmd_base = os.path.basename(self.command).lower()
        if cmd_base not in self._ALLOWED_COMMANDS and not os.path.isabs(self.command):
            raise ValueError(
                f"Command '{self.command}' is not in the allowed runtimes list: "
                f"{', '.join(sorted(self._ALLOWED_COMMANDS))}. "
                f"Use a full absolute path for custom executables."
            )

        # 1. Resolve runtime
        resolved = resolve_runtime(self.command)
        logger.info("StdioBridge: starting %s %s", resolved, self.args)

        # 2. Spawn subprocess — inject runtime's directory into PATH
        #    so child processes (npm, node-gyp, etc.) can also find it
        spawn_env = os.environ.copy()
        runtime_dir = os.path.dirname(resolved)
        if runtime_dir:
            spawn_env["PATH"] = runtime_dir + os.pathsep + spawn_env.get("PATH", "")
        if self.env:
            spawn_env.update(self.env)

        self._process = await asyncio.create_subprocess_exec(
            resolved,
            *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=spawn_env,
            cwd=self.cwd,
        )

        # Give process a moment to start
        await asyncio.sleep(0.3)

        # Check it didn't die immediately
        if self._process.returncode is not None:
            stderr = ""
            if self._process.stderr:
                stderr = (await self._process.stderr.read()).decode(errors="replace")
            raise RuntimeError(
                f"MCP server process exited immediately (code {self._process.returncode}): {stderr[:500]}"
            )

        # 3. MCP initialize handshake
        self._init_result = await self._send_stdio({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mass-stdio-bridge",
                    "version": "1.0.0",
                },
            },
        })

        # Send initialized notification (no response expected)
        await self._write_stdio({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })

        # 4. Start HTTP server on random port
        self._server = await asyncio.start_server(
            self._handle_http, "127.0.0.1", 0,
        )
        addr = self._server.sockets[0].getsockname()
        self._port = addr[1]
        self._started = True

        logger.info("StdioBridge: listening on http://127.0.0.1:%d", self._port)
        return self.url

    async def stop(self) -> None:
        """Shut down the bridge."""
        if not self._started:
            return

        self._started = False

        # Stop HTTP server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Stop subprocess
        if self._process and self._process.returncode is None:
            try:
                if self._process.stdin:
                    self._process.stdin.close()
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._process.kill()
                    await self._process.wait()
            except ProcessLookupError:
                pass

        self._process = None
        self._port = None
        logger.info("StdioBridge: stopped")

    async def __aenter__(self) -> StdioBridge:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    # ── HTTP handler ──────────────────────────────────────────────

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one HTTP connection from MCPClient.http()."""
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not request_line:
                writer.close()
                return

            # Read headers
            content_length = 0
            while True:
                header_line = await reader.readline()
                if header_line in (b"\r\n", b"\n", b""):
                    break
                header = header_line.decode("utf-8", errors="replace").strip()
                if header.lower().startswith("content-length:"):
                    content_length = int(header.split(":", 1)[1].strip())

            # Read body
            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=30.0,
                )

            # Parse JSON-RPC request
            request = json.loads(body) if body else {}
            method = request.get("method", "")

            # Route request
            if method == "initialize":
                # Return cached init result
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": self._init_result,
                }
            elif method.startswith("notifications/"):
                # notifications/initialized was already sent during bridge
                # init handshake — don't re-send.  Other notifications are
                # forwarded but we swallow any error the server may return
                # (JSON-RPC notifications should NOT get responses, but some
                # servers send one anyway which would corrupt the stdout
                # stream if left unread).
                if method != "notifications/initialized":
                    try:
                        await self._send_stdio_notification(request)
                    except Exception as exc:
                        logger.debug(
                            "StdioBridge: notification %s error (ignored): %s",
                            method, exc,
                        )
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {},
                }
            else:
                # Forward to stdio and get response
                response = await self._forward_to_stdio(request)

            # Send HTTP response
            response_body = json.dumps(response).encode("utf-8")
            http_response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(response_body)}\r\n".encode()
                + f"mcp-session-id: {self._session_id}\r\n".encode()
                + b"Connection: close\r\n"
                + b"\r\n"
                + response_body
            )
            writer.write(http_response)
            await writer.drain()

        except Exception as e:
            # Send error response
            error_body = json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": str(e)},
            }).encode("utf-8")
            error_response = (
                b"HTTP/1.1 500 Internal Server Error\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(error_body)}\r\n".encode()
                + b"Connection: close\r\n"
                + b"\r\n"
                + error_body
            )
            writer.write(error_response)
            await writer.drain()
            logger.warning("StdioBridge HTTP error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Stdio protocol ────────────────────────────────────────────

    async def _forward_to_stdio(self, request: dict) -> dict:
        """Forward a JSON-RPC request to the subprocess and return the response."""
        raw = await self._send_stdio(request)
        # Wrap raw result in JSON-RPC response format
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": raw,
        }

    async def _send_stdio(self, data: dict) -> dict:
        """Send JSON-RPC to stdin, read response from stdout."""
        async with self._lock:
            if not self._process or self._process.returncode is not None:
                stderr_text = ""
                if self._process and self._process.stderr:
                    try:
                        stderr_text = (
                            await asyncio.wait_for(self._process.stderr.read(), timeout=1.0)
                        ).decode(errors="replace")
                    except Exception:
                        pass
                raise RuntimeError(
                    f"MCP server process is not running. stderr: {stderr_text[:500]}"
                )

            line = json.dumps(data) + "\n"
            self._process.stdin.write(line.encode("utf-8"))
            await self._process.stdin.drain()

            # Read response line
            try:
                response_line = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=30.0,
                )
            except asyncio.TimeoutError:
                raise RuntimeError("MCP server did not respond within 30 seconds")

            if not response_line:
                raise RuntimeError("MCP server closed stdout (no response)")

            response = json.loads(response_line.decode("utf-8"))

            if "error" in response:
                raise RuntimeError(f"MCP error: {response['error']}")

            return response.get("result", response)

    async def _write_stdio(self, data: dict) -> None:
        """Write a message to stdin without expecting a response (notifications)."""
        async with self._lock:
            if not self._process or self._process.returncode is not None:
                return
            line = json.dumps(data) + "\n"
            self._process.stdin.write(line.encode("utf-8"))
            await self._process.stdin.drain()

    async def _send_stdio_notification(self, data: dict) -> None:
        """Send a notification and drain any unsolicited response.

        Per JSON-RPC 2.0 spec, notifications (no "id") should NOT receive a
        response.  But some MCP servers respond anyway — if we don't drain
        that response, it corrupts the stdout stream for the next real
        request.  So we write the notification and briefly peek at stdout.
        """
        async with self._lock:
            if not self._process or self._process.returncode is not None:
                return
            line = json.dumps(data) + "\n"
            self._process.stdin.write(line.encode("utf-8"))
            await self._process.stdin.drain()

            # Brief wait to drain any unsolicited response
            try:
                response_line = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=1.0,
                )
                if response_line:
                    logger.debug(
                        "StdioBridge: drained unsolicited notification response: %s",
                        response_line.decode("utf-8", errors="replace").strip()[:200],
                    )
            except asyncio.TimeoutError:
                pass  # Good — no response, as expected per spec

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id


# ── Bridge registry & lifecycle management ───────────────────────────

_active_bridges: dict[str, dict[str, Any]] = {}

_BRIDGE_MAX_AGE_SECONDS = 30 * 60  # 30 minutes safety timeout
_BRIDGE_POLL_INTERVAL = 5  # seconds between job status checks


async def start_bridge(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[str, str]:
    """Start a new bridge and register it.

    Returns (bridge_id, bridge_url).
    """
    bridge = StdioBridge(command=command, args=args, env=env, cwd=cwd)
    url = await bridge.start()

    bridge_id = str(uuid.uuid4())
    _active_bridges[bridge_id] = {
        "bridge": bridge,
        "url": url,
        "job_ids": [],
        "created_at": datetime.now(timezone.utc),
    }

    logger.info("Bridge %s started at %s", bridge_id[:8], url)
    return bridge_id, url


async def stop_bridge(bridge_id: str) -> None:
    """Stop and unregister a bridge."""
    entry = _active_bridges.pop(bridge_id, None)
    if entry:
        bridge: StdioBridge = entry["bridge"]
        await bridge.stop()
        logger.info("Bridge %s stopped", bridge_id[:8])


async def monitor_bridge_jobs(
    bridge_id: str,
    job_ids: list[str],
) -> None:
    """Background coroutine: stop bridge when all related jobs finish.

    Checks job statuses every 5 seconds via Redis. Also enforces a 30-minute
    maximum bridge lifetime as a safety net.
    """
    from mass.api.utils.job_store import JobStore
    store = JobStore("sandbox")

    entry = _active_bridges.get(bridge_id)
    if not entry:
        return

    entry["job_ids"] = job_ids
    start_time = time.monotonic()

    while bridge_id in _active_bridges:
        await asyncio.sleep(_BRIDGE_POLL_INTERVAL)

        # Safety timeout
        elapsed = time.monotonic() - start_time
        if elapsed > _BRIDGE_MAX_AGE_SECONDS:
            logger.warning(
                "Bridge %s exceeded max age (%ds), force stopping",
                bridge_id[:8],
                _BRIDGE_MAX_AGE_SECONDS,
            )
            break

        # Check if all jobs are done (via Redis)
        all_done = True
        for job_id in job_ids:
            job = await store.load(job_id)
            if not job:
                continue
            job_status = job.get("status", "unknown")
            if job_status in ("pending", "running"):
                all_done = False
                break

        if all_done:
            logger.info(
                "Bridge %s: all %d jobs complete, stopping",
                bridge_id[:8],
                len(job_ids),
            )
            break

    await stop_bridge(bridge_id)


async def stop_all_bridges() -> None:
    """Stop all active bridges. Called during shutdown."""
    bridge_ids = list(_active_bridges.keys())
    for bid in bridge_ids:
        await stop_bridge(bid)
