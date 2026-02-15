"""Docker container management for MCP server package auditing.

Spins up MCP server packages (npm/pip) in isolated Docker containers,
connects a stdio-to-HTTP bridge, and exposes the server for security
testing by the existing MCPInterrogator pipeline.

Uses the raw Docker Engine API via Unix socket — same pattern as
``ollama_manager.py``.  No Docker SDK or CLI required.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import re
import socket
import time
from typing import Any
from uuid import uuid4

import httpx

logger = logging.getLogger(__name__)

_DOCKER_SOCKET = "/var/run/docker.sock"
_DOCKER_API_VERSION = "v1.44"

# Bridge listens on this port inside the container
_BRIDGE_PORT = 3000

# Default resource limits
_DEFAULT_MEMORY_LIMIT = 512 * 1024 * 1024  # 512 MB
_DEFAULT_CPU_PERIOD = 100_000
_DEFAULT_CPU_QUOTA = 100_000  # 1 CPU core

# Images per runtime
_RUNTIME_IMAGES: dict[str, str] = {
    "npx": "node:20-slim",
    "npm": "node:20-slim",
    "pip": "python:3.12-slim",
    "uvx": "python:3.12-slim",
    "command": "node:20-slim",
}


# ── Docker socket helpers ──────────────────────────────────────────────


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket (for Docker API)."""

    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost")
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._socket_path)
        self.sock.settimeout(300)


def _docker_api(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    timeout: int = 60,
) -> tuple[int, Any]:
    """Make a Docker Engine API call via Unix socket.

    Returns (status_code, parsed_json_or_text).
    """
    conn = _UnixHTTPConnection(_DOCKER_SOCKET)
    conn.timeout = timeout

    headers: dict[str, str] = {}
    encoded_body: str | None = None
    if body is not None:
        encoded_body = json.dumps(body)
        headers["Content-Type"] = "application/json"

    full_path = f"/{_DOCKER_API_VERSION}{path}"
    conn.request(method, full_path, body=encoded_body, headers=headers)

    resp = conn.getresponse()
    raw = resp.read()
    status = resp.status

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        data = raw.decode(errors="replace")

    conn.close()
    return status, data


def _get_api_container_id() -> str | None:
    """Detect the container ID of the API container (ourselves).

    Tries hostname first (Docker sets hostname = container ID by default),
    then falls back to cgroup parsing.
    """
    # Method 1: hostname (most reliable in Docker)
    hostname = os.environ.get("HOSTNAME", "")
    if hostname and len(hostname) >= 12 and re.match(r"^[a-f0-9]+$", hostname):
        return hostname

    # Method 2: /proc/self/cgroup
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                parts = line.strip().split("/")
                if len(parts) > 2:
                    cid = parts[-1]
                    if len(cid) >= 12 and re.match(r"^[a-f0-9]+$", cid):
                        return cid
    except FileNotFoundError:
        pass

    # Method 3: /proc/self/mountinfo
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                match = re.search(r"/docker/containers/([a-f0-9]{12,})", line)
                if match:
                    return match.group(1)
    except FileNotFoundError:
        pass

    return None


def _get_api_network() -> str | None:
    """Detect the Docker network the API container is on.

    Returns the network name so audit containers can join it for DNS resolution.
    """
    api_id = _get_api_container_id()
    if not api_id:
        return None
    try:
        status, data = _docker_api("GET", f"/containers/{api_id}/json")
        if status == 200 and isinstance(data, dict):
            networks = data.get("NetworkSettings", {}).get("Networks", {})
            # Return the first network (usually the compose project network)
            for name in networks:
                return name
    except Exception:
        pass
    return None


def docker_available() -> bool:
    """Check whether the Docker socket is accessible."""
    try:
        status, _ = _docker_api("GET", "/_ping")
        return status == 200
    except Exception:
        return False


# ── Bridge scripts ─────────────────────────────────────────────────────


def _bridge_script_js() -> str:
    """Embedded Node.js stdio-to-HTTP bridge.

    Spawns the MCP server as a child process, proxies JSON-RPC over HTTP.
    """
    return r"""
const http = require('http');
const { spawn } = require('child_process');

const cmd = process.argv[2];
const args = process.argv.slice(3);
let buffer = '';
const pending = {};

const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'] });
child.stdout.on('data', d => {
    buffer += d.toString();
    let nl;
    while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        try {
            const msg = JSON.parse(line);
            if (msg.id && pending[msg.id]) {
                pending[msg.id](msg);
                delete pending[msg.id];
            }
        } catch {}
    }
});
child.on('exit', code => { console.error('MCP server exited:', code); process.exit(code || 1); });

const server = http.createServer((req, res) => {
    if (req.method === 'GET') {
        res.writeHead(200, {'Content-Type':'application/json'});
        res.end('{"status":"ok"}');
        return;
    }
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
        try {
            const rpc = JSON.parse(body);
            if (!rpc.id) {
                child.stdin.write(JSON.stringify(rpc) + '\n');
                res.writeHead(202);
                res.end();
                return;
            }
            const p = new Promise(resolve => { pending[rpc.id] = resolve; });
            child.stdin.write(JSON.stringify(rpc) + '\n');
            const timer = setTimeout(() => {
                if (pending[rpc.id]) {
                    delete pending[rpc.id];
                    res.writeHead(504, {'Content-Type':'application/json'});
                    res.end(JSON.stringify({jsonrpc:'2.0',id:rpc.id,error:{code:-32000,message:'Timeout'}}));
                }
            }, 30000);
            p.then(result => {
                clearTimeout(timer);
                res.writeHead(200, {'Content-Type':'application/json'});
                res.end(JSON.stringify(result));
            });
        } catch(e) {
            res.writeHead(400, {'Content-Type':'application/json'});
            res.end(JSON.stringify({error: e.message}));
        }
    });
});
server.listen(3000, '0.0.0.0', () => console.log('Bridge ready on :3000'));
""".strip()


def _bridge_script_py() -> str:
    """Embedded Python stdio-to-HTTP bridge.

    Same concept as JS version, but runs in Python containers.
    """
    return r"""
import json, subprocess, sys, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

cmd = sys.argv[1:]
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=sys.stderr, text=True, bufsize=1)
pending = {}
lock = threading.Lock()

def reader():
    for line in proc.stdout:
        line = line.strip()
        if not line: continue
        try:
            msg = json.loads(line)
            mid = msg.get('id')
            if mid and mid in pending:
                with lock:
                    ev = pending.pop(mid)
                    ev['result'] = msg
                    ev['event'].set()
        except Exception: pass

threading.Thread(target=reader, daemon=True).start()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0)))
        rpc = json.loads(body)
        rid = rpc.get('id')
        if not rid:
            proc.stdin.write(json.dumps(rpc)+'\n'); proc.stdin.flush()
            self.send_response(202); self.end_headers(); return
        ev = threading.Event()
        entry = {'event': ev, 'result': None}
        with lock: pending[rid] = entry
        proc.stdin.write(json.dumps(rpc)+'\n'); proc.stdin.flush()
        if not ev.wait(timeout=30):
            with lock: pending.pop(rid, None)
            self.send_response(504)
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'jsonrpc':'2.0','id':rid,
                'error':{'code':-32000,'message':'Timeout'}}).encode())
            return
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps(entry['result']).encode())

print('Bridge ready on :3000', flush=True)
HTTPServer(('0.0.0.0', 3000), H).serve_forever()
""".strip()


# ── Container command builders ─────────────────────────────────────────


def _build_container_cmd(
    package: str,
    runtime: str,
    bridge_file: str,
    command: str | None = None,
    args: list[str] | None = None,
) -> list[str]:
    """Build the shell command that installs the package and starts the bridge."""
    args_str = " ".join(args) if args else ""

    if runtime == "npx":
        # npx auto-installs and runs
        server_cmd = f"npx --yes {package} {args_str}".strip()
        return [
            "sh", "-c",
            f"cat > /tmp/bridge.js << 'BRIDGEOF'\n{_bridge_script_js()}\nBRIDGEOF\n"
            f"node /tmp/bridge.js {server_cmd}",
        ]

    elif runtime == "npm":
        # Install globally then run
        server_cmd = f"{package} {args_str}".strip()
        return [
            "sh", "-c",
            f"npm install -g {package} && "
            f"cat > /tmp/bridge.js << 'BRIDGEOF'\n{_bridge_script_js()}\nBRIDGEOF\n"
            f"node /tmp/bridge.js {server_cmd}",
        ]

    elif runtime == "pip":
        server_cmd = f"python -m {package} {args_str}".strip()
        if command:
            server_cmd = f"{command} {args_str}".strip()
        return [
            "sh", "-c",
            f"pip install {package} && "
            f"cat > /tmp/bridge.py << 'BRIDGEOF'\n{_bridge_script_py()}\nBRIDGEOF\n"
            f"python /tmp/bridge.py {server_cmd}",
        ]

    elif runtime == "uvx":
        server_cmd = f"uvx {package} {args_str}".strip()
        return [
            "sh", "-c",
            f"pip install uv && "
            f"cat > /tmp/bridge.py << 'BRIDGEOF'\n{_bridge_script_py()}\nBRIDGEOF\n"
            f"python /tmp/bridge.py {server_cmd}",
        ]

    elif runtime == "command":
        if not command:
            raise ValueError("Custom command is required when runtime='command'")
        server_cmd = f"{command} {args_str}".strip()
        # Guess bridge type from command
        if "python" in command.lower():
            return [
                "sh", "-c",
                f"cat > /tmp/bridge.py << 'BRIDGEOF'\n{_bridge_script_py()}\nBRIDGEOF\n"
                f"python /tmp/bridge.py {server_cmd}",
            ]
        return [
            "sh", "-c",
            f"cat > /tmp/bridge.js << 'BRIDGEOF'\n{_bridge_script_js()}\nBRIDGEOF\n"
            f"node /tmp/bridge.js {server_cmd}",
        ]

    else:
        raise ValueError(f"Unsupported runtime: {runtime}")


# ── MCPAuditContainer ──────────────────────────────────────────────────


class MCPAuditContainer:
    """Manages lifecycle of a sandboxed MCP server container for auditing.

    Usage::

        container = MCPAuditContainer("@coingecko/mcp-server", runtime="npx")
        base_url = await container.start()
        # ... run MCPInterrogator against base_url ...
        await container.stop()
    """

    def __init__(
        self,
        package: str,
        runtime: str = "npx",
        env: dict[str, str] | None = None,
        timeout: int = 600,
        command: str | None = None,
        args: list[str] | None = None,
        allow_network: bool = True,
    ) -> None:
        self.package = package
        self.runtime = runtime
        self.env = env or {}
        self.timeout = timeout
        self.command = command
        self.args = args or []
        self.allow_network = allow_network

        self._audit_id = str(uuid4())[:12]
        self._container_name = f"mass-audit-{self._audit_id}"
        self._network_name = f"mass-audit-net-{self._audit_id}"
        self._container_id: str | None = None
        self._network_id: str | None = None
        self._api_container_id: str | None = None
        self._api_network: str | None = None
        self._started = False

    @property
    def container_name(self) -> str:
        return self._container_name

    async def start(self) -> str:
        """Create network + container, install package, start bridge.

        Returns the HTTP base URL to connect MCPClient to.
        """
        if not docker_available():
            raise RuntimeError(
                "Docker socket not available at /var/run/docker.sock. "
                "Containerized MCP auditing requires Docker access."
            )

        self._api_container_id = _get_api_container_id()
        self._api_network = _get_api_network()

        try:
            # 1. Create isolated audit network
            await self._create_network()

            # 2. Pull image
            image = _RUNTIME_IMAGES.get(self.runtime, "node:20-slim")
            await self._pull_image(image)

            # 3. Create container (on the audit network)
            await self._create_container(image)

            # 4. Start container
            await self._start_container()

            # 5. Connect audit container to the API's network for DNS resolution
            if self._api_network:
                await self._connect_container_to_api_network()

            # 6. Wait for bridge to be ready
            base_url = f"http://{self._container_name}:{_BRIDGE_PORT}"
            await self._wait_for_ready(base_url)

            self._started = True
            logger.info(
                "MCP audit container started: %s → %s",
                self._container_name, base_url,
            )
            return base_url

        except Exception:
            # Clean up on failure
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop container, disconnect network, remove container + network."""
        errors: list[str] = []

        # 1. Stop container
        if self._container_id:
            try:
                await asyncio.to_thread(
                    _docker_api, "POST",
                    f"/containers/{self._container_id}/stop",
                    {"t": 5},
                )
            except Exception as e:
                errors.append(f"stop container: {e}")

        # 2. Disconnect audit container from API network
        if self._container_id and self._api_network:
            try:
                # Find the API network ID
                net_status, net_data = await asyncio.to_thread(
                    _docker_api, "GET", f"/networks/{self._api_network}",
                )
                if net_status == 200 and isinstance(net_data, dict):
                    api_net_id = net_data.get("Id", "")
                    if api_net_id:
                        await asyncio.to_thread(
                            _docker_api, "POST",
                            f"/networks/{api_net_id}/disconnect",
                            {"Container": self._container_id, "Force": True},
                        )
            except Exception as e:
                errors.append(f"disconnect from API network: {e}")

        # 3. Remove container
        if self._container_id:
            try:
                await asyncio.to_thread(
                    _docker_api, "DELETE",
                    f"/containers/{self._container_id}?force=true",
                )
            except Exception as e:
                errors.append(f"remove container: {e}")

        # 4. Remove network
        if self._network_id:
            try:
                await asyncio.to_thread(
                    _docker_api, "DELETE",
                    f"/networks/{self._network_id}",
                )
            except Exception as e:
                errors.append(f"remove network: {e}")

        if errors:
            logger.warning("Cleanup errors for %s: %s", self._container_name, "; ".join(errors))

        self._started = False
        self._container_id = None
        self._network_id = None
        logger.info("MCP audit container cleaned up: %s", self._container_name)

    async def get_logs(self, tail: int = 200) -> str:
        """Fetch container logs for debugging."""
        if not self._container_id:
            return ""
        try:
            status, data = await asyncio.to_thread(
                _docker_api, "GET",
                f"/containers/{self._container_id}/logs?stdout=true&stderr=true&tail={tail}",
            )
            if isinstance(data, str):
                # Strip Docker log frame headers (8-byte prefix per line)
                return re.sub(r"[\x00-\x08]", "", data)
            return str(data)
        except Exception as e:
            return f"Failed to get logs: {e}"

    # ── Internal lifecycle methods ─────────────────────────────────────

    async def _create_network(self) -> None:
        """Create an isolated Docker bridge network for this audit."""
        status, data = await asyncio.to_thread(
            _docker_api, "POST", "/networks/create",
            {
                "Name": self._network_name,
                "Driver": "bridge",
                "Internal": not self.allow_network,
                "Labels": {
                    "mass.audit": "true",
                    "mass.audit.id": self._audit_id,
                },
            },
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create network: {status} {data}")
        self._network_id = data.get("Id", "")
        logger.debug("Created audit network: %s (%s)", self._network_name, self._network_id[:12])

    async def _pull_image(self, image: str) -> None:
        """Pull the base image if not already available."""
        # Check if image exists locally
        tag = image.replace(":", "/")
        check_status, _ = await asyncio.to_thread(
            _docker_api, "GET", f"/images/{image}/json",
        )
        if check_status == 200:
            logger.debug("Image %s already available", image)
            return

        # Pull image
        logger.info("Pulling image %s ...", image)
        status, data = await asyncio.to_thread(
            _docker_api, "POST",
            f"/images/create?fromImage={image.split(':')[0]}&tag={image.split(':')[1] if ':' in image else 'latest'}",
            timeout=300,
        )
        if status != 200:
            raise RuntimeError(f"Failed to pull image {image}: {status} {data}")
        logger.info("Image %s pulled successfully", image)

    async def _create_container(self, image: str) -> None:
        """Create the audit container with the bridge + package."""
        cmd = _build_container_cmd(
            self.package, self.runtime, "/tmp/bridge",
            command=self.command, args=self.args,
        )

        # Build environment list
        env_list = [f"{k}={v}" for k, v in self.env.items()]

        container_config: dict[str, Any] = {
            "Image": image,
            "Cmd": cmd,
            "Env": env_list,
            "ExposedPorts": {f"{_BRIDGE_PORT}/tcp": {}},
            "HostConfig": {
                "Memory": _DEFAULT_MEMORY_LIMIT,
                "CpuPeriod": _DEFAULT_CPU_PERIOD,
                "CpuQuota": _DEFAULT_CPU_QUOTA,
                "NetworkMode": self._network_name,
                "AutoRemove": False,
            },
            "Labels": {
                "mass.audit": "true",
                "mass.audit.id": self._audit_id,
                "mass.audit.package": self.package,
                "mass.audit.runtime": self.runtime,
            },
        }

        status, data = await asyncio.to_thread(
            _docker_api, "POST",
            f"/containers/create?name={self._container_name}",
            container_config,
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create container: {status} {data}")

        self._container_id = data.get("Id", "")
        logger.debug("Created audit container: %s (%s)", self._container_name, self._container_id[:12])

    async def _start_container(self) -> None:
        """Start the audit container."""
        status, data = await asyncio.to_thread(
            _docker_api, "POST",
            f"/containers/{self._container_id}/start",
        )
        if status not in (200, 204):
            raise RuntimeError(f"Failed to start container: {status} {data}")
        logger.debug("Started audit container: %s", self._container_name)

    async def _connect_container_to_api_network(self) -> None:
        """Connect the audit container to the API's network for DNS resolution.

        This ensures the API container can resolve the audit container's hostname,
        since they'll share the same Docker network.
        """
        if not self._api_network or not self._container_id:
            return

        # Find the network ID for the API's network
        status, data = await asyncio.to_thread(
            _docker_api, "GET",
            f"/networks/{self._api_network}",
        )
        if status != 200:
            logger.warning("Could not find API network %s: %s", self._api_network, data)
            return

        api_network_id = data.get("Id", "") if isinstance(data, dict) else ""
        if not api_network_id:
            return

        status, data = await asyncio.to_thread(
            _docker_api, "POST",
            f"/networks/{api_network_id}/connect",
            {"Container": self._container_id},
        )
        if status not in (200, 204):
            logger.warning(
                "Failed to connect audit container to API network %s: %s %s",
                self._api_network, status, data,
            )
        else:
            logger.debug("Connected audit container to API network: %s", self._api_network)

    async def _wait_for_ready(self, base_url: str, max_wait: int = 120) -> None:
        """Poll the bridge health endpoint until it responds."""
        start = time.monotonic()
        last_error = ""

        while time.monotonic() - start < max_wait:
            # Check container is still running
            c_status, c_data = await asyncio.to_thread(
                _docker_api, "GET",
                f"/containers/{self._container_id}/json",
            )
            if c_status == 200:
                state = c_data.get("State", {})
                if not state.get("Running", False):
                    logs = await self.get_logs(tail=50)
                    raise RuntimeError(
                        f"Container exited before bridge was ready. "
                        f"Exit code: {state.get('ExitCode', '?')}. "
                        f"Logs:\n{logs}"
                    )

            # Try to reach the bridge
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(base_url)
                    if resp.status_code == 200:
                        logger.info("Bridge ready at %s (took %.1fs)", base_url, time.monotonic() - start)
                        return
            except Exception as e:
                last_error = str(e)

            await asyncio.sleep(2)

        logs = await self.get_logs(tail=30)
        raise RuntimeError(
            f"Bridge did not become ready within {max_wait}s. "
            f"Last error: {last_error}. Logs:\n{logs}"
        )


# ── Orphan cleanup ─────────────────────────────────────────────────────


async def cleanup_orphaned_containers(max_age_seconds: int = 900) -> int:
    """Remove any mass-audit containers older than max_age_seconds.

    Called periodically or on startup to clean up leaked containers.
    """
    cleaned = 0
    try:
        status, data = await asyncio.to_thread(
            _docker_api, "GET",
            '/containers/json?filters={"label":["mass.audit=true"]}',
        )
        if status != 200 or not isinstance(data, list):
            return 0

        import datetime

        now = datetime.datetime.utcnow()
        for container in data:
            created_str = container.get("Created", 0)
            if isinstance(created_str, (int, float)):
                created = datetime.datetime.utcfromtimestamp(created_str)
            else:
                continue

            age = (now - created).total_seconds()
            if age > max_age_seconds:
                cid = container.get("Id", "")
                name = (container.get("Names") or ["?"])[0]
                logger.warning("Cleaning up orphaned audit container: %s (age: %ds)", name, int(age))
                await asyncio.to_thread(_docker_api, "POST", f"/containers/{cid}/stop", {"t": 2})
                await asyncio.to_thread(_docker_api, "DELETE", f"/containers/{cid}?force=true")
                cleaned += 1

        # Also clean up orphaned networks
        net_status, net_data = await asyncio.to_thread(
            _docker_api, "GET",
            '/networks?filters={"label":["mass.audit=true"]}',
        )
        if net_status == 200 and isinstance(net_data, list):
            for network in net_data:
                containers = network.get("Containers", {})
                if not containers:
                    net_id = network.get("Id", "")
                    net_name = network.get("Name", "?")
                    logger.info("Removing orphaned audit network: %s", net_name)
                    await asyncio.to_thread(_docker_api, "DELETE", f"/networks/{net_id}")

    except Exception as e:
        logger.warning("Orphan cleanup failed: %s", e)

    return cleaned
