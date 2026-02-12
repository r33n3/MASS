"""Ollama container manager.

Talks to the Ollama REST API to check health, list models, and pull
models on demand. Used by the interrogation flow to auto-setup models
before running adversarial conversations.
"""

import asyncio
import hashlib
import http.client
import json
import logging
import os
import re
import socket
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Timeout for health checks and model listing
_QUICK_TIMEOUT = 10.0
# Timeout for model pulls (large models can take 10+ minutes)
_PULL_TIMEOUT = 1800.0
# Timeout for GGUF model creation (import can take minutes for large files)
_CREATE_TIMEOUT = 600.0

# Docker socket path for container exec
_DOCKER_SOCKET = "/var/run/docker.sock"


def get_ollama_containers() -> dict[str, str]:
    """Return configured Ollama container names keyed by role."""
    return {
        "destination": os.getenv("OLLAMA_CONTAINER_NAME", "mass-ollama"),
        "source": os.getenv("OLLAMA_ATTACKER_CONTAINER_NAME", "mass-ollama-attacker"),
    }


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket (for Docker API)."""

    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost")
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._socket_path)
        self.sock.settimeout(300)


def _docker_exec_sync(
    container: str, cmd: list[str]
) -> tuple[bool, str]:
    """Execute a command in a Docker container via the Docker socket.

    Uses Python stdlib only (http.client + socket). No packages needed.

    Returns:
        Tuple of (success, output_text).
    """
    try:
        # 1. Create exec instance
        conn = _UnixHTTPConnection(_DOCKER_SOCKET)
        body = json.dumps({
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": cmd,
        })
        conn.request(
            "POST",
            f"/v1.44/containers/{container}/exec",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        if resp.status != 201:
            return False, f"Docker exec create failed: {resp.status} {resp.read().decode()}"
        exec_id = json.loads(resp.read())["Id"]

        # 2. Start exec (blocking, captures output)
        conn2 = _UnixHTTPConnection(_DOCKER_SOCKET)
        conn2.request(
            "POST",
            f"/v1.44/exec/{exec_id}/start",
            body=json.dumps({"Detach": False}),
            headers={"Content-Type": "application/json"},
        )
        resp2 = conn2.getresponse()
        raw_output = resp2.read()
        # Docker multiplexes stdout/stderr with 8-byte headers per frame;
        # strip non-printable header bytes for clean text output
        output = raw_output.decode(errors="replace")
        output = re.sub(r"[\x00-\x08]", "", output)

        # 3. Check exit code
        conn3 = _UnixHTTPConnection(_DOCKER_SOCKET)
        conn3.request("GET", f"/v1.44/exec/{exec_id}/json")
        resp3 = conn3.getresponse()
        info = json.loads(resp3.read())
        exit_code = info.get("ExitCode", -1)

        return exit_code == 0, output.strip()
    except FileNotFoundError:
        return False, "Docker socket not found"
    except ConnectionRefusedError:
        return False, "Docker socket connection refused"
    except Exception as e:
        return False, f"Docker exec failed: {e}"


def _build_modelfile(
    gguf_path: str,
    system_prompt: str | None = None,
    parameters: dict[str, Any] | None = None,
) -> str:
    """Build an Ollama Modelfile string."""
    lines = [f"FROM {gguf_path}"]
    if system_prompt:
        escaped = system_prompt.replace('"', '\\"')
        lines.append(f'SYSTEM "{escaped}"')
    if parameters:
        for key, value in parameters.items():
            lines.append(f"PARAMETER {key} {value}")
    return "\n".join(lines)


async def _create_via_docker_exec(
    container: str,
    model_name: str,
    gguf_path: str,
    system_prompt: str | None = None,
    parameters: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Create an Ollama model by exec'ing into the Ollama container.

    This avoids uploading multi-GB files over HTTP since the GGUF file
    is already mounted at the same path inside the Ollama container.
    """
    modelfile = _build_modelfile(gguf_path, system_prompt, parameters)

    # Write Modelfile and run ollama create in one shell command
    # Use printf to avoid echo interpretation issues
    escaped_modelfile = modelfile.replace("'", "'\\''")
    cmd = [
        "sh", "-c",
        f"printf '%s' '{escaped_modelfile}' > /tmp/mass_modelfile "
        f"&& ollama create {model_name} -f /tmp/mass_modelfile "
        f"&& rm -f /tmp/mass_modelfile",
    ]

    logger.info("Creating model %s via Docker exec (fast path)...", model_name)
    success, output = await asyncio.to_thread(
        _docker_exec_sync, container, cmd
    )

    if success:
        logger.info("Model %s created via Docker exec", model_name)
        return True, f"Model {model_name} created from {gguf_path}"
    else:
        logger.warning("Docker exec failed: %s", output)
        return False, output


def get_ollama_hosts() -> dict[str, str]:
    """Return configured Ollama host URLs keyed by role."""
    return {
        "destination": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        "source": os.getenv("OLLAMA_ATTACKER_HOST", "http://localhost:11435"),
    }


async def check_health(host_url: str) -> bool:
    """Check if an Ollama instance is reachable.

    Args:
        host_url: Ollama server URL (e.g. http://ollama:11434).

    Returns:
        True if Ollama is responsive.
    """
    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.get(f"{host_url.rstrip('/')}/api/tags")
            resp.raise_for_status()
            return True
    except Exception as e:
        logger.debug("Ollama health check failed for %s: %s", host_url, e)
        return False


async def list_models(host_url: str) -> list[dict]:
    """List models available on an Ollama instance.

    Returns:
        List of model dicts with name, size, modified_at, etc.
    """
    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.get(f"{host_url.rstrip('/')}/api/tags")
            resp.raise_for_status()
            return resp.json().get("models", [])
    except Exception as e:
        logger.warning("Failed to list models from %s: %s", host_url, e)
        return []


async def is_model_available(host_url: str, model_name: str) -> bool:
    """Check if a specific model is pulled on an Ollama instance.

    Handles both exact matches (qwen3:8b) and base name matches (qwen3).
    """
    models = await list_models(host_url)
    # Normalize: Ollama returns names like "qwen3:8b", user might pass "qwen3:8b" or "qwen3"
    for m in models:
        name = m.get("name", "")
        if name == model_name or name.startswith(f"{model_name}:"):
            return True
        # Also check without tag: "qwen3:8b" matches query "qwen3:8b"
        if model_name == name.split(":")[0]:
            return True
    return False


def _normalize_for_matching(name: str) -> str:
    """Normalize a model name for fuzzy matching.

    Strips extensions, quantization tags, and lowercases.
    'Hermes-2-Pro-Mistral-7B.Q4_K_M.gguf' → 'hermes-2-pro-mistral-7b'
    'hermes-2-pro-mistral-7b:latest'       → 'hermes-2-pro-mistral-7b'
    """
    # Remove file extensions
    for ext in (".gguf", ".bin", ".safetensors"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
    # Remove quantization suffixes like .Q4_K_M, .Q5_K_S, etc.
    name = re.sub(r"[._]Q\d+_K_[A-Z]+$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[._]Q\d+_[A-Z]+$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[._]F\d+$", "", name, flags=re.IGNORECASE)
    # Remove :tag suffix
    name = name.split(":")[0]
    # Lowercase and normalize separators
    return name.lower().replace("_", "-").strip("-")


async def find_matching_model(host_url: str, model_name: str) -> str | None:
    """Find a matching Ollama model by fuzzy-matching against loaded models.

    Useful when the user selects a GGUF filename from discovered files but the
    Ollama instance has the model under its registry name.

    Returns the Ollama model name if found, None otherwise.
    """
    models = await list_models(host_url)
    query = _normalize_for_matching(model_name)

    for m in models:
        tag = m.get("name", "")
        candidate = _normalize_for_matching(tag)
        # Exact normalized match
        if candidate == query:
            logger.info("Fuzzy match: '%s' → '%s'", model_name, tag)
            return tag
        # One contains the other (handles partial names)
        if candidate in query or query in candidate:
            logger.info("Fuzzy match (substring): '%s' → '%s'", model_name, tag)
            return tag

    return None


async def pull_model(host_url: str, model_name: str) -> tuple[bool, str]:
    """Pull a model on an Ollama instance.

    This is a blocking call that waits for the pull to complete.
    Can take several minutes for large models.

    Args:
        host_url: Ollama server URL.
        model_name: Model to pull (e.g. "qwen3:8b").

    Returns:
        Tuple of (success: bool, message: str).
    """
    url = f"{host_url.rstrip('/')}/api/pull"
    payload = {"name": model_name, "stream": False}

    logger.info("Pulling model %s on %s (this may take a while)...", model_name, host_url)

    try:
        async with httpx.AsyncClient(timeout=_PULL_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "unknown")
            logger.info("Model pull complete: %s — %s", model_name, status)
            return True, f"Model {model_name} ready ({status})"
    except httpx.TimeoutException:
        msg = f"Model pull timed out for {model_name} on {host_url} (>{_PULL_TIMEOUT}s)"
        logger.error(msg)
        return False, msg
    except httpx.ConnectError:
        msg = f"Cannot reach Ollama at {host_url}"
        logger.error(msg)
        return False, msg
    except Exception as e:
        msg = f"Failed to pull {model_name} on {host_url}: {e}"
        logger.error(msg)
        return False, msg


async def ensure_model_ready(
    host_url: str, model_name: str
) -> tuple[bool, str, str | None]:
    """Ensure a model is available on an Ollama instance.

    Checks health, checks if model exists (with fuzzy matching), pulls if needed.

    Args:
        host_url: Ollama server URL.
        model_name: Model to ensure is ready (can be GGUF filename or Ollama tag).

    Returns:
        Tuple of (success, message, resolved_name).
        resolved_name is the actual Ollama tag to use for API calls (may differ
        from model_name if fuzzy matching resolved a GGUF filename).
    """
    # 1. Health check
    healthy = await check_health(host_url)
    if not healthy:
        return False, f"Ollama not reachable at {host_url}", None

    # 2. Check if model is already available (exact match)
    available = await is_model_available(host_url, model_name)
    if available:
        logger.info("Model %s already available on %s", model_name, host_url)
        return True, f"Model {model_name} ready", model_name

    # 3. Fuzzy match: GGUF filenames → Ollama registry names
    matched = await find_matching_model(host_url, model_name)
    if matched:
        logger.info("Model %s resolved to %s via fuzzy match on %s", model_name, matched, host_url)
        return True, f"Model {model_name} ready (matched: {matched})", matched

    # 4. Pull the model as last resort (may take minutes for large models)
    logger.info("Model %s not found on %s, pulling...", model_name, host_url)
    ok, msg = await pull_model(host_url, model_name)
    return ok, msg, model_name if ok else None


def sanitize_model_name(name: str) -> str:
    """Convert a filename or arbitrary string to a valid Ollama model name.

    Ollama model names should be lowercase, alphanumeric with hyphens.
    Example: 'Hermes-2-Pro-Mistral-7B.Q4_K_M.gguf' → 'hermes-2-pro-mistral-7b-q4-k-m'
    """
    # Remove file extension
    if "." in name:
        name = name.rsplit(".", 1)[0]
    name = name.lower().strip()
    name = re.sub(r"[^a-z0-9\-]", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return name or "custom-model"


def _sha256_file(path: str) -> str:
    """Compute SHA256 hash of a file incrementally (memory-efficient)."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


async def _ensure_blob(host_url: str, gguf_path: str) -> tuple[str, str | None]:
    """Upload GGUF file to Ollama blob storage if not already present.

    Returns:
        Tuple of (digest_string, error_message_or_none).
    """
    logger.info("Computing SHA256 of %s ...", gguf_path)
    digest = _sha256_file(gguf_path)
    digest_str = f"sha256:{digest}"

    base = host_url.rstrip("/")
    blob_url = f"{base}/api/blobs/{digest_str}"

    # Check if blob already exists
    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.head(blob_url)
            if resp.status_code == 200:
                logger.info("Blob already exists: %s", digest_str[:20])
                return digest_str, None
    except Exception:
        pass  # Proceed to upload

    # Stream-upload the file using sync client in a thread (httpx AsyncClient
    # doesn't support streaming content in all versions)
    file_size = Path(gguf_path).stat().st_size
    logger.info(
        "Uploading blob %s (%d MB) to %s ...",
        digest_str[:20], file_size // (1024 * 1024), host_url,
    )

    def _upload_sync() -> tuple[int, str]:
        def _stream():
            with open(gguf_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    yield chunk

        with httpx.Client(timeout=httpx.Timeout(_CREATE_TIMEOUT)) as client:
            r = client.post(blob_url, content=_stream())
            return r.status_code, r.text

    try:
        status_code, resp_text = await asyncio.to_thread(_upload_sync)
        if status_code not in (200, 201):
            return "", f"Blob upload failed: {status_code} {resp_text}"
        logger.info("Blob uploaded: %s", digest_str[:20])
        return digest_str, None
    except httpx.TimeoutException:
        return "", f"Blob upload timed out (>{_CREATE_TIMEOUT}s)"
    except Exception as e:
        return "", f"Blob upload failed: {e}"


async def create_from_gguf(
    host_url: str,
    model_name: str,
    gguf_path: str,
    system_prompt: str | None = None,
    parameters: dict[str, Any] | None = None,
    instance: str = "destination",
) -> tuple[bool, str]:
    """Create an Ollama model from a local GGUF file.

    Tries Docker exec first (instant, no file transfer) then falls back
    to blob upload via the REST API.

    Args:
        host_url: Ollama server URL.
        model_name: Name for the created model.
        gguf_path: Absolute path to the GGUF file (shared volume mount).
        system_prompt: Optional system prompt to embed in the model.
        parameters: Optional Ollama parameters (temperature, num_ctx, etc.).
        instance: Ollama instance role ("destination" or "source").

    Returns:
        Tuple of (success: bool, message: str).
    """
    logger.info(
        "Creating model %s from %s on %s ...",
        model_name, gguf_path, host_url,
    )

    # Fast path: Docker exec (file already on disk in Ollama container)
    if Path(_DOCKER_SOCKET).exists():
        containers = get_ollama_containers()
        container = containers.get(instance, containers["destination"])
        success, msg = await _create_via_docker_exec(
            container, model_name, gguf_path, system_prompt, parameters
        )
        if success:
            return True, msg
        logger.warning(
            "Docker exec fast path failed for %s, falling back to blob upload: %s",
            model_name, msg,
        )

    # Slow path: Upload blob via REST API then create model
    digest_str, err = await _ensure_blob(host_url, gguf_path)
    if err:
        logger.error("Blob upload failed: %s", err)
        return False, err

    filename = Path(gguf_path).name
    url = f"{host_url.rstrip('/')}/api/create"
    payload: dict[str, Any] = {
        "model": model_name,
        "files": {filename: digest_str},
        "stream": False,
    }
    if system_prompt:
        payload["system"] = system_prompt
    if parameters:
        payload["parameters"] = parameters

    try:
        async with httpx.AsyncClient(timeout=_CREATE_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            logger.info("Model %s created via blob upload", model_name)
            return True, f"Model {model_name} created from {gguf_path}"
    except httpx.TimeoutException:
        msg = f"Model creation timed out for {model_name} (>{_CREATE_TIMEOUT}s)"
        logger.error(msg)
        return False, msg
    except httpx.ConnectError:
        msg = f"Cannot reach Ollama at {host_url}"
        logger.error(msg)
        return False, msg
    except httpx.HTTPStatusError as e:
        msg = f"Ollama rejected model creation: {e.response.text}"
        logger.error(msg)
        return False, msg
    except Exception as e:
        msg = f"Failed to create model {model_name}: {e}"
        logger.error(msg)
        return False, msg


async def delete_model(host_url: str, model_name: str) -> tuple[bool, str]:
    """Delete a model from an Ollama instance.

    Args:
        host_url: Ollama server URL.
        model_name: Model to delete.

    Returns:
        Tuple of (success: bool, message: str).
    """
    url = f"{host_url.rstrip('/')}/api/delete"
    payload = {"name": model_name}

    logger.info("Deleting model %s from %s", model_name, host_url)

    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.request("DELETE", url, json=payload)
            resp.raise_for_status()
            logger.info("Model %s deleted", model_name)
            return True, f"Model {model_name} deleted"
    except httpx.HTTPStatusError as e:
        msg = f"Failed to delete {model_name}: {e.response.text}"
        logger.warning(msg)
        return False, msg
    except Exception as e:
        msg = f"Failed to delete {model_name}: {e}"
        logger.warning(msg)
        return False, msg


async def show_model(host_url: str, model_name: str) -> dict | None:
    """Get detailed information about a loaded model.

    Args:
        host_url: Ollama server URL.
        model_name: Model to inspect.

    Returns:
        Model info dict or None if not found.
    """
    url = f"{host_url.rstrip('/')}/api/show"
    payload = {"name": model_name}

    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None
