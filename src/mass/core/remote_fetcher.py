"""Remote target fetching — unified download logic for all source types.

Handles importing scan targets from:
- Host OS paths (Windows/Linux/Mac) via Docker API copy
- S3 buckets via boto3
- Azure Blob Storage via azure-storage-blob
- Google Cloud Storage via google-cloud-storage
- Git remotes (any host, not just GitHub) via subprocess git
- HTTP archives (.zip, .tar.gz) via httpx

All downloads land in the configured ``downloads_dir`` (``/app/downloads/``),
except git clones which go to ``github_clones_dir`` (``/app/github_clones/``).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Source type detection ─────────────────────────────────────────────

SourceType = Literal[
    "host_path", "s3", "azure_blob", "gcs",
    "git", "http_archive",
]


def detect_source_type(url: str) -> SourceType | None:
    """Classify a URL/path into a remote source type.

    Returns None for container-internal paths (``/app/...``) that can be
    used directly without fetching.
    """
    if not url or not url.strip():
        return None

    url = url.strip()

    # S3
    if url.startswith("s3://"):
        return "s3"

    # GCS
    if url.startswith("gs://"):
        return "gcs"

    # Azure Blob
    if re.match(r"https?://[^/]+\.blob\.core\.windows\.net/", url):
        return "azure_blob"

    # Git remotes
    if url.startswith("git@") or url.startswith("git://"):
        return "git"
    if url.startswith("https://") and url.rstrip("/").endswith(".git"):
        return "git"

    # HTTP archives
    if url.startswith("https://") or url.startswith("http://"):
        lower = url.lower().split("?")[0]  # Strip query params
        if any(lower.endswith(ext) for ext in (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            return "http_archive"

    # Host OS paths — anything with a Windows drive letter or a non-/app/ absolute path
    normalised = url.replace("\\", "/")
    # Windows: C:/ D:/ etc.
    if re.match(r"^[A-Za-z]:/", normalised):
        return "host_path"
    # Unix absolute path not inside /app/ (container internal)
    if normalised.startswith("/") and not normalised.startswith("/app/"):
        return "host_path"

    return None


# ── Stable directory naming ───────────────────────────────────────────

def _stable_dir_name(uri: str, prefix: str = "") -> str:
    """Generate a stable, filesystem-safe directory name from a URI.

    Returns ``{prefix}{basename}_{hash8}`` where hash8 is the first 8
    chars of the MD5 of the full URI.
    """
    url_hash = hashlib.md5(uri.encode()).hexdigest()[:8]
    # Extract a human-readable basename
    cleaned = uri.rstrip("/").replace("\\", "/")
    basename = cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
    # Remove non-filesystem-safe characters
    basename = re.sub(r"[^a-zA-Z0-9._-]", "_", basename)
    basename = basename[:60]  # Truncate very long names
    if prefix:
        return f"{prefix}{basename}_{url_hash}"
    return f"{basename}_{url_hash}"


# ── Host path import via Docker API ───────────────────────────────────

async def fetch_from_host(host_path: str, dest_dir: Path) -> Path:
    """Copy files from a host OS path into the container using Docker API.

    Creates a temporary Alpine container that bind-mounts the host path
    and copies its contents to the shared downloads directory.  Docker
    Desktop (Windows/Mac) and Docker Engine (Linux) both handle host-path
    bind mounts natively, so this works on all OSes.

    Args:
        host_path: The host OS path (e.g. ``C:\\Users\\brad\\Projects\\myapp``)
        dest_dir: Container-side destination (typically ``/app/downloads``)

    Returns:
        Path to the copied directory inside the container.
    """
    from mass.mcp.container import _docker_api, docker_available

    if not docker_available():
        raise RuntimeError(
            "Docker socket not available. Host path import requires "
            "Docker socket access at /var/run/docker.sock."
        )

    # Normalise for Docker: forward slashes
    normalised = host_path.replace("\\", "/")
    dir_name = _stable_dir_name(normalised, prefix="host_")
    dest_path = dest_dir / dir_name

    # Ensure destination exists
    dest_dir.mkdir(parents=True, exist_ok=True)

    # If already imported, return existing
    if dest_path.exists() and any(dest_path.iterdir()):
        logger.info("Host import already exists: %s", dest_path)
        return dest_path

    dest_path.mkdir(parents=True, exist_ok=True)

    # Resolve the host-side downloads path for the bind mount.
    # We need the HOST path that maps to dest_dir inside the container.
    # The env var MASS_DOWNLOADS_DIR gives us the host side.
    host_downloads = os.environ.get("MASS_DOWNLOADS_DIR", "./downloads")

    container_name = f"mass-import-{hashlib.md5(normalised.encode()).hexdigest()[:8]}"

    logger.info("Importing host path %s → %s via Docker API", host_path, dest_path)

    try:
        # Pull alpine (usually cached)
        await asyncio.to_thread(
            _docker_api, "POST",
            "/images/create?fromImage=alpine&tag=latest",
            timeout=60,
        )

        # Create container with host path and downloads dir mounted
        container_config: dict[str, Any] = {
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", f"cp -a /source/. /dest/{dir_name}/ 2>/dev/null; echo done"],
            "HostConfig": {
                "Binds": [
                    f"{normalised}:/source:ro",
                    f"{host_downloads}:/dest",
                ],
                "AutoRemove": True,
                "Memory": 256 * 1024 * 1024,  # 256 MB limit
            },
            "Labels": {
                "mass.import": "true",
                "mass.import.source": normalised[:200],
            },
        }

        status, data = await asyncio.to_thread(
            _docker_api, "POST",
            f"/containers/create?name={container_name}",
            container_config,
            timeout=30,
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create import container: {status} {data}")

        container_id = data.get("Id", "")

        # Start container
        status, _ = await asyncio.to_thread(
            _docker_api, "POST",
            f"/containers/{container_id}/start",
            timeout=10,
        )
        if status not in (200, 204):
            raise RuntimeError(f"Failed to start import container: {status}")

        # Wait for container to finish (poll status)
        for _ in range(120):  # Max 2 minutes
            await asyncio.sleep(1)
            status, info = await asyncio.to_thread(
                _docker_api, "GET",
                f"/containers/{container_id}/json",
                timeout=10,
            )
            if status == 404:
                # AutoRemove already cleaned up — container finished
                break
            if status == 200 and isinstance(info, dict):
                state = info.get("State", {})
                if not state.get("Running", True):
                    exit_code = state.get("ExitCode", -1)
                    if exit_code != 0:
                        logger.warning("Import container exited with code %d", exit_code)
                    break
        else:
            # Timeout — try to stop
            try:
                await asyncio.to_thread(
                    _docker_api, "POST",
                    f"/containers/{container_id}/stop",
                    {"t": 5},
                    timeout=15,
                )
            except Exception:
                pass
            raise RuntimeError("Host import timed out after 120 seconds")

    except Exception:
        # Clean up destination on failure
        if dest_path.exists() and not any(dest_path.iterdir()):
            shutil.rmtree(dest_path, ignore_errors=True)
        raise
    finally:
        # Ensure container is removed (in case AutoRemove didn't fire)
        try:
            await asyncio.to_thread(
                _docker_api, "DELETE",
                f"/containers/{container_name}?force=true",
                timeout=10,
            )
        except Exception:
            pass

    # Verify files were copied
    if not dest_path.exists() or not any(dest_path.iterdir()):
        raise RuntimeError(
            f"Host import completed but no files found at {dest_path}. "
            f"Check that the host path exists: {host_path}"
        )

    logger.info("Host import complete: %s → %s", host_path, dest_path)
    return dest_path


# ── S3 fetch ──────────────────────────────────────────────────────────

async def fetch_from_s3(
    s3_uri: str,
    dest_dir: Path,
    credentials: dict[str, str] | None = None,
) -> Path:
    """Download all objects under an S3 prefix to a local directory.

    Args:
        s3_uri: S3 URI, e.g. ``s3://my-bucket/path/to/project/``
        dest_dir: Local base directory (typically ``/app/downloads``)
        credentials: Optional dict with ``access_key``, ``secret_key``,
            ``session_token``, ``region``.  Falls back to StorageSettings
            then the default boto3 credential chain (IAM role, env vars).

    Returns:
        Path to the downloaded directory.
    """
    parsed = urlparse(s3_uri)
    bucket = parsed.netloc
    prefix = parsed.path.lstrip("/")
    if not bucket:
        raise ValueError(f"Invalid S3 URI (no bucket): {s3_uri}")

    dir_name = _stable_dir_name(s3_uri, prefix="s3_")
    local_dir = dest_dir / dir_name
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Build boto3 session kwargs
    creds = credentials or {}
    if not creds:
        # Fall back to StorageSettings
        try:
            from mass.core.config import get_settings
            storage = get_settings().storage
            creds = {
                "access_key": storage.s3_access_key.get_secret_value(),
                "secret_key": storage.s3_secret_key.get_secret_value(),
                "region": storage.s3_region,
            }
        except Exception:
            pass  # Let boto3 use its default credential chain

    session_kwargs: dict[str, str] = {}
    if creds.get("access_key"):
        session_kwargs["aws_access_key_id"] = creds["access_key"]
    if creds.get("secret_key"):
        session_kwargs["aws_secret_access_key"] = creds["secret_key"]
    if creds.get("session_token"):
        session_kwargs["aws_session_token"] = creds["session_token"]
    if creds.get("region"):
        session_kwargs["region_name"] = creds["region"]

    def _sync_download() -> int:
        """Synchronous S3 download (runs in executor)."""
        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "boto3 is not installed. Install with: pip install boto3"
            )

        session = boto3.Session(**session_kwargs)
        client = session.client("s3")
        paginator = client.get_paginator("list_objects_v2")

        file_count = 0
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                # Skip directory markers
                if key.endswith("/"):
                    continue

                # Compute relative path
                rel_path = key[len(prefix):].lstrip("/") if prefix else key
                if not rel_path:
                    continue

                local_file = local_dir / rel_path
                local_file.parent.mkdir(parents=True, exist_ok=True)

                logger.debug("S3 download: s3://%s/%s → %s", bucket, key, local_file)
                client.download_file(bucket, key, str(local_file))
                file_count += 1

        return file_count

    logger.info("Downloading S3 prefix: %s → %s", s3_uri, local_dir)
    file_count = await asyncio.to_thread(_sync_download)
    logger.info("S3 download complete: %d files from %s", file_count, s3_uri)

    if file_count == 0:
        logger.warning("No files downloaded from S3 prefix: %s", s3_uri)

    return local_dir


# ── Azure Blob fetch ──────────────────────────────────────────────────

async def fetch_from_azure(
    blob_url: str,
    dest_dir: Path,
    credentials: dict[str, str] | None = None,
) -> Path:
    """Download blobs from an Azure Blob Storage container/prefix.

    Args:
        blob_url: Azure Blob URL, e.g.
            ``https://account.blob.core.windows.net/container/path``
        dest_dir: Local base directory (typically ``/app/downloads``)
        credentials: Optional dict with ``connection_string`` or
            ``client_id``, ``client_secret``, ``tenant_id``.

    Returns:
        Path to the downloaded directory.
    """
    # Parse the URL: https://account.blob.core.windows.net/container/prefix
    parsed = urlparse(blob_url)
    path_parts = parsed.path.lstrip("/").split("/", 1)
    if len(path_parts) < 1 or not path_parts[0]:
        raise ValueError(f"Invalid Azure Blob URL (no container): {blob_url}")

    container_name = path_parts[0]
    blob_prefix = path_parts[1] if len(path_parts) > 1 else ""
    account_url = f"{parsed.scheme}://{parsed.netloc}"

    dir_name = _stable_dir_name(blob_url, prefix="azure_")
    local_dir = dest_dir / dir_name
    dest_dir.mkdir(parents=True, exist_ok=True)

    creds = credentials or {}
    if not creds:
        try:
            from mass.core.config import get_settings
            storage = get_settings().storage
            conn_str = storage.azure_connection_string.get_secret_value()
            if conn_str:
                creds = {"connection_string": conn_str}
        except Exception:
            pass

    def _sync_download() -> int:
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError:
            raise RuntimeError(
                "azure-storage-blob is not installed. "
                "Install with: pip install azure-storage-blob"
            )

        if creds.get("connection_string"):
            service_client = BlobServiceClient.from_connection_string(
                creds["connection_string"]
            )
        else:
            try:
                from azure.identity import ClientSecretCredential
                credential = ClientSecretCredential(
                    tenant_id=creds.get("tenant_id", ""),
                    client_id=creds.get("client_id", creds.get("access_key", "")),
                    client_secret=creds.get("client_secret", creds.get("secret_key", "")),
                )
                service_client = BlobServiceClient(
                    account_url=account_url, credential=credential
                )
            except ImportError:
                raise RuntimeError(
                    "azure-identity is required for service principal auth"
                )

        container_client = service_client.get_container_client(container_name)
        file_count = 0
        for blob in container_client.list_blobs(name_starts_with=blob_prefix):
            if blob.name.endswith("/"):
                continue
            rel_path = blob.name[len(blob_prefix):].lstrip("/") if blob_prefix else blob.name
            if not rel_path:
                continue

            local_file = local_dir / rel_path
            local_file.parent.mkdir(parents=True, exist_ok=True)

            with open(local_file, "wb") as f:
                stream = container_client.download_blob(blob.name)
                f.write(stream.readall())
            file_count += 1

        return file_count

    logger.info("Downloading Azure Blob: %s → %s", blob_url, local_dir)
    file_count = await asyncio.to_thread(_sync_download)
    logger.info("Azure Blob download complete: %d files from %s", file_count, blob_url)
    return local_dir


# ── GCS fetch ─────────────────────────────────────────────────────────

async def fetch_from_gcs(
    gcs_uri: str,
    dest_dir: Path,
    credentials: dict[str, str] | None = None,
) -> Path:
    """Download objects from a Google Cloud Storage bucket/prefix.

    Args:
        gcs_uri: GCS URI, e.g. ``gs://my-bucket/path/to/project/``
        dest_dir: Local base directory (typically ``/app/downloads``)
        credentials: Optional dict with ``service_account_json`` (file path
            or JSON string) or ``credentials_file``.

    Returns:
        Path to the downloaded directory.
    """
    parsed = urlparse(gcs_uri)
    bucket_name = parsed.netloc
    prefix = parsed.path.lstrip("/")
    if not bucket_name:
        raise ValueError(f"Invalid GCS URI (no bucket): {gcs_uri}")

    dir_name = _stable_dir_name(gcs_uri, prefix="gcs_")
    local_dir = dest_dir / dir_name
    dest_dir.mkdir(parents=True, exist_ok=True)

    creds = credentials or {}
    if not creds:
        try:
            from mass.core.config import get_settings
            storage = get_settings().storage
            if storage.gcs_credentials_file:
                creds = {"credentials_file": storage.gcs_credentials_file}
        except Exception:
            pass

    def _sync_download() -> int:
        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            raise RuntimeError(
                "google-cloud-storage is not installed. "
                "Install with: pip install google-cloud-storage"
            )

        client_kwargs: dict[str, Any] = {}
        if creds.get("credentials_file"):
            client = gcs_storage.Client.from_service_account_json(
                creds["credentials_file"]
            )
        elif creds.get("service_account_json"):
            import json as json_mod
            info = json_mod.loads(creds["service_account_json"])
            from google.oauth2 import service_account
            sa_creds = service_account.Credentials.from_service_account_info(info)
            client = gcs_storage.Client(credentials=sa_creds, **client_kwargs)
        else:
            # Use default credentials (GCE metadata, env var, etc.)
            client = gcs_storage.Client(**client_kwargs)

        bucket = client.bucket(bucket_name)
        file_count = 0
        for blob in bucket.list_blobs(prefix=prefix):
            if blob.name.endswith("/"):
                continue
            rel_path = blob.name[len(prefix):].lstrip("/") if prefix else blob.name
            if not rel_path:
                continue

            local_file = local_dir / rel_path
            local_file.parent.mkdir(parents=True, exist_ok=True)
            blob.download_to_filename(str(local_file))
            file_count += 1

        return file_count

    logger.info("Downloading GCS: %s → %s", gcs_uri, local_dir)
    file_count = await asyncio.to_thread(_sync_download)
    logger.info("GCS download complete: %d files from %s", file_count, gcs_uri)
    return local_dir


# ── Git clone (generalized) ──────────────────────────────────────────

async def fetch_from_git(
    url: str,
    clones_dir: Path,
    branch: str | None = None,
) -> Path:
    """Clone any git remote to a local directory.

    Generalized from ``_clone_github_repo()`` in discovery.py.  Supports
    GitHub, GitLab, Bitbucket, self-hosted, SSH, and HTTPS remotes.

    Args:
        url: Git remote URL (HTTPS, SSH, or git:// protocol)
        clones_dir: Base directory for clones (typically ``/app/github_clones``)
        branch: Optional branch/tag/ref to clone

    Returns:
        Path to the cloned directory.
    """
    # Normalize URL
    clean_url = url.rstrip("/")
    if clean_url.endswith(".git"):
        clean_url = clean_url[:-4]

    # Extract owner/repo for directory naming
    if clean_url.startswith("git@"):
        # git@host:owner/repo
        path_part = clean_url.split(":", 1)[-1]
    else:
        # https://host/owner/repo or git://host/owner/repo
        parsed = urlparse(clean_url)
        path_part = parsed.path.lstrip("/")

    parts = path_part.rstrip("/").split("/")
    repo_name = parts[-1] if parts else "repo"
    owner = parts[-2] if len(parts) >= 2 else "unknown"

    url_hash = hashlib.md5(clean_url.encode()).hexdigest()[:8]
    clone_dir = clones_dir / f"{owner}_{repo_name}_{url_hash}"

    clones_dir.mkdir(parents=True, exist_ok=True)

    def _sync_clone() -> Path:
        # If already cloned, pull latest
        if clone_dir.exists() and (clone_dir / ".git").exists():
            logger.info("Updating existing clone: %s", clone_dir)
            try:
                subprocess.run(
                    ["git", "-C", str(clone_dir), "pull", "--ff-only"],
                    capture_output=True,
                    timeout=60,
                )
            except Exception as e:
                logger.warning("Failed to update clone: %s", e)
            return clone_dir

        # Remove partial clone if exists
        if clone_dir.exists():
            shutil.rmtree(clone_dir)

        # Clone
        logger.info("Cloning %s to %s", url, clone_dir)
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([url, str(clone_dir)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                raise RuntimeError(f"git clone failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            if clone_dir.exists():
                shutil.rmtree(clone_dir)
            raise RuntimeError("Clone timed out after 120 seconds")
        except FileNotFoundError:
            raise RuntimeError("git is not installed")

        return clone_dir

    return await asyncio.to_thread(_sync_clone)


# ── HTTP archive fetch ────────────────────────────────────────────────

async def fetch_from_http(url: str, dest_dir: Path) -> Path:
    """Download and extract an HTTP archive (.zip, .tar.gz, etc.).

    Args:
        url: URL to a downloadable archive file
        dest_dir: Local base directory (typically ``/app/downloads``)

    Returns:
        Path to the extracted directory.
    """
    import httpx

    dir_name = _stable_dir_name(url, prefix="http_")
    local_dir = dest_dir / dir_name
    dest_dir.mkdir(parents=True, exist_ok=True)

    if local_dir.exists() and any(local_dir.iterdir()):
        logger.info("HTTP archive already extracted: %s", local_dir)
        return local_dir

    local_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading HTTP archive: %s", url)

    # Download to temp file first (avoids OOM for large archives)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="mass_archive_")
    try:
        async with httpx.AsyncClient(timeout=300, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                with os.fdopen(tmp_fd, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        f.write(chunk)
                # Keep tmp_fd from being closed again
                tmp_fd = -1

        # Detect archive type and extract
        lower_url = url.lower().split("?")[0]
        if lower_url.endswith(".zip"):
            _extract_zip(tmp_path, local_dir)
        elif lower_url.endswith((".tar.gz", ".tgz")):
            _extract_tar(tmp_path, local_dir, mode="r:gz")
        elif lower_url.endswith(".tar.bz2"):
            _extract_tar(tmp_path, local_dir, mode="r:bz2")
        elif lower_url.endswith(".tar.xz"):
            _extract_tar(tmp_path, local_dir, mode="r:xz")
        else:
            raise ValueError(f"Unsupported archive format: {url}")

    except Exception:
        # Clean up on failure
        if local_dir.exists() and not any(local_dir.iterdir()):
            shutil.rmtree(local_dir, ignore_errors=True)
        raise
    finally:
        if tmp_fd >= 0:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    logger.info("HTTP archive extracted: %s → %s", url, local_dir)
    return local_dir


def _extract_zip(archive_path: str, dest_dir: Path) -> None:
    """Extract a zip archive, stripping single top-level directory if present."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        names = zf.namelist()
        top_dirs = {n.split("/", 1)[0] for n in names if "/" in n}
        strip_prefix = ""
        if len(top_dirs) == 1:
            strip_prefix = top_dirs.pop() + "/"

        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = info.filename
            if strip_prefix and rel.startswith(strip_prefix):
                rel = rel[len(strip_prefix):]
            if not rel:
                continue
            # Security: prevent path traversal (Zip Slip)
            if ".." in rel or rel.startswith("/"):
                continue
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def _extract_tar(archive_path: str, dest_dir: Path, mode: str = "r:gz") -> None:
    """Extract a tar archive, stripping single top-level directory if present."""
    with tarfile.open(archive_path, mode) as tf:
        members = tf.getmembers()
        top_dirs = {m.name.split("/", 1)[0] for m in members if "/" in m.name}
        strip_prefix = ""
        if len(top_dirs) == 1:
            strip_prefix = top_dirs.pop() + "/"

        for member in members:
            if member.isdir():
                continue
            rel = member.name
            if strip_prefix and rel.startswith(strip_prefix):
                rel = rel[len(strip_prefix):]
            if not rel:
                continue
            # Security: prevent path traversal
            if ".." in rel or rel.startswith("/"):
                continue
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src:
                with open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
