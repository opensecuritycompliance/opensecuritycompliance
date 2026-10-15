"""File-system backend for object storage.

With ``COW_DATA_PERSISTENCE_TYPE=local``, files that would go to MinIO (or any
S3-compatible store) are written under a folder on disk instead, and referred
to by ``file://`` URLs, so a rule can run end to end without Docker or a storage
server.

Layout: ``<root>/<bucket>/<object>``, the shape of a bucket in object storage,
and ``file://localhost/<root>/<bucket>/<object>`` as the URL. The host is written
out because tasks check their URL inputs for a scheme and a host
(``urlparse(url).netloc``), which ``file:///path`` would fail. The Go side
(``src/cowlibrary/localstorage``) does the same, so a file written by a Python
task is read by a Go task and the other way round.
"""
import os
from typing import Optional
from urllib import parse

ENV_PERSISTENCE_TYPE = "COW_DATA_PERSISTENCE_TYPE"
ENV_ROOT = "COW_LOCAL_STORAGE_PATH"
DEFAULT_BUCKET = "demo"

_LOCAL_TYPES = {"local", "local_file_store_path"}


class LocalStorageError(Exception):
    """A name that is not allowed, or a file that is not there."""


def is_enabled() -> bool:
    """True only when local storage is explicitly selected. A deployment that
    does not set the variable must keep using object storage."""
    return os.getenv(ENV_PERSISTENCE_TYPE, "").strip().lower() in _LOCAL_TYPES


def root() -> str:
    """The folder the files live in, as an absolute path."""
    configured = os.getenv(ENV_ROOT, "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    return os.path.join(os.path.expanduser("~"), ".cowctl", "storage")


def _object_path(bucket: Optional[str], object_name: str) -> str:
    """Map bucket and object name to a path under the root. A name that would
    leave the root is refused: object names come from task inputs."""
    bucket = bucket or DEFAULT_BUCKET
    object_name = (object_name or "").lstrip("/")
    if not object_name:
        raise LocalStorageError("the object name is empty")
    if ".." in (bucket + "/" + object_name).split("/"):
        raise LocalStorageError(
            f"invalid object name '{bucket}/{object_name}': it must stay inside the storage folder")
    base = root()
    path = os.path.normpath(os.path.join(base, bucket, object_name))
    if not path.startswith(base + os.sep):
        raise LocalStorageError(
            f"invalid object name '{object_name}': it must stay inside the storage folder")
    return path


def to_url(path: str) -> str:
    """The ``file://`` URL of a path on disk: file://localhost/abs/path."""
    p = path.replace(os.sep, "/")
    if not p.startswith("/"):
        p = "/" + p  # C:/dir/file on Windows
    return "file://localhost" + parse.quote(p)


def path_from_url(url: str) -> Optional[str]:
    """The path a ``file://`` URL names, or None for anything else, including the
    older ``file://name`` form, which names a file in LOCAL_FOLDER."""
    if not isinstance(url, str) or not url.startswith("file://"):
        return None
    parsed = parse.urlparse(url)
    if parsed.netloc not in ("", "localhost") or not parsed.path.startswith("/"):
        return None
    path = parse.unquote(parsed.path)
    if os.name == "nt" and len(path) > 2 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return path.replace("/", os.sep)


def is_local_url(url: str) -> bool:
    """True for a ``file://`` URL with an absolute path, the form written here."""
    return path_from_url(url) is not None


def put(bucket: Optional[str], object_name: str, content: bytes) -> str:
    """Store content as bucket/object and return its ``file://`` URL."""
    path = _object_path(bucket, object_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)
    return to_url(path)


def read(url: str) -> bytes:
    """The content of a ``file://`` URL."""
    path = path_from_url(url)
    if path is None:
        raise LocalStorageError(f"'{url}' is not a local file URL (expected file:///absolute/path)")
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise LocalStorageError(f"cannot read '{path}': {e.strerror or e}") from e


def size_bytes(url: str) -> int:
    """The size of the file a ``file://`` URL names."""
    path = path_from_url(url)
    if path is None:
        raise LocalStorageError(f"'{url}' is not a local file URL (expected file:///absolute/path)")
    try:
        return os.path.getsize(path)
    except OSError as e:
        raise LocalStorageError(f"cannot read '{path}': {e.strerror or e}") from e
