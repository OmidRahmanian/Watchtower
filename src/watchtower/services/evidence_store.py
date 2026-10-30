"""Filesystem, content-addressed storage for evidence bodies.

Blobs live at ``<root>/<project_id>/<sha256[:2]>/<sha256>`` and are addressed
by ``fs:<project_id>/<sha256>`` URIs. Files are written once through a private
temporary file and an atomic rename, are readable only by their owner, and are
verified against their digest on every read.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
import re
import tempfile
from uuid import UUID

from watchtower.domain.models import StoredBlob

URI_PATTERN = re.compile(r"fs:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([0-9a-f]{64})")
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


class BlobError(Exception):
    """A blob URI was malformed, escaped the store, or its content failed verification."""


class FilesystemBlobStore:
    """Implements ``watchtower.domain.repositories.BlobStore`` on a local directory."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
        self.root = self.root.resolve(strict=True)

    def put(self, project_id: UUID, data: bytes, *, media_type: str) -> StoredBlob:
        digest = hashlib.sha256(data).hexdigest()
        uri = f"fs:{UUID(str(project_id))}/{digest}"
        path = self._path(uri)
        if not self._intact(path, digest):
            self._write(path, data)
        return StoredBlob(uri=uri, sha256=digest, size_bytes=len(data))

    def get(self, uri: str) -> bytes:
        path = self._path(uri)
        digest = path.name
        try:
            data = path.read_bytes()
        except FileNotFoundError as error:
            raise BlobError(f"blob not found: {uri}") from error
        if hashlib.sha256(data).hexdigest() != digest:
            raise BlobError(f"blob failed digest verification: {uri}")
        return data

    def _path(self, uri: str) -> Path:
        match = URI_PATTERN.fullmatch(uri) if isinstance(uri, str) else None
        if match is None:
            raise BlobError(f"not a blob URI: {uri!r}")
        project, digest = match.groups()
        path = self.root / project / digest[:2] / digest
        # The pattern already excludes separators and dot segments; this guards
        # against a project directory replaced by a symlink pointing elsewhere.
        if not path.parent.resolve().is_relative_to(self.root):
            raise BlobError(f"blob path escapes the store: {uri!r}")
        return path

    @staticmethod
    def _intact(path: Path, digest: str) -> bool:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest() == digest
        except FileNotFoundError:
            return False

    def _write(self, path: Path, data: bytes) -> None:
        # mkdir(parents=True) would create the project directory with default
        # permissions, so create each level with the private mode.
        for directory in (path.parent.parent, path.parent):
            directory.mkdir(mode=DIRECTORY_MODE, exist_ok=True)
        if not path.parent.resolve().is_relative_to(self.root):
            raise BlobError(f"blob path escapes the store: {path}")
        descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), FILE_MODE)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
            raise
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
