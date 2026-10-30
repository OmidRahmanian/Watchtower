import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from uuid import uuid4

from watchtower.domain.models import StoredBlob
from watchtower.services.evidence_store import BlobError, FilesystemBlobStore

DATA = b'{"check_id":"exposed-git-config"}'
DIGEST = hashlib.sha256(DATA).hexdigest()


class FilesystemBlobStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "blobs"
        self.store = FilesystemBlobStore(self.root)
        self.project = uuid4()

    def test_round_trip_and_layout(self):
        blob = self.store.put(self.project, DATA, media_type="application/json")
        self.assertEqual(blob, StoredBlob(f"fs:{self.project}/{DIGEST}", DIGEST, len(DATA)))
        path = self.store.root / str(self.project) / DIGEST[:2] / DIGEST
        self.assertEqual(path.read_bytes(), DATA)
        self.assertEqual(self.store.get(blob.uri), DATA)
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_nothing_is_group_or_world_accessible(self):
        old = os.umask(0)
        try:
            self.store.put(self.project, DATA, media_type="application/json")
        finally:
            os.umask(old)
        for path in [self.store.root, *self.store.root.rglob("*")]:
            with self.subTest(path=path.relative_to(self.store.root.parent)):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    def test_writes_are_idempotent_and_per_project(self):
        first = self.store.put(self.project, DATA, media_type="application/json")
        path = self.store.root / str(self.project) / DIGEST[:2] / DIGEST
        written = path.stat().st_mtime_ns
        self.assertEqual(self.store.put(self.project, DATA, media_type="application/json"), first)
        self.assertEqual(path.stat().st_mtime_ns, written)
        other = self.store.put(uuid4(), DATA, media_type="application/json")
        self.assertNotEqual(other.uri, first.uri)
        self.assertEqual(other.sha256, first.sha256)

    def test_corrupt_blobs_fail_verification_and_are_rewritten(self):
        blob = self.store.put(self.project, DATA, media_type="application/json")
        path = self.store.root / str(self.project) / DIGEST[:2] / DIGEST
        path.write_bytes(b"tampered")
        with self.assertRaisesRegex(BlobError, "digest"):
            self.store.get(blob.uri)
        self.store.put(self.project, DATA, media_type="application/json")
        self.assertEqual(self.store.get(blob.uri), DATA)

    def test_failed_writes_leave_no_partial_files(self):
        with mock.patch("os.replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            self.store.put(self.project, DATA, media_type="application/json")
        files = [path for path in self.store.root.rglob("*") if path.is_file()]
        self.assertEqual(files, [])

    def test_malformed_and_escaping_uris_are_rejected(self):
        outside = self.root.parent / "secret"
        outside.write_bytes(DATA)
        uris = [
            f"fs:{self.project}/{DIGEST[:-1]}",
            f"fs:{self.project}/{DIGEST.upper()}",
            f"fs:../{DIGEST}",
            f"fs:{self.project}/../../secret",
            f"fs:not-a-uuid/{DIGEST}",
            f"fs:{self.project}/{DIGEST}\n",
            f"file://{outside}",
            str(outside),
            f"s3://bucket/{DIGEST}",
            None,
        ]
        for uri in uris:
            with self.subTest(uri=uri), self.assertRaises(BlobError):
                self.store.get(uri)

    def test_symlinked_project_directory_cannot_escape(self):
        elsewhere = self.root.parent / "elsewhere"
        (elsewhere / DIGEST[:2]).mkdir(parents=True)
        (elsewhere / DIGEST[:2] / DIGEST).write_bytes(DATA)
        (self.store.root / str(self.project)).symlink_to(elsewhere)
        for action in (lambda: self.store.get(f"fs:{self.project}/{DIGEST}"),
                       lambda: self.store.put(self.project, DATA, media_type="application/json")):
            with self.assertRaisesRegex(BlobError, "escapes"):
                action()

    def test_missing_blob(self):
        with self.assertRaisesRegex(BlobError, "not found"):
            self.store.get(f"fs:{self.project}/{DIGEST}")


if __name__ == "__main__":
    unittest.main()
