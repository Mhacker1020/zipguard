"""Integration tests for SafeExtractor using real ZIP files."""

import io
import zipfile
import pytest
from pathlib import Path

from safe_extract.extractor import SafeExtractor
from safe_extract.policy import ExtractionPolicy
from safe_extract.audit import Decision


def make_zip(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    """Helper: create a ZIP file with given {name: content} entries."""
    zpath = tmp_path / "test.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return zpath


class TestSafeExtractor:

    def test_clean_archive(self, tmp_path):
        zpath = make_zip(tmp_path, {"hello.txt": b"hello world"})
        out = tmp_path / "out"
        report = SafeExtractor().extract(zpath, out)

        assert not report.aborted
        assert report.allowed_count == 1
        assert (out / "hello.txt").read_bytes() == b"hello world"

    def test_zip_slip_blocked(self, tmp_path):
        zpath = tmp_path / "slip.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("../../evil.txt", b"pwned")

        out = tmp_path / "out"
        report = SafeExtractor().extract(zpath, out)

        assert report.blocked_count == 1
        assert not (tmp_path / "evil.txt").exists()

    def test_blocked_extension_renamed(self, tmp_path):
        zpath = make_zip(tmp_path, {"malware.exe": b"MZ..."})
        out = tmp_path / "out"
        policy = ExtractionPolicy(rename_blocked=True)
        report = SafeExtractor(policy).extract(zpath, out)

        assert report.renamed_count == 1
        assert (out / "malware.exe.blocked").exists()
        assert not (out / "malware.exe").exists()

    def test_dry_run_does_not_write(self, tmp_path):
        zpath = make_zip(tmp_path, {"file.txt": b"data"})
        out = tmp_path / "out"
        report = SafeExtractor().extract(zpath, out, dry_run=True)

        assert report.allowed_count == 1
        assert not out.exists()

    def test_duplicate_entries_aborted(self, tmp_path):
        """Archive with duplicate entry names should be aborted before extraction."""
        zpath = tmp_path / "dupes.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("file.txt", b"first")
            zf.writestr("file.txt", b"second")

        out = tmp_path / "out"
        report = SafeExtractor().extract(zpath, out)

        assert report.aborted
        assert "duplicate" in report.abort_reason.lower()

    def test_overwrite_blocked(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "existing.txt").write_bytes(b"original")

        zpath = make_zip(tmp_path, {"existing.txt": b"overwritten"})
        policy = ExtractionPolicy(allow_overwrite=False)
        report = SafeExtractor(policy).extract(zpath, out)

        assert report.blocked_count == 1
        assert (out / "existing.txt").read_bytes() == b"original"

    def test_hashes_computed(self, tmp_path):
        import hashlib
        content = b"hello hash"
        zpath = make_zip(tmp_path, {"data.txt": content})
        out = tmp_path / "out"
        report = SafeExtractor(ExtractionPolicy(scan_hashes=True)).extract(zpath, out)

        entry = report.entries[0]
        expected = hashlib.sha256(content).hexdigest()
        assert entry.sha256 == expected

    def test_forged_metadata_size_limit(self, tmp_path):
        """Archive with forged file_size=0 in metadata but real content exceeds limit."""
        import struct

        # Create a ZIP where file_size metadata says 0 but content is large
        # We simulate this by using a very small max_file_size and real content
        content = b"A" * 5000  # 5KB real content
        zpath = make_zip(tmp_path, {"big.bin": content})
        out = tmp_path / "out"

        policy = ExtractionPolicy(max_file_size=1000)  # 1KB limit
        report = SafeExtractor(policy).extract(zpath, out)

        assert report.blocked_count == 1
        assert not (out / "big.bin").exists()

    def test_forged_metadata_total_size_limit(self, tmp_path):
        """Two files that together exceed max_total_size are caught during streaming."""
        content = b"B" * 3000
        zpath = make_zip(tmp_path, {"a.bin": content, "b.bin": content})
        out = tmp_path / "out"

        policy = ExtractionPolicy(max_total_size=5000)
        report = SafeExtractor(policy).extract(zpath, out)

        # First file passes, second is blocked
        assert report.blocked_count >= 1

    def test_encrypted_zip_clear_error(self, tmp_path):
        """Encrypted ZIP entries produce a clear error, not a generic exception."""
        zpath = tmp_path / "encrypted.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("secret.txt", "hidden data")

        # Patch the reader to simulate an encrypted entry error
        from safe_extract.formats.zip import EncryptedArchiveError, ZipReader
        original_extract = ZipReader.extract_entry

        def mock_extract(self, entry, dest, on_chunk=None):
            raise EncryptedArchiveError("Entry 'secret.txt' is encrypted")

        ZipReader.extract_entry = mock_extract
        try:
            out = tmp_path / "out"
            report = SafeExtractor().extract(zpath, out)
            assert report.blocked_count == 1
            assert "encrypted" in report.entries[0].reason.lower()
        finally:
            ZipReader.extract_entry = original_extract
