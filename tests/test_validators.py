"""Tests for path, content, and resource validators."""

import pytest
from pathlib import Path

from zipguard.policy import ExtractionPolicy
from zipguard.validators.path import validate_entry_path, check_symlink, PathTraversalError, SymlinkError
from zipguard.validators.content import validate_filename, UnsafeFilenameError, DoubleExtensionError, BlockedExtensionError
from zipguard.validators.resource import ResourceTracker, FileSizeLimitError, CompressionRatioError, FileCountLimitError


# --- Path traversal ---

class TestPathValidation:
    def test_normal_file(self, tmp_path):
        dest = validate_entry_path("subdir/file.txt", tmp_path)
        assert dest == (tmp_path / "subdir" / "file.txt").resolve()

    def test_zip_slip_relative(self, tmp_path):
        with pytest.raises(PathTraversalError):
            validate_entry_path("../../evil.exe", tmp_path)

    def test_absolute_unix_path(self, tmp_path):
        with pytest.raises(PathTraversalError):
            validate_entry_path("/etc/passwd", tmp_path)

    def test_absolute_windows_path(self, tmp_path):
        with pytest.raises(PathTraversalError):
            validate_entry_path("C:/Windows/System32/evil.dll", tmp_path)

    def test_unc_path(self, tmp_path):
        with pytest.raises(PathTraversalError):
            validate_entry_path("//server/share/evil.exe", tmp_path)


class TestSymlinkValidation:
    def test_symlink_blocked_by_default(self):
        policy = ExtractionPolicy()
        with pytest.raises(SymlinkError):
            check_symlink(is_symlink=True, is_hardlink=False, policy_allow=policy.allow_symlinks)

    def test_hardlink_blocked_by_default(self):
        policy = ExtractionPolicy()
        with pytest.raises(SymlinkError):
            check_symlink(is_symlink=False, is_hardlink=True, policy_allow=policy.allow_symlinks)

    def test_symlink_allowed_when_configured(self):
        check_symlink(is_symlink=True, is_hardlink=False, policy_allow=True)  # should not raise


# --- Content validation ---

class TestFilenameValidation:
    def test_normal_file(self):
        policy = ExtractionPolicy()
        safe_name, reason = validate_filename("document.pdf", policy)
        assert safe_name == "document.pdf"
        assert reason == ""

    def test_blocked_extension_rename(self):
        policy = ExtractionPolicy(rename_blocked=True)
        safe_name, reason = validate_filename("malware.exe", policy)
        assert safe_name == "malware.exe.blocked"
        assert ".exe" in reason

    def test_blocked_extension_hard_block(self):
        policy = ExtractionPolicy(rename_blocked=False)
        with pytest.raises(BlockedExtensionError):
            validate_filename("malware.exe", policy)

    def test_rtlo_detection(self):
        policy = ExtractionPolicy(block_rtlo=True)
        # Filename with RTLO character U+202E
        with pytest.raises(UnsafeFilenameError):
            validate_filename("document\u202etxt.exe", policy)

    def test_double_extension(self):
        policy = ExtractionPolicy(block_double_extension=True)
        with pytest.raises(DoubleExtensionError):
            validate_filename("document.pdf.exe", policy)

    def test_double_extension_allowed_when_disabled(self):
        policy = ExtractionPolicy(block_double_extension=False)
        # Should not raise, but the .exe will be renamed
        safe_name, reason = validate_filename("document.pdf.exe", policy)
        assert safe_name == "document.pdf.exe.blocked"
        assert ".exe" in reason


# --- Resource limits ---

class TestResourceLimits:
    def test_file_size_limit(self):
        policy = ExtractionPolicy(max_file_size=1000)
        tracker = ResourceTracker(policy)
        with pytest.raises(FileSizeLimitError):
            tracker.check_file_size("big.bin", compressed_size=100, file_size=2000)

    def test_compression_ratio_limit(self):
        policy = ExtractionPolicy(max_compression_ratio=10)
        tracker = ResourceTracker(policy)
        with pytest.raises(CompressionRatioError):
            tracker.check_file_size("bomb.bin", compressed_size=10, file_size=10000)

    def test_file_count_limit(self):
        policy = ExtractionPolicy(max_files=2)
        tracker = ResourceTracker(policy)
        tracker.record_extracted("a.txt", 100)
        tracker.record_extracted("b.txt", 100)
        with pytest.raises(FileCountLimitError):
            tracker.record_extracted("c.txt", 100)

    def test_total_size_limit(self):
        policy = ExtractionPolicy(max_total_size=500)
        tracker = ResourceTracker(policy)
        tracker.record_extracted("a.txt", 300)
        with pytest.raises(Exception):
            tracker.record_extracted("b.txt", 300)
