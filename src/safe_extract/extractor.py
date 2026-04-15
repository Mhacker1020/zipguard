"""SafeExtractor — main orchestration class."""

from __future__ import annotations

import hashlib
from pathlib import Path

from safe_extract.audit import Decision, EntryResult, ExtractionReport
from safe_extract.formats.base import ArchiveEntry, BaseArchiveReader
from safe_extract.formats.zip import ZipReader
from safe_extract.policy import ExtractionPolicy
from safe_extract.validators.content import (
    BlockedExtensionError,
    DoubleExtensionError,
    UnsafeFilenameError,
    validate_filename,
)
from safe_extract.validators.path import (
    PathTraversalError,
    SymlinkError,
    check_symlink,
    validate_entry_path,
)
from safe_extract.validators.resource import ResourceTracker


def _get_reader(archive_path: Path) -> BaseArchiveReader:
    suffix = archive_path.suffix.lower()
    if suffix == ".zip" or suffix in (".whl", ".jar", ".apk"):
        return ZipReader(archive_path)
    raise ValueError(f"Unsupported archive format: '{suffix}'")


class SafeExtractor:
    """
    Validates and extracts archives according to an ExtractionPolicy.

    Usage:
        extractor = SafeExtractor(policy)
        report = extractor.extract(Path("input.zip"), Path("./output"))
    """

    def __init__(self, policy: ExtractionPolicy | None = None) -> None:
        self.policy = policy or ExtractionPolicy()

    def extract(
        self,
        archive_path: Path,
        target_dir: Path,
        dry_run: bool = False,
    ) -> ExtractionReport:
        """
        Extract archive to target_dir under policy constraints.
        Returns an ExtractionReport with the result of every entry.
        """
        report = ExtractionReport(archive=str(archive_path))
        reader = _get_reader(archive_path)

        # Phase 1: structural validation (before touching any entry)
        if self.policy.block_ambiguous_archives:
            try:
                reader.validate_structure()
            except Exception as e:
                report.abort(str(e))
                return report

        target_dir = Path(target_dir)
        if not dry_run:
            target_dir.mkdir(parents=True, exist_ok=True)

        tracker = ResourceTracker(self.policy)
        entries = reader.entries()

        # Phase 2: pre-flight size check on all entries
        try:
            for entry in entries:
                if not entry.is_dir:
                    tracker.check_file_size(entry.name, entry.compressed_size, entry.file_size)
        except Exception as e:
            report.abort(str(e))
            return report

        # Phase 3: extract entry by entry
        for entry in entries:
            result = self._process_entry(entry, reader, target_dir, tracker, dry_run)
            report.add(result)
            if report.aborted:
                break

        report.finish()
        return report

    def _process_entry(
        self,
        entry: ArchiveEntry,
        reader: BaseArchiveReader,
        target_dir: Path,
        tracker: ResourceTracker,
        dry_run: bool,
    ) -> EntryResult:
        """Validate and extract a single entry. Returns its EntryResult."""

        if entry.is_dir:
            if not dry_run:
                try:
                    dest = validate_entry_path(entry.name, target_dir)
                    dest.mkdir(parents=True, exist_ok=True)
                except PathTraversalError as e:
                    return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))
            return EntryResult(entry.name, Decision.SKIPPED, reason="directory")

        # --- Symlink check ---
        try:
            check_symlink(entry.is_symlink, entry.is_hardlink, self.policy.allow_symlinks)
        except SymlinkError as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))

        # --- Path validation ---
        try:
            dest = validate_entry_path(entry.name, target_dir)
        except PathTraversalError as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))

        # --- Filename / content validation ---
        try:
            safe_name = validate_filename(entry.name, self.policy)
        except (UnsafeFilenameError, DoubleExtensionError) as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))
        except BlockedExtensionError as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))

        was_renamed = safe_name != Path(entry.name).name
        if was_renamed:
            dest = dest.parent / safe_name

        # --- Overwrite check ---
        if not self.policy.allow_overwrite and dest.exists():
            return EntryResult(
                entry.name, Decision.BLOCKED,
                reason=f"Destination already exists and overwrite is disabled: {dest}"
            )

        if dry_run:
            decision = Decision.RENAMED if was_renamed else Decision.ALLOWED
            return EntryResult(
                entry.name, decision,
                reason="dry-run" if not was_renamed else f"renamed to {safe_name}",
                dest=str(dest),
                file_size=entry.file_size,
            )

        # --- Extract ---
        try:
            bytes_written = reader.extract_entry(entry, dest)
        except Exception as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=f"Extraction error: {e}")

        # --- Resource tracking (post-write) ---
        try:
            tracker.record_extracted(entry.name, bytes_written)
        except Exception as e:
            # Limit exceeded — clean up the file we just wrote
            dest.unlink(missing_ok=True)
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))

        sha256 = _hash_file(dest) if self.policy.scan_hashes else ""
        decision = Decision.RENAMED if was_renamed else Decision.ALLOWED
        reason = f"renamed to {safe_name}" if was_renamed else ""

        return EntryResult(
            entry.name, decision,
            reason=reason,
            dest=str(dest),
            sha256=sha256,
            file_size=bytes_written,
        )


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()
