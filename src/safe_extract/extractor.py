"""SafeExtractor — main orchestration class."""

from __future__ import annotations

import hashlib
from pathlib import Path

from safe_extract.audit import Decision, EntryResult, ExtractionReport
from safe_extract.formats.base import ArchiveEntry, BaseArchiveReader
from safe_extract.formats.zip import AmbiguousArchiveError, EncryptedArchiveError, ZipReader
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
from safe_extract.validators.resource import (
    FileCountLimitError,
    FileSizeLimitError,
    TotalSizeLimitError,
)


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
        The archive is opened once and kept open for the full extraction.
        Returns an ExtractionReport with the result of every entry.
        """
        report = ExtractionReport(archive=str(archive_path))
        reader = _get_reader(archive_path)

        try:
            with reader:
                self._run_extraction(reader, report, target_dir, dry_run)
        except (AmbiguousArchiveError, ValueError) as e:
            if not report.aborted:
                report.abort(str(e))

        return report

    def _run_extraction(
        self,
        reader: BaseArchiveReader,
        report: ExtractionReport,
        target_dir: Path,
        dry_run: bool,
    ) -> None:
        # Phase 1: structural validation before touching any entry
        if self.policy.block_ambiguous_archives:
            try:
                reader.validate_structure()
            except Exception as e:
                report.abort(str(e))
                return

        target_dir = Path(target_dir)
        if not dry_run:
            target_dir.mkdir(parents=True, exist_ok=True)

        entries = reader.entries()

        # Running counters — checked during streaming (not from forged metadata)
        total_extracted: int = 0
        file_count: int = 0

        for entry in entries:
            result = self._process_entry(
                entry, reader, target_dir,
                total_extracted, file_count,
                dry_run,
            )
            report.add(result)

            if result.decision == Decision.ALLOWED or result.decision == Decision.RENAMED:
                total_extracted += result.file_size
                file_count += 1

            # Abort the whole extraction if a hard resource limit was hit
            if result.reason and any(
                kw in result.reason for kw in ("total_size", "file_count", "Total extracted", "Exceeded max_files")
            ):
                report.abort(result.reason)
                return

        report.finish()

    def _process_entry(
        self,
        entry: ArchiveEntry,
        reader: BaseArchiveReader,
        target_dir: Path,
        total_extracted: int,
        file_count: int,
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

        # --- File count limit ---
        if file_count >= self.policy.max_files:
            return EntryResult(
                entry.name, Decision.BLOCKED,
                reason=f"Exceeded max_files limit of {self.policy.max_files} files",
            )

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
        except (UnsafeFilenameError, DoubleExtensionError, BlockedExtensionError) as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))

        was_renamed = safe_name != Path(entry.name).name
        if was_renamed:
            dest = dest.parent / safe_name

        # --- Overwrite check ---
        if not self.policy.allow_overwrite and dest.exists():
            return EntryResult(
                entry.name, Decision.BLOCKED,
                reason=f"Destination exists and overwrite is disabled: {dest}",
            )

        if dry_run:
            decision = Decision.RENAMED if was_renamed else Decision.ALLOWED
            return EntryResult(
                entry.name, decision,
                reason="dry-run" if not was_renamed else f"renamed to {safe_name}",
                dest=str(dest),
                file_size=entry.file_size,
            )

        # --- Extract with streaming guard ---
        # NOTE: entry.file_size from ZIP metadata can be forged.
        # We count actual bytes during streaming and abort mid-write if limits hit.
        file_bytes: int = 0

        def on_chunk(chunk_size: int) -> None:
            nonlocal file_bytes
            file_bytes += chunk_size
            if file_bytes > self.policy.max_file_size:
                raise FileSizeLimitError(
                    f"File '{entry.name}' exceeds max_file_size limit: "
                    f"{file_bytes:,} > {self.policy.max_file_size:,} bytes"
                )
            if total_extracted + file_bytes > self.policy.max_total_size:
                raise TotalSizeLimitError(
                    f"Total extracted size limit exceeded: "
                    f"{total_extracted + file_bytes:,} > {self.policy.max_total_size:,} bytes"
                )

        try:
            bytes_written = reader.extract_entry(entry, dest, on_chunk=on_chunk)
        except (FileSizeLimitError, TotalSizeLimitError) as e:
            dest.unlink(missing_ok=True)
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))
        except EncryptedArchiveError as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=str(e))
        except Exception as e:
            return EntryResult(entry.name, Decision.BLOCKED, reason=f"Extraction error: {e}")

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
