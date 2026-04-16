"""Resource limit validation — archive bombs, size limits, file count."""

from __future__ import annotations

from zipguard.policy import ExtractionPolicy


class FileSizeLimitError(ValueError):
    pass


class TotalSizeLimitError(ValueError):
    pass


class FileCountLimitError(ValueError):
    pass


class CompressionRatioError(ValueError):
    pass


class ResourceTracker:
    """
    Tracks cumulative extraction stats and enforces resource limits.
    One instance per extraction job.
    """

    def __init__(self, policy: ExtractionPolicy) -> None:
        self.policy = policy
        self.total_extracted: int = 0
        self.file_count: int = 0

    def check_file_size(self, filename: str, compressed_size: int, file_size: int) -> None:
        """Check individual file size and compression ratio before extracting."""
        if file_size > self.policy.max_file_size:
            raise FileSizeLimitError(
                f"File '{filename}' exceeds max_file_size limit: "
                f"{file_size:,} > {self.policy.max_file_size:,} bytes"
            )

        if compressed_size > 0:
            ratio = file_size / compressed_size
            if ratio > self.policy.max_compression_ratio:
                raise CompressionRatioError(
                    f"File '{filename}' has suspicious compression ratio: "
                    f"{ratio:.0f}x (limit: {self.policy.max_compression_ratio}x) — "
                    f"possible archive bomb"
                )

    def record_extracted(self, filename: str, bytes_written: int) -> None:
        """Update counters after a file is written. Raises if limits exceeded."""
        self.file_count += 1
        self.total_extracted += bytes_written

        if self.file_count > self.policy.max_files:
            raise FileCountLimitError(
                f"Exceeded max_files limit of {self.policy.max_files} files"
            )

        if self.total_extracted > self.policy.max_total_size:
            raise TotalSizeLimitError(
                f"Exceeded max_total_size limit: "
                f"{self.total_extracted:,} > {self.policy.max_total_size:,} bytes"
            )
