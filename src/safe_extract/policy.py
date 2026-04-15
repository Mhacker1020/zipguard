"""Extraction policy configuration and validation rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# 100 MB
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024
# 500 MB
DEFAULT_MAX_TOTAL_SIZE = 500 * 1024 * 1024
DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_COMPRESSION_RATIO = 100

DEFAULT_BLOCK_EXTENSIONS: list[str] = [
    ".exe", ".dll", ".sys", ".drv",
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".com",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".lnk", ".pif", ".scr",
    ".msi", ".msp", ".msc",
    ".hta", ".cpl",
]


@dataclass
class ExtractionPolicy:
    """Defines what is allowed during extraction."""

    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE
    max_files: int = DEFAULT_MAX_FILES
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO

    block_extensions: list[str] = field(default_factory=lambda: list(DEFAULT_BLOCK_EXTENSIONS))
    rename_blocked: bool = True           # .exe -> .exe.blocked instead of hard block
    allow_symlinks: bool = False
    allow_overwrite: bool = False
    scan_hashes: bool = True
    block_rtlo: bool = True
    block_double_extension: bool = True
    block_ambiguous_archives: bool = True  # duplicate entry names

    @classmethod
    def from_file(cls, path: Path) -> "ExtractionPolicy":
        """Load policy from a JSON config file."""
        with open(path) as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def permissive(cls) -> "ExtractionPolicy":
        """Minimal restrictions — useful for trusted archives."""
        return cls(
            block_extensions=[],
            allow_symlinks=True,
            allow_overwrite=True,
            block_rtlo=False,
            block_double_extension=False,
            block_ambiguous_archives=False,
        )

    def to_dict(self) -> dict:
        return {
            "max_file_size": self.max_file_size,
            "max_total_size": self.max_total_size,
            "max_files": self.max_files,
            "max_compression_ratio": self.max_compression_ratio,
            "block_extensions": self.block_extensions,
            "rename_blocked": self.rename_blocked,
            "allow_symlinks": self.allow_symlinks,
            "allow_overwrite": self.allow_overwrite,
            "scan_hashes": self.scan_hashes,
            "block_rtlo": self.block_rtlo,
            "block_double_extension": self.block_double_extension,
            "block_ambiguous_archives": self.block_ambiguous_archives,
        }
