"""zipguard — Security-focused archive extraction with policy enforcement."""

from zipguard.extractor import SafeExtractor
from zipguard.policy import ExtractionPolicy

__all__ = ["SafeExtractor", "ExtractionPolicy"]
__version__ = "0.2.0"
