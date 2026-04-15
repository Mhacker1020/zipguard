"""safe-extract — Security-focused archive extraction with policy enforcement."""

from safe_extract.extractor import SafeExtractor
from safe_extract.policy import ExtractionPolicy

__all__ = ["SafeExtractor", "ExtractionPolicy"]
__version__ = "0.1.0"
