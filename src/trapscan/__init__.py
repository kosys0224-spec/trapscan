"""trapscan - scan a repository for things that run the moment you open it."""

__version__ = "0.1.0"
__all__ = ["__version__", "scan_path", "Finding", "Severity"]

from .findings import Finding, Severity  # noqa: E402
from .scanner import scan_path  # noqa: E402
