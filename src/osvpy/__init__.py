"""In-process container scanning with normalized, immutable batch reports."""

from .exceptions import NativeLibraryError, OSVError
from .languages import LanguageSelection
from .models import (
    AdvisorySource,
    BatchResult,
    Finding,
    ImageResult,
    Occurrence,
    Package,
    RegistryAuth,
    Vulnerability,
)
from .scanner import scan

__version__ = "0.1.0"
__all__ = [
    "AdvisorySource",
    "BatchResult",
    "Finding",
    "ImageResult",
    "LanguageSelection",
    "NativeLibraryError",
    "OSVError",
    "Occurrence",
    "Package",
    "RegistryAuth",
    "Vulnerability",
    "scan",
]
