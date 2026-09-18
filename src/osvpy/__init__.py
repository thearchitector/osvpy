"""In-process container scanning with normalized, immutable batch reports."""

from .exceptions import (
    ImageNotFoundError,
    InvalidImageError,
    NativeLibraryError,
    OSVError,
    RegistryAuthenticationError,
    ScanError,
)
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
    "ImageNotFoundError",
    "ImageResult",
    "InvalidImageError",
    "LanguageSelection",
    "NativeLibraryError",
    "OSVError",
    "Occurrence",
    "Package",
    "RegistryAuth",
    "RegistryAuthenticationError",
    "ScanError",
    "Vulnerability",
    "scan",
]
