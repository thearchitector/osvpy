"""In-process container scanning with normalized, immutable batch reports."""

from .exceptions import (
    ImageNotFoundError,
    InvalidImageError,
    NativeLibraryError,
    OfflineDatabaseError,
    OSVError,
    RegistryAuthenticationError,
    ScanError,
)
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
from .scanner import scan_docker_archive, scan_image

__version__ = "0.1.0"
__all__ = [
    "AdvisorySource",
    "BatchResult",
    "Finding",
    "ImageNotFoundError",
    "ImageResult",
    "InvalidImageError",
    "NativeLibraryError",
    "OSVError",
    "Occurrence",
    "OfflineDatabaseError",
    "Package",
    "RegistryAuth",
    "RegistryAuthenticationError",
    "ScanError",
    "Vulnerability",
    "scan_docker_archive",
    "scan_image",
]
