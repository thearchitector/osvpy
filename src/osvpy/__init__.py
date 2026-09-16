"""In-process container scanning with bundled OSV-Scanner and Pydantic reports."""

from .exceptions import (
    ImageNotFoundError,
    InvalidImageError,
    NativeLibraryError,
    OfflineDatabaseError,
    OSVError,
    RegistryAuthenticationError,
    ScanError,
)
from .models import FullScanResult, RegistryAuth, ScanResult, Vulnerability
from .scanner import scan_docker_archive, scan_image

__version__ = "0.1.0"
__all__ = [
    "FullScanResult",
    "ImageNotFoundError",
    "InvalidImageError",
    "NativeLibraryError",
    "OSVError",
    "OfflineDatabaseError",
    "RegistryAuth",
    "RegistryAuthenticationError",
    "ScanError",
    "ScanResult",
    "Vulnerability",
    "scan_docker_archive",
    "scan_image",
]
