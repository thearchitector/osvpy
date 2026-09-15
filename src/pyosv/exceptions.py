"""Stable error categories, independent of upstream Go error text."""


class OSVError(Exception):
    """Base error for pyosv operations."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class ImageNotFoundError(OSVError):
    """The registry image or archive does not exist."""


class RegistryAuthenticationError(OSVError):
    """Registry access was denied."""


class ScanError(OSVError):
    """Image acquisition, extraction or vulnerability matching failed."""


class InvalidImageError(ScanError, ValueError):
    """An image reference or source is invalid."""


class OfflineDatabaseError(ScanError):
    """Offline scanning cannot proceed with the provided image/databases."""


class NativeLibraryError(OSVError):
    """The native library is unavailable or violated the JSON ABI."""
