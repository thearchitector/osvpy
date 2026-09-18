"""Stable error categories, independent of upstream Go error text."""


class OSVError(Exception):
    """Base error for osvpy operations."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class ImageNotFoundError(OSVError):
    """The registry image does not exist."""


class RegistryAuthenticationError(OSVError):
    """Registry access was denied."""


class ScanError(OSVError):
    """Image acquisition, extraction or vulnerability matching failed."""


class InvalidImageError(ScanError, ValueError):
    """An image reference is invalid."""


class NativeLibraryError(OSVError):
    """The native library could not load or complete an operation."""
