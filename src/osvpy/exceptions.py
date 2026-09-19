"""Stable error categories, independent of upstream Go error text."""


class OSVError(Exception):
    """Base error for osvpy operations."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class NativeLibraryError(OSVError):
    """The native library could not load or complete an operation."""
