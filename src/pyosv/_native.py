"""Small ctypes boundary. Every non-null returned allocation is freed once."""

import ctypes
import json
import platform
import threading
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from .exceptions import (
    ImageNotFoundError,
    InvalidImageError,
    NativeLibraryError,
    OfflineDatabaseError,
    RegistryAuthenticationError,
    ScanError,
)
from .models import NativeResponse

if TYPE_CHECKING:
    from typing import Any

_ERRORS = {
    "image_not_found": ImageNotFoundError,
    "registry_authentication": RegistryAuthenticationError,
    "invalid_image": InvalidImageError,
    "invalid_request": ScanError,
    "offline_unavailable": OfflineDatabaseError,
    "internal_error": NativeLibraryError,
}


def _library_path() -> Path:
    system = platform.system()
    names = {"Linux": "libpyosv.so", "Darwin": "libpyosv.dylib"}
    if system not in names:
        raise NativeLibraryError(f"No native library support for {system}")
    return Path(str(files("pyosv") / "_lib" / names[system]))


class NativeLibrary:
    def __init__(self) -> None:
        path = _library_path()
        try:
            self._lib = ctypes.CDLL(str(path))
            self._scan = self._lib.osv_scan_image
            self._scan.argtypes = [ctypes.c_char_p]
            # c_char_p as the return type would discard the allocation address.
            self._scan.restype = ctypes.c_void_p
            self._free = self._lib.osv_free_string
            self._free.argtypes = [ctypes.c_void_p]
            self._free.restype = None
        except OSError as exc:
            raise NativeLibraryError(
                f"Cannot load pyosv native library at {path}. Install a wheel for your "
                "platform, or build the native library for a source checkout."
            ) from exc

    def call(self, request: dict[str, "Any"]) -> NativeResponse:
        payload = json.dumps(request, ensure_ascii=False).encode("utf-8")
        ptr = self._scan(payload)
        try:
            envelope = NativeResponse.model_validate_json(ctypes.string_at(ptr))
        finally:
            self._free(ptr)
        if envelope.abi_version != 3:
            raise NativeLibraryError("Unsupported native ABI version")
        if not envelope.ok:
            error = envelope.error
            assert error is not None
            raise _ERRORS.get(error.code, ScanError)(error.message, code=error.code)
        return envelope


_instance: NativeLibrary | None = None
_load_lock = threading.Lock()


def scan(request: dict[str, "Any"]) -> NativeResponse:
    global _instance
    with _load_lock:
        if _instance is None:
            _instance = NativeLibrary()
        native = _instance
    # CDLL releases the GIL; the Go mutex protects the upstream global logger.
    return native.call(request)
