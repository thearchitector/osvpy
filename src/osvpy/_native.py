"""ABI 4 construction; all C output is released before returning Python views."""

import ctypes
import json
import platform
import threading
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from ._store import decode
from .exceptions import NativeLibraryError
from .models import BatchResult

if TYPE_CHECKING:
    from typing import Any


def _library_path() -> Path:
    names = {"Linux": "libosvpy.so", "Darwin": "libosvpy.dylib"}
    system = platform.system()
    if system not in names:
        raise NativeLibraryError(f"No native library support for {system}")
    return Path(str(files("osvpy") / "_lib" / names[system]))


def _check(status: int) -> None:
    if status:
        code = {1: "internal_error", 2: "report_overflow", 3: "allocation_failure"}[
            status
        ]
        raise NativeLibraryError(f"Native batch failed: {code}", code=code)


class NativeLibrary:
    def __init__(self) -> None:
        path = _library_path()
        try:
            self._lib = ctypes.CDLL(str(path))
            self._begin = self._lib.osv_batch_begin
            self._begin.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
            self._begin.restype = ctypes.c_int
            self._add = self._lib.osv_batch_add
            self._add.argtypes = [ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
            self._add.restype = ctypes.c_int
            self._finish = self._lib.osv_batch_finish
            self._finish.argtypes = [
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_size_t),
            ]
            self._finish.restype = ctypes.c_int
            self._abort = self._lib.osv_batch_abort
            self._abort.argtypes = [ctypes.c_size_t]
            self._abort.restype = ctypes.c_int
            self._free = self._lib.osv_report_free
            self._free.argtypes = [ctypes.c_void_p]
            self._free.restype = None
        except OSError as exc:
            raise NativeLibraryError(
                f"Cannot load ABI 4 native library at {path}; rebuild or reinstall osvpy"
            ) from exc

    def call(self, inputs: tuple[str, ...], request: dict[str, "Any"]) -> BatchResult:
        payload = json.dumps(request, ensure_ascii=False).encode("utf-8")
        handle = ctypes.c_size_t()
        ptr = ctypes.c_void_p()
        size = ctypes.c_size_t()
        try:
            _check(self._begin(payload, ctypes.byref(handle)))
            for image in inputs:
                # Python regains control between adds, including cancellation.
                encoded = image.encode("utf-8")
                _check(self._add(handle, encoded, len(encoded)))
            _check(self._finish(handle, ctypes.byref(ptr), ctypes.byref(size)))
            return BatchResult(decode(ctypes.string_at(ptr, size.value)))
        finally:
            if ptr.value:
                self._free(ptr)
            if handle.value:
                _check(self._abort(handle))


_instance: NativeLibrary | None = None
_init_lock = threading.Lock()


def scan(inputs: tuple[str, ...], request: dict[str, "Any"]) -> BatchResult:
    global _instance
    with _init_lock:
        if _instance is None:
            _instance = NativeLibrary()
        instance = _instance
    return instance.call(inputs, request)
