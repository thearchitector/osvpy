import ctypes
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from osvpy import NativeLibraryError, ScanError, _native
from osvpy.models import NativeResponse

if TYPE_CHECKING:
    from typing import Any


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b'{"abi_version":3,"ok":true}', None),
        (b"not json", ValidationError),
        (b'{"abi_version":4,"ok":true}', NativeLibraryError),
        (
            b'{"abi_version":3,"ok":false,"error":{"code":"scan_error","message":"failed"}}',
            ScanError,
        ),
    ],
)
def test_response_freed_before_validation(
    monkeypatch: pytest.MonkeyPatch, payload: bytes, error: type[Exception] | None
) -> None:
    buffer = ctypes.create_string_buffer(payload)
    address = ctypes.addressof(buffer)
    freed: list[int] = []
    library = object.__new__(_native.NativeLibrary)
    monkeypatch.setattr(library, "_scan", lambda _: address, raising=False)
    monkeypatch.setattr(library, "_free", freed.append, raising=False)
    validate = NativeResponse.model_validate_json

    def validate_after_free(data: bytes) -> NativeResponse:
        assert freed == [address]
        assert data == payload
        return validate(data)

    monkeypatch.setattr(NativeResponse, "model_validate_json", validate_after_free)
    if error is None:
        assert library.call({}).ok
    else:
        with pytest.raises(error):
            library.call({})
    assert freed == [address]


def test_copy_failure_frees_response(monkeypatch: pytest.MonkeyPatch) -> None:
    freed: list[int] = []
    library = object.__new__(_native.NativeLibrary)
    monkeypatch.setattr(library, "_scan", lambda _: 123, raising=False)
    monkeypatch.setattr(library, "_free", freed.append, raising=False)

    def fail_copy(_: int) -> bytes:
        raise MemoryError

    monkeypatch.setattr(ctypes, "string_at", fail_copy)
    with pytest.raises(MemoryError):
        library.call({})
    assert freed == [123]


def test_scan_serializes_entire_call_and_releases_lock_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    second_started = threading.Event()
    calls: list[int] = []

    class Library:
        def call(self, request: dict[str, "Any"]) -> NativeResponse:
            calls.append(request["id"])
            if request["id"] == 1:
                entered.set()
                assert release.wait(5)
                raise ScanError("fixture failure")
            return NativeResponse(abi_version=3, ok=True)

    monkeypatch.setattr(_native, "_instance", Library())

    def second_scan() -> NativeResponse:
        second_started.set()
        return _native.scan({"id": 2})

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_native.scan, {"id": 1})
        try:
            assert entered.wait(5)
            second = executor.submit(second_scan)
            assert second_started.wait(5)
            assert _native._scan_lock.locked()
            assert calls == [1]
        finally:
            release.set()
        with pytest.raises(ScanError, match="fixture failure"):
            first.result(timeout=5)
        assert second.result(timeout=5).ok
    assert calls == [1, 2]
