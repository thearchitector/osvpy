"""Scan coroutine behavior with an isolated, controllable backend."""

import asyncio
import json
from threading import Event
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

import osvpy
from osvpy import RegistryAuth, scanner

if TYPE_CHECKING:
    from collections.abc import Callable


class Controller:
    def __init__(self) -> None:
        self.stopped = Event()

    def cancel(self) -> None:
        self.stopped.set()


@pytest.fixture
def backend(monkeypatch: pytest.MonkeyPatch) -> "Callable[..., None]":
    def install(operation: "Callable[[bytes, Controller], osvpy.BatchResult]") -> None:
        monkeypatch.setattr(
            scanner,
            "_native",
            SimpleNamespace(CancellationController=Controller, scan=operation),
        )

    return install


def test_scan_returns_backend_result(backend: "Callable[..., None]") -> None:
    expected = cast("osvpy.BatchResult", object())
    backend(lambda payload, controller: expected)
    assert asyncio.run(osvpy.scan("example:latest")) is expected


def test_scan_propagates_backend_failure(backend: "Callable[..., None]") -> None:
    def fail(payload: bytes, controller: Controller) -> osvpy.BatchResult:
        raise osvpy.NativeLibraryError("cannot scan", code="scan_error")

    backend(fail)
    with pytest.raises(osvpy.NativeLibraryError, match="cannot scan") as error:
        asyncio.run(osvpy.scan("example:latest"))
    assert error.value.code == "scan_error"


def test_scan_encodes_the_public_request_options(
    backend: "Callable[..., None]",
) -> None:
    captured: dict[str, object] = {}
    expected = cast("osvpy.BatchResult", object())

    def work(payload: bytes, controller: Controller) -> osvpy.BatchResult:
        captured.update(json.loads(payload))
        return expected

    backend(work)
    result = asyncio.run(
        osvpy.scan(
            "registry.example/😀:latest",
            "registry.example/other:v2",
            languages=osvpy.LanguageSelection.PYTHON,
            all_packages=True,
            allowed_licenses=["MIT", "Apache-2.0", "MIT"],
            workers=3,
            auth=RegistryAuth("user", "password"),
            platform="linux/arm64",
        )
    )

    assert result is expected
    assert captured == {
        "inputs": ["registry.example/😀:latest", "registry.example/other:v2"],
        "all_packages": True,
        "allowed_licenses": ["Apache-2.0", "MIT"],
        "auth": {"username": "user", "password": "password"},
        "platform": "linux/arm64",
        "workers": 3,
        "languages": [
            "python/wheelegg",
            "python/requirements",
            "python/poetrylock",
            "python/pipfilelock",
            "python/pdmlock",
            "python/pylock",
            "python/uvlock",
        ],
    }


def test_scan_encodes_documented_defaults(backend: "Callable[..., None]") -> None:
    captured: dict[str, object] = {}

    def work(payload: bytes, controller: Controller) -> osvpy.BatchResult:
        captured.update(json.loads(payload))
        return cast("osvpy.BatchResult", object())

    backend(work)
    asyncio.run(osvpy.scan())

    assert captured == {
        "inputs": [],
        "all_packages": False,
        "allowed_licenses": None,
        "auth": None,
        "platform": "",
        "workers": 1,
        "languages": [
            "go/binary",
            "java/archive",
            "javascript/nodemodules",
            "python/wheelegg",
            "rust/cargoauditable",
        ],
    }


def test_scan_cancellation_wins_over_worker_failure(
    backend: "Callable[..., None]",
) -> None:
    started, stopped = Event(), Event()

    def work(payload: bytes, controller: Controller) -> osvpy.BatchResult:
        started.set()
        assert controller.stopped.wait(10)
        stopped.set()
        raise osvpy.NativeLibraryError("worker failed", code="worker_error")

    backend(work)

    async def run() -> None:
        task = asyncio.create_task(osvpy.scan("example:latest"))
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stopped.is_set()

    asyncio.run(run())


@pytest.mark.parametrize("workers", [0, -1])
def test_scan_rejects_nonpositive_worker_limit(workers: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        asyncio.run(osvpy.scan(workers=workers))


def test_cancellation_waits_for_work_to_finish(backend: "Callable[..., None]") -> None:
    started, finished = Event(), Event()

    def work(payload: bytes, controller: Controller) -> osvpy.BatchResult:
        started.set()
        try:
            if not controller.stopped.wait(10):
                raise TimeoutError("work was not cancelled")
            return cast("osvpy.BatchResult", object())
        finally:
            finished.set()

    backend(work)

    async def run() -> None:
        task = asyncio.create_task(osvpy.scan("example:latest"))
        try:
            assert await asyncio.to_thread(started.wait, 10)
        finally:
            task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()

    asyncio.run(run())
