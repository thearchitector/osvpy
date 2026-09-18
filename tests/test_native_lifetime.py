"""Check actual Go roots, independently of allocator caches and GC timing."""

import asyncio
import ctypes
import gc
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, cast

import pytest

import osvpy
from osvpy import _native

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


@pytest.fixture
def live_results() -> "Callable[[], int]":
    library = ctypes.CDLL(_native.__file__)
    count = library.osv_result_count
    count.argtypes = []
    count.restype = ctypes.c_uint64

    def current() -> int:
        gc.collect()
        return int(count())

    return current


@pytest.mark.parametrize("images", [(), ("BAD IMAGE",)])
def test_last_reference_releases_report(
    images: tuple[str, ...], live_results: "Callable[[], int]"
) -> None:
    baseline = live_results()
    for _ in range(20):
        report = asyncio.run(osvpy.scan(*images))
        alias = report
        assert live_results() == baseline + 1
        del report
        assert live_results() == baseline + 1
        del alias
        assert live_results() == baseline


@pytest.mark.parametrize("keep", ["child", "sequence", "slice", "iterator"])
def test_views_keep_report_alive(keep: str, live_results: "Callable[[], int]") -> None:
    baseline = live_results()
    report = asyncio.run(osvpy.scan("BAD IMAGE"))
    retained: _native.NativeError | Iterable[_native.NativeError]
    if keep == "child":
        retained = report.images[0].diagnostics[0]
    elif keep == "sequence":
        retained = report.images[0].diagnostics
    elif keep == "slice":
        retained = report.images[0].diagnostics[:]
    else:
        retained = iter(report.images[0].diagnostics)
    del report
    assert live_results() == baseline + 1
    if keep == "child":
        assert cast("_native.NativeError", retained).code == "invalid_image"
    else:
        assert (
            next(iter(cast("Iterable[_native.NativeError]", retained))).code
            == "invalid_image"
        )
    del retained
    assert live_results() == baseline


def test_cyclic_gc_releases_report(live_results: "Callable[[], int]") -> None:
    baseline = live_results()
    cycle: list[object] = [asyncio.run(osvpy.scan("BAD IMAGE"))]
    cycle.append(cycle)
    assert live_results() == baseline + 1
    del cycle
    assert live_results() == baseline


def test_copied_values_do_not_retain_report(
    package_image: str, live_results: "Callable[[], int]"
) -> None:
    baseline = live_results()
    report = asyncio.run(osvpy.scan(package_image))
    name = report.packages[0].name
    summary = report.advisory_sources[0].summary
    index = report.images[0].index
    complete = report.complete
    del report
    assert live_results() == baseline
    assert name == "example"
    assert summary
    assert index == 0
    assert complete


def test_completed_task_owns_result(live_results: "Callable[[], int]") -> None:
    baseline = live_results()

    async def run() -> None:
        task = asyncio.create_task(osvpy.scan("BAD IMAGE"))
        report = await task
        del report
        assert live_results() == baseline + 1

    asyncio.run(run())
    assert live_results() == baseline


def test_last_reference_can_be_dropped_on_another_thread(
    live_results: "Callable[[], int]",
) -> None:
    baseline = live_results()
    reports = [asyncio.run(osvpy.scan("BAD IMAGE"))]
    assert live_results() == baseline + 1
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(reports.clear).result()
    assert live_results() == baseline


def test_retained_native_error_does_not_own_report(
    live_results: "Callable[[], int]",
) -> None:
    baseline = live_results()
    controller = _native.CancellationController()
    controller.cancel()
    with pytest.raises(osvpy.NativeLibraryError) as error:
        _native.scan(b'{"inputs": [], "workers": 1}', controller)
    assert error.value.__traceback__ is not None
    assert live_results() == baseline
