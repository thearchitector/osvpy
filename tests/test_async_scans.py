import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import osvpy
from osvpy.languages import resolve_languages


def test_many_tasks_and_shared_result_readers(package_image: str) -> None:
    async def run() -> list[osvpy.BatchResult]:
        return await asyncio.gather(
            *(osvpy.scan(package_image, package_image) for _ in range(8))
        )

    batches = asyncio.run(run())
    assert all(batch.complete for batch in batches)
    assert len({batch.packages[0] for batch in batches}) == 8
    view = batches[0].packages[0]
    del batches
    barrier = threading.Barrier(8)

    def read(_: int) -> None:
        barrier.wait(10)
        for _ in range(100):
            assert [im.index for im in view.present_images] == [0, 1]
            assert view.name == "example"
            assert view.findings[0].advisory_source.summary

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(read, range(8)))


def test_language_coverage() -> None:
    assert resolve_languages(None) == resolve_languages(
        osvpy.LanguageSelection.INSTALLED
    )
    assert resolve_languages(osvpy.LanguageSelection.NONE) == ()
    plugins = [resolve_languages(selection) for selection in osvpy.LanguageSelection]
    assert all(len(group) == 1 for group in plugins)
    assert len(set(plugins)) == len(plugins)
    assert set(resolve_languages(osvpy.LanguageSelection.ALL)) == {
        group[0] for group in plugins
    }
    assert set(
        resolve_languages(osvpy.LanguageSelection.PYTHON | osvpy.LanguageSelection.JAVA)
    ) == (
        set(resolve_languages(osvpy.LanguageSelection.PYTHON))
        | set(resolve_languages(osvpy.LanguageSelection.JAVA))
    )


def test_concurrent_language_options(package_image: str) -> None:
    async def run() -> tuple[osvpy.BatchResult, osvpy.BatchResult]:
        enabled, disabled = await asyncio.gather(
            osvpy.scan(
                package_image,
                languages=osvpy.LanguageSelection.PYTHON_INSTALLED,
                all_packages=True,
            ),
            osvpy.scan(
                package_image, languages=osvpy.LanguageSelection.NONE, all_packages=True
            ),
        )
        return enabled, disabled

    enabled, disabled = asyncio.run(run())
    assert [p.name for p in enabled.packages] == ["example"]
    assert enabled.findings
    assert not disabled.packages
    assert not disabled.images[0].metadata.languages
    assert tuple(enabled.images[0].metadata.languages) == ("python/wheelegg",)


@pytest.mark.parametrize("workers", [0, -1])
def test_invalid_limits(workers: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        asyncio.run(osvpy.scan(workers=workers))


def test_cancel_while_executor_is_occupied() -> None:
    entered, release = threading.Event(), threading.Event()

    def occupy() -> None:
        entered.set()
        assert release.wait(10)

    async def run() -> None:
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        blocker = loop.run_in_executor(None, occupy)
        assert entered.wait(10)
        started = asyncio.Event()

        async def scan() -> osvpy.BatchResult:
            started.set()
            return await osvpy.scan("BAD IMAGE")

        task = asyncio.create_task(scan())
        await started.wait()
        task.cancel()
        task.cancel()
        release.set()
        await blocker
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await osvpy.scan()).complete

    asyncio.run(run())
