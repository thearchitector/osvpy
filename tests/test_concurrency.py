"""Public API concurrency checks using real native scans and local fixtures."""

import gc
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import osvpy
from explore_toolkit.images import make_fixture, registry_resources, serve_registry

if TYPE_CHECKING:
    from pathlib import Path


def test_eight_threads_keep_results_independent(tmp_path: "Path") -> None:
    archives = []
    for index in range(8):
        directory = tmp_path / str(index)
        directory.mkdir()
        archive, database = make_fixture(directory, version=f"3.0.0-{index % 2}")
        archives.append(archive)
    # All workers share a read-only database, prepared before any scan starts.
    start = threading.Barrier(8)

    def worker(index: int) -> None:
        start.wait(timeout=15)
        views = []
        for iteration in range(4):
            inventory = (index + iteration) % 2 == 0
            batch = osvpy.scan_docker_archive(
                archives[index],
                tmp_path / "missing.tar",
                archives[index],
                offline=True,
                database_path=database,
                all_packages=inventory,
            )
            assert [im.complete for im in batch.images] == [True, False, True]
            assert batch.errors[0][0] == 1
            assert {p.data.name for p in batch.packages} == (
                {"openssl", "unaffected"} if inventory else {"openssl"}
            )
            package = next(p for p in batch.packages if p.data.name == "openssl")
            assert package.data.version == f"3.0.0-{index % 2}"
            assert [im.index for im in package.present_images] == [0, 2]
            assert batch.images[0].data.metadata.all_packages is inventory
            views.append(batch.vulnerabilities[0])
            del batch
        gc.collect()
        assert all(v.data.id == "OSVPY-TEST-0001" for v in views)
        assert all([im.index for im in v.affected_images] == [0, 2] for v in views)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(worker, range(8)))


def test_registry_calls_overlap_with_isolated_credentials_and_platforms() -> None:
    barrier = threading.Barrier(2)
    resources = registry_resources()
    auths = [osvpy.RegistryAuth("first", "one"), osvpy.RegistryAuth("second", "two")]
    with (
        serve_registry(resources, auth=auths[0], barrier=barrier) as first,
        serve_registry(resources, auth=auths[1], barrier=barrier) as second,
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        futures = [
            executor.submit(osvpy.scan_image, image, auth=auth, platform=platform)
            for image, auth, platform in zip(
                [first, second], auths, ["linux/amd64", "linux/arm64"], strict=True
            )
        ]
        batches = [future.result(timeout=30) for future in futures]
    assert all(batch.complete for batch in batches)
    assert [batch.images[0].data.metadata.image_platform for batch in batches] == [
        "linux/amd64",
        "linux/arm64",
    ]
