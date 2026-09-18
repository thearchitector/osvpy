"""Public API concurrency checks using real native scans and local fixtures."""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import osvpy
from explore_toolkit.images import registry_resources, serve_registry


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
            executor.submit(
                lambda *a, **k: asyncio.run(osvpy.scan(*a, **k)),
                image,
                auth=auth,
                platform=platform,
            )
            for image, auth, platform in zip(
                [first, second], auths, ["linux/amd64", "linux/arm64"], strict=True
            )
        ]
        batches = [future.result(timeout=30) for future in futures]
    assert all(batch.complete for batch in batches)
    assert [batch.images[0].metadata.image_platform for batch in batches] == [
        "linux/amd64",
        "linux/arm64",
    ]


def test_license_policy_is_snapshotted_before_network_work() -> None:
    policy = ["MIT"]
    barrier = threading.Barrier(2, action=lambda: policy.append("GPL-3.0-only"))
    resources = registry_resources({
        "etc/os-release": b"ID=alpine\nVERSION_ID=3.20.0\n",
        "etc/alpine-release": b"3.20.0\n",
        "lib/apk/db/installed": b"P:osvpy-license-forbidden\nV:1.0-r0\nA:x86_64\nL:GPL-3.0-only\n\n",
    })

    async def run(image: str) -> osvpy.BatchResult:
        task = asyncio.create_task(osvpy.scan(image, allowed_licenses=policy))
        await asyncio.to_thread(barrier.wait, 10)
        return await task

    with serve_registry(resources, barrier=barrier) as image:
        report = asyncio.run(run(image))
    assert report.complete
    (occurrence,) = report.images[0].occurrences
    assert tuple(occurrence.license_assessment.policy or ()) == ("MIT",)
    assert occurrence.license_assessment.status == "noncompliant"
