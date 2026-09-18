import asyncio
from typing import TYPE_CHECKING

import pytest

import osvpy

if TYPE_CHECKING:
    from collections.abc import Iterator

from explore_toolkit.images import registry_resources, serve_registry


@pytest.fixture
def licensed_image() -> "Iterator[str]":
    resources = registry_resources({
        "etc/os-release": b"ID=alpine\nVERSION_ID=3.20.0\n",
        "etc/alpine-release": b"3.20.0\n",
        "lib/apk/db/installed": (
            b"P:osvpy-license-allowed\nV:1.0-r0\nA:x86_64\nL:MIT OR Apache-2.0\n\n"
            b"P:osvpy-license-forbidden\nV:1.0-r0\nA:x86_64\nL:GPL-3.0-only\n\n"
        ),
    })
    with serve_registry(resources) as image:
        yield image


@pytest.mark.parametrize(
    ("allowed", "forbidden"),
    [
        ({"MIT"}, {"osvpy-license-forbidden"}),
        ({"MIT", "GPL-3.0-only"}, set()),
        (set(), {"osvpy-license-allowed", "osvpy-license-forbidden"}),
    ],
)
def test_license_policy(
    licensed_image: str, allowed: set[str], forbidden: set[str]
) -> None:
    result = asyncio.run(osvpy.scan(licensed_image, allowed_licenses=allowed))
    assert result.complete
    assert not result.vulnerabilities
    assert {p.name for p in result.images[0].noncompliant_packages} == forbidden
    for o in result.images[0].occurrences:
        assert tuple(o.license_assessment.policy or ()) == tuple(sorted(allowed))
        assert o.license_assessment.status == "noncompliant"
        assert o.package.noncompliant_images
        assert not o.package.vulnerable_images


def test_license_expression(licensed_image: str) -> None:
    result = asyncio.run(osvpy.scan(licensed_image, allowed_licenses={"MIT"}))
    assert result.complete
    (o,) = result.images[0].occurrences
    assert tuple(o.license_assessment.violations) == ("GPL-3.0-only",)


def test_empty_policy_is_distinct_from_no_policy() -> None:
    resources = registry_resources({
        "etc/os-release": b"ID=alpine\nVERSION_ID=3.20.0\n",
        "etc/alpine-release": b"3.20.0\n",
        "lib/apk/db/installed": b"P:osvpy-license-unknown\nV:1.0-r0\nA:x86_64\n\n",
    })
    with serve_registry(resources) as image:
        unknown = asyncio.run(osvpy.scan(image, allowed_licenses=[]))
        disabled = asyncio.run(osvpy.scan(image, all_packages=True))
    (occurrence,) = unknown.images[0].occurrences
    assert occurrence.license_assessment.policy is not None
    assert not occurrence.license_assessment.policy
    assert disabled.images[0].occurrences[0].license_assessment.policy is None
    assert (
        disabled.images[0].occurrences[0].license_assessment.status == "not_evaluated"
    )
