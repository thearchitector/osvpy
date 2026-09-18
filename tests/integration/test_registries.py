import asyncio
from typing import TYPE_CHECKING

import pytest

import osvpy

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64"])
def test_anonymous_pull_selects_platform(
    registry_factory: "Callable[..., str]", platform: str
) -> None:
    result = asyncio.run(osvpy.scan(registry_factory(), platform=platform))
    assert result.complete
    assert result.images[0].metadata.image_platform == platform


def test_empty_image(registry_factory: "Callable[..., str]") -> None:
    result = asyncio.run(osvpy.scan(registry_factory()))
    assert result.complete
    assert result.images[0].metadata.no_packages
    assert not result.packages
    assert not result.vulnerabilities


def test_explicit_credentials(registry_factory: "Callable[..., str]") -> None:
    auth = osvpy.RegistryAuth("reader", "secret")
    image = registry_factory(auth=auth)
    assert asyncio.run(osvpy.scan(image, auth=auth)).complete
    for bad in (None, osvpy.RegistryAuth("reader", "wrong")):
        result = asyncio.run(osvpy.scan(image, auth=bad))
        assert not result.complete
        assert result.errors[0][1].code == "registry_authentication"


@pytest.mark.parametrize(
    ("status", "code"),
    [(403, "registry_authentication"), (404, "image_not_found"), (418, "scan_error")],
)
def test_registry_failure_category(
    registry_factory: "Callable[..., str]", status: int, code: str
) -> None:
    result = asyncio.run(osvpy.scan(registry_factory(status=status)))
    assert result.errors[0][1].code == code


def test_invalid_reference() -> None:
    assert asyncio.run(osvpy.scan("UPPER CASE")).errors[0][1].code == "invalid_image"
