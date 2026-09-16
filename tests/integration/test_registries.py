from typing import TYPE_CHECKING

import pytest

import osvpy

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64"])
def test_anonymous_pull_selects_platform(
    registry_factory: "Callable[..., str]", platform: str
) -> None:
    result = osvpy.scan_image(registry_factory(), platform=platform)
    assert result.complete
    assert result.images[0].data.metadata.image_platform == platform


def test_empty_image(registry_factory: "Callable[..., str]") -> None:
    result = osvpy.scan_image(registry_factory())
    assert result.complete
    assert result.images[0].data.metadata.no_packages
    assert not result.packages
    assert not result.vulnerabilities


def test_explicit_credentials(registry_factory: "Callable[..., str]") -> None:
    auth = osvpy.RegistryAuth("reader", "secret")
    image = registry_factory(auth=auth)
    assert osvpy.scan_image(image, auth=auth).complete
    for bad in (None, osvpy.RegistryAuth("reader", "wrong")):
        result = osvpy.scan_image(image, auth=bad)
        assert not result.complete
        assert result.errors[0][1].code == "registry_authentication"


@pytest.mark.parametrize(
    ("status", "code"),
    [(403, "registry_authentication"), (404, "image_not_found"), (418, "scan_error")],
)
def test_registry_failure_category(
    registry_factory: "Callable[..., str]", status: int, code: str
) -> None:
    result = osvpy.scan_image(registry_factory(status=status))
    assert result.errors[0][1].code == code


def test_invalid_reference_and_offline() -> None:
    assert osvpy.scan_image("UPPER CASE").errors[0][1].code == "invalid_image"
    with pytest.raises(osvpy.OfflineDatabaseError):
        osvpy.scan_image("ubuntu:latest", offline=True)
