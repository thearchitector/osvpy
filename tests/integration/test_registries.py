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
    assert result.metadata.image_platform == platform


def test_image_without_packages_is_a_successful_scan(
    registry_factory: "Callable[..., str]",
) -> None:
    result = osvpy.scan_image(registry_factory())
    assert result.metadata.no_packages
    assert result.packages == []
    assert result.vulnerabilities == []


def test_private_registry_accepts_credentials(
    registry_factory: "Callable[..., str]",
) -> None:
    image = registry_factory(auth=osvpy.RegistryAuth("reader", "secret"))
    result = osvpy.scan_image(image, auth=osvpy.RegistryAuth("reader", "secret"))
    assert result.metadata.image_digest is not None


@pytest.mark.parametrize(
    "auth", [None, osvpy.RegistryAuth("reader", "wrong")], ids=["missing", "incorrect"]
)
def test_private_registry_rejects_invalid_credentials(
    registry_factory: "Callable[..., str]", auth: osvpy.RegistryAuth | None
) -> None:
    image = registry_factory(auth=osvpy.RegistryAuth("reader", "secret"))
    with pytest.raises(osvpy.RegistryAuthenticationError):
        osvpy.scan_image(image, auth=auth)


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (403, osvpy.RegistryAuthenticationError),
        (404, osvpy.ImageNotFoundError),
        (418, osvpy.ScanError),
    ],
)
def test_registry_failure_category(
    registry_factory: "Callable[..., str]", status: int, error: type[osvpy.OSVError]
) -> None:
    with pytest.raises(error):
        osvpy.scan_image(registry_factory(status=status))


def test_invalid_image_reference() -> None:
    with pytest.raises(osvpy.InvalidImageError):
        osvpy.scan_image("UPPER CASE")


def test_remote_image_cannot_be_scanned_offline() -> None:
    with pytest.raises(osvpy.OfflineDatabaseError):
        osvpy.scan_image("ubuntu:latest", offline=True)
