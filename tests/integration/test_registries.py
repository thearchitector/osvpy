from typing import TYPE_CHECKING

import pytest

import pyosv

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64"])
def test_anonymous_pull_selects_platform(
    registry_factory: "Callable[..., str]", platform: str
) -> None:
    result = pyosv.scan_image(registry_factory(), platform=platform)
    assert result.metadata.image_platform == platform


def test_image_without_packages_is_a_successful_scan(
    registry_factory: "Callable[..., str]",
) -> None:
    result = pyosv.scan_image(registry_factory())
    assert result.metadata.no_packages
    assert result.packages == []
    assert result.vulnerabilities == []


def test_private_registry_accepts_credentials(
    registry_factory: "Callable[..., str]",
) -> None:
    image = registry_factory(auth=pyosv.RegistryAuth("reader", "secret"))
    result = pyosv.scan_image(image, auth=pyosv.RegistryAuth("reader", "secret"))
    assert result.metadata.image_digest is not None


@pytest.mark.parametrize(
    "auth", [None, pyosv.RegistryAuth("reader", "wrong")], ids=["missing", "incorrect"]
)
def test_private_registry_rejects_invalid_credentials(
    registry_factory: "Callable[..., str]", auth: pyosv.RegistryAuth | None
) -> None:
    image = registry_factory(auth=pyosv.RegistryAuth("reader", "secret"))
    with pytest.raises(pyosv.RegistryAuthenticationError):
        pyosv.scan_image(image, auth=auth)


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (403, pyosv.RegistryAuthenticationError),
        (404, pyosv.ImageNotFoundError),
        (418, pyosv.ScanError),
    ],
)
def test_registry_failure_category(
    registry_factory: "Callable[..., str]", status: int, error: type[pyosv.OSVError]
) -> None:
    with pytest.raises(error):
        pyosv.scan_image(registry_factory(status=status))


def test_invalid_image_reference() -> None:
    with pytest.raises(pyosv.InvalidImageError):
        pyosv.scan_image("UPPER CASE")


def test_remote_image_cannot_be_scanned_offline() -> None:
    with pytest.raises(pyosv.OfflineDatabaseError):
        pyosv.scan_image("ubuntu:latest", offline=True)
