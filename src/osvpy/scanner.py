"""Public synchronous API; scanners execute in the calling process."""

import logging
import os
from typing import TYPE_CHECKING

from . import _native

if TYPE_CHECKING:
    from collections.abc import Collection
    from typing import Any, Literal, TypedDict, Unpack, overload

    from .models import FullScanResult, RegistryAuth, ScanResult

    class _ScanOptions(TypedDict, total=False):
        offline: bool
        all_packages: bool
        allowed_licenses: Collection[str] | None
        database_path: str | os.PathLike[str] | None

    class _ImageOptions(_ScanOptions, total=False):
        auth: RegistryAuth | None
        platform: str | None


logger = logging.getLogger("osvpy")


def _scan(
    image: str,
    source: str,
    *,
    offline: bool,
    all_packages: bool,
    detail: "Literal['compact', 'full']",
    allowed_licenses: "Collection[str] | None",
    auth: "RegistryAuth | None" = None,
    platform: str | None = None,
    database_path: str | os.PathLike[str] | None = None,
) -> "ScanResult | FullScanResult":
    if detail not in ("compact", "full"):
        raise ValueError("detail must be compact or full")
    request: dict[str, Any] = {
        "image": image,
        "source": source,
        "offline": offline,
        "all_packages": all_packages,
        "detail": detail,
    }
    if allowed_licenses is not None:
        request["allowed_licenses"] = sorted(allowed_licenses)
    if auth is not None:
        request["auth"] = {"username": auth.username, "password": auth.password}
    if platform is not None:
        request["platform"] = platform
    if database_path is not None:
        request["database_path"] = os.fspath(database_path)
    envelope = _native.scan(request)
    result = envelope.result if detail == "full" else envelope.report
    assert result is not None
    logger.debug("Scan completed in %s seconds", result.metadata.duration_seconds)
    return result


if TYPE_CHECKING:

    @overload
    def scan_image(
        image: str,
        *,
        detail: Literal["compact"] = "compact",
        **options: Unpack[_ImageOptions],
    ) -> ScanResult: ...

    @overload
    def scan_image(
        image: str, *, detail: Literal["full"], **options: Unpack[_ImageOptions]
    ) -> FullScanResult: ...


def scan_image(
    image: str,
    *,
    offline: bool = False,
    all_packages: bool = False,
    detail: "Literal['compact', 'full']" = "compact",
    allowed_licenses: "Collection[str] | None" = None,
    auth: "RegistryAuth | None" = None,
    platform: str | None = None,
    database_path: str | os.PathLike[str] | None = None,
) -> "ScanResult | FullScanResult":
    """Pull and scan a Linux image directly from an OCI registry.

    Tags, digests and explicit basic registry credentials are supported. The
    default platform follows go-containerregistry (linux/amd64). Offline calls
    fail: use scan_docker_archive with pre-populated OSV databases instead.
    """
    return _scan(
        image,
        "registry",
        offline=offline,
        all_packages=all_packages,
        detail=detail,
        allowed_licenses=allowed_licenses,
        auth=auth,
        platform=platform,
        database_path=database_path,
    )


if TYPE_CHECKING:

    @overload
    def scan_docker_archive(
        path: str | os.PathLike[str],
        *,
        detail: Literal["compact"] = "compact",
        **options: Unpack[_ScanOptions],
    ) -> ScanResult: ...

    @overload
    def scan_docker_archive(
        path: str | os.PathLike[str],
        *,
        detail: Literal["full"],
        **options: Unpack[_ScanOptions],
    ) -> FullScanResult: ...


def scan_docker_archive(
    path: str | os.PathLike[str],
    *,
    offline: bool = False,
    all_packages: bool = False,
    detail: "Literal['compact', 'full']" = "compact",
    allowed_licenses: "Collection[str] | None" = None,
    database_path: str | os.PathLike[str] | None = None,
) -> "ScanResult | FullScanResult":
    """Scan a single-image Docker save archive; never invokes Docker."""
    return _scan(
        os.fspath(path),
        "docker_archive",
        offline=offline,
        all_packages=all_packages,
        detail=detail,
        allowed_licenses=allowed_licenses,
        database_path=database_path,
    )
