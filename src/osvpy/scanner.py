"""Synchronous variadic scanning with uniform batch options."""

import os
from typing import TYPE_CHECKING

from . import _native
from .exceptions import OfflineDatabaseError

if TYPE_CHECKING:
    from collections.abc import Collection
    from typing import Any

    from .models import BatchResult, RegistryAuth


def _scan(
    inputs: tuple[str, ...],
    source: str,
    *,
    offline: bool,
    all_packages: bool,
    allowed_licenses: "Collection[str] | None",
    database_path: str | os.PathLike[str] | None,
    auth: "RegistryAuth | None" = None,
    platform: str | None = None,
) -> "BatchResult":
    req: dict[str, Any] = {
        "source": source,
        "offline": offline,
        "all_packages": all_packages,
    }
    if allowed_licenses is not None:
        req["allowed_licenses"] = sorted(set(allowed_licenses))
    if database_path is not None:
        req["database_path"] = os.fspath(database_path)
    if auth is not None:
        req["auth"] = {"username": auth.username, "password": auth.password}
    if platform is not None:
        req["platform"] = platform
    if offline and (
        source == "registry"
        or not req.get("database_path")
        or allowed_licenses is not None
    ):
        raise OfflineDatabaseError(
            "Offline scans require archives, a populated database_path, and no license policy"
        )
    return _native.scan(inputs, req)


def scan_image(
    *images: str,
    offline: bool = False,
    all_packages: bool = False,
    allowed_licenses: "Collection[str] | None" = None,
    auth: "RegistryAuth | None" = None,
    platform: str | None = None,
    database_path: str | os.PathLike[str] | None = None,
) -> "BatchResult":
    """Scan registry images in request order; acquisition failures become failed slots."""
    return _scan(
        images,
        "registry",
        offline=offline,
        all_packages=all_packages,
        allowed_licenses=allowed_licenses,
        auth=auth,
        platform=platform,
        database_path=database_path,
    )


def scan_docker_archive(
    *paths: str | os.PathLike[str],
    offline: bool = False,
    all_packages: bool = False,
    allowed_licenses: "Collection[str] | None" = None,
    database_path: str | os.PathLike[str] | None = None,
) -> "BatchResult":
    """Scan individual single-image Docker-save archives; never invokes Docker."""
    inputs = tuple(os.fspath(path) for path in paths)
    return _scan(
        inputs,
        "docker_archive",
        offline=offline,
        all_packages=all_packages,
        allowed_licenses=allowed_licenses,
        database_path=database_path,
    )
