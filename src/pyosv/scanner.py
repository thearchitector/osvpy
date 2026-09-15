"""Public synchronous API; scanners execute in the calling process."""

import logging
import os
from typing import Any

from . import _native
from .models import RegistryAuth, ScanResult

logger = logging.getLogger("pyosv")


def _scan(
    image: str,
    source: str,
    *,
    offline: bool,
    all_packages: bool,
    auth: RegistryAuth | None = None,
    platform: str | None = None,
    database_path: str | os.PathLike[str] | None = None,
) -> ScanResult:
    request: dict[str, Any] = {
        "image": image,
        "source": source,
        "offline": offline,
        "all_packages": all_packages,
    }
    if auth is not None:
        request["auth"] = {"username": auth.username, "password": auth.password}
    if platform is not None:
        request["platform"] = platform
    if database_path is not None:
        request["database_path"] = os.fspath(database_path)
    envelope = _native.scan(request)
    assert envelope.result is not None
    assert envelope.metadata is not None
    # Already validated in one JSON parse. Reuse the nested models without copying.
    result = ScanResult.model_construct(
        image=image, metadata=envelope.metadata, **envelope.result.__dict__
    )
    logger.debug(
        "Scan completed: %d packages, %d findings, duration=%s seconds",
        len(result.packages),
        len(result.vulnerabilities),
        result.metadata.duration_seconds,
    )
    return result


def scan_image(
    image: str,
    *,
    offline: bool = False,
    all_packages: bool = False,
    auth: RegistryAuth | None = None,
    platform: str | None = None,
    database_path: str | os.PathLike[str] | None = None,
) -> ScanResult:
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
        auth=auth,
        platform=platform,
        database_path=database_path,
    )


def scan_docker_archive(
    path: str | os.PathLike[str],
    *,
    offline: bool = False,
    all_packages: bool = False,
    database_path: str | os.PathLike[str] | None = None,
) -> ScanResult:
    """Scan a single-image Docker save archive; never invokes Docker."""
    return _scan(
        os.fspath(path),
        "docker_archive",
        offline=offline,
        all_packages=all_packages,
        database_path=database_path,
    )
