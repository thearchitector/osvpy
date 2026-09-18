"""Cancellable full-batch scanning on the calling loop's executor."""

import asyncio
import json
from contextlib import suppress
from typing import TYPE_CHECKING

from . import _native
from .languages import resolve_languages

if TYPE_CHECKING:
    from collections.abc import Collection

    from .languages import LanguageSelection
    from .models import BatchResult, RegistryAuth


def _execute(
    payload: bytes, controller: _native.CancellationController
) -> "BatchResult | BaseException":
    # Shield futures abandoned by task cancellation may log worker exceptions
    # even when the owner later retrieves them. Publish an explicit outcome;
    # the owning coroutine propagates it after all native cleanup completes.
    try:
        return _native.scan(payload, controller)
    except BaseException as error:  # noqa: BLE001 -- transferred to the owning coroutine
        return error.with_traceback(None)


async def scan(
    *images: str,
    languages: "LanguageSelection | None" = None,
    all_packages: bool = False,
    allowed_licenses: "Collection[str] | None" = None,
    workers: int = 1,
    auth: "RegistryAuth | None" = None,
    platform: str | None = None,
) -> "BatchResult":
    """Scan registry images in input order. Cancellation waits for native cleanup."""
    if workers < 1:
        raise ValueError("workers must be positive")
    # Immutable encoded request is the ownership boundary with the executor.
    payload = json.dumps(
        {
            "inputs": images,
            "all_packages": all_packages,
            "allowed_licenses": None
            if allowed_licenses is None
            else tuple(sorted(set(allowed_licenses))),
            "auth": None
            if auth is None
            else {"username": auth.username, "password": auth.password},
            "platform": platform or "",
            "workers": workers,
            "languages": resolve_languages(languages),
        },
        ensure_ascii=False,
    ).encode("utf-8")
    controller = _native.CancellationController()
    completion = asyncio.get_running_loop().run_in_executor(
        None, _execute, payload, controller
    )
    try:
        outcome = await asyncio.shield(completion)
    except asyncio.CancelledError:
        controller.cancel()
        # Repeated task.cancel() cannot abandon the owning executor job.
        while not completion.done():
            try:
                await asyncio.shield(completion)
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001 -- retrieve worker errors before propagating cancellation
                break
        with suppress(BaseException):
            completion.result()
        # A retained CancelledError traceback must not retain a completed batch
        # (or a worker exception whose traceback contains a result owner).
        del completion
        raise
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome
