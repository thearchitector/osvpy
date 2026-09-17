"""Keep untraced timings, Python retention, and process RSS separate."""

import gc
import resource
import sys
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class PythonMemory:
    retained_bytes: int
    peak_bytes: int


def timed[T](
    operation: "Callable[[], T]", *, repeats: int = 5, warmups: int = 1
) -> list[float]:
    """Return untraced durations in seconds; discard each result between samples."""
    if repeats < 1 or warmups < 0:
        raise ValueError("repeats must be positive and warmups nonnegative")
    if tracemalloc.is_tracing():
        raise RuntimeError("stop tracemalloc before measuring untraced timings")
    for _ in range(warmups):
        operation()
    samples = []
    for _ in range(repeats):
        gc.collect()
        start = time.perf_counter()
        result = operation()
        samples.append(time.perf_counter() - start)
        del result
    return samples


def retained[T](operation: "Callable[[], T]") -> tuple[T, PythonMemory]:
    """Return the live result and its traced Python allocation measurements.

    Prepare inputs before calling. Return every object that should remain live,
    including escaped views. Native allocations and allocator slack are excluded.
    """
    if tracemalloc.is_tracing():
        raise RuntimeError("retained requires its own tracemalloc session")
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        result = operation()
        gc.collect()
        current, peak = tracemalloc.get_traced_memory()
        return result, PythonMemory(current - before, peak - before)
    finally:
        tracemalloc.stop()


def peak_rss_bytes() -> int:
    """Process lifetime high-water RSS, including setup, runtimes, and warm-up."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss * (1 if sys.platform == "darwin" else 1024)


def current_rss_bytes() -> int | None:
    """Current Linux process RSS; None on platforms without /proc."""
    if sys.platform != "linux":
        return None
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return None
