"""Measure worker startup/transport and aggregate memory for a normalized result."""

import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if sys.argv[1] == "child":
    os.environ["PYOSV_LAB_LIBRARY"] = str(Path(__file__).with_name("lab.so"))
    import store_review as s

    shape, directory = sys.argv[2:4]
    data = s.fixture("unique" if shape == "mixed" else shape)
    if shape == "mixed":
        data["result"]["results"][0]["packages"] *= 10
    wire = s.msgspec.json.encode(data)
    del data
    assert s.lib.lab_load(wire, len(wire)) == 0
    del wire
    lib = s.lib
    c = s.c
    lib.store_dense_direct.argtypes = [
        c.POINTER(c.c_void_p),
        c.POINTER(c.c_size_t),
        c.POINTER(c.c_void_p),
        c.POINTER(c.c_size_t),
    ]
    p, n, ap, an = c.c_void_p(), c.c_size_t(), c.c_void_p(), c.c_size_t()
    start = time.perf_counter()
    lib.store_dense_direct(c.byref(p), c.byref(n), c.byref(ap), c.byref(an))
    for path, ptr, length in [
        ("meta", p.value, n.value),
        ("arena", ap.value, an.value),
    ]:
        with open(Path(directory) / path, "wb") as f:
            f.write(s.view(ptr, length))
        lib.lab_free(ptr)
    print(
        json.dumps({
            "worker_peak_MiB": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            / 1024,
            "encode_write_ms": 1000 * (time.perf_counter() - start),
        })
    )
else:
    import gc
    import mmap

    from decoder_review import convert_type, msgspec
    from osvpy._generated import GroupInfo, ImageOriginDetails, PackageInfo

    class Context(msgspec.Struct):
        image_origin_details: convert_type(ImageOriginDetails) | None = None
        dependency_groups: tuple[str, ...] = ()
        groups: tuple[convert_type(GroupInfo), ...] = ()
        licenses: tuple[str, ...] = ()
        license_violations: tuple[str, ...] = ()

    class Meta(msgspec.Struct):
        image: str
        metadata: object
        sources: tuple[object, ...]
        packages: tuple[convert_type(PackageInfo), ...]
        contexts: tuple[Context, ...]
        occurrences: bytes
        refs: bytes
        extras: object

    def rss():
        return int(Path("/proc/self/statm").read_text().split()[1]) * 4096 / 2**20

    parent_before = rss()
    with tempfile.TemporaryDirectory() as directory:
        start = time.perf_counter()
        p = subprocess.run(
            [sys.executable, __file__, "child", sys.argv[1], directory],
            capture_output=True,
            text=True,
        )
        if p.returncode:
            raise RuntimeError(p.stderr)
        meta = msgspec.msgpack.decode(
            (Path(directory) / "meta").read_bytes(), type=Meta
        )
        with open(Path(directory) / "arena", "rb") as f:
            arena = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        records = msgspec.msgpack.decode(arena, type=tuple[msgspec.Raw, ...])
        elapsed = 1000 * (time.perf_counter() - start)
        info = json.loads(p.stdout)
        info.update(
            shape=sys.argv[1],
            worker_start_build_transfer_ms=elapsed,
            parent_before_MiB=parent_before,
            parent_after_MiB=rss(),
            mapped_MiB=len(arena) / 2**20,
            aggregate_peak_upper_MiB=parent_before + info["worker_peak_MiB"],
        )
        assert msgspec.msgpack.decode(records[0])["id"]
        try:
            arena.close()
        except BufferError:
            pass
        else:
            raise AssertionError("mapping closed with live Raw views")
        del records
        gc.collect()
        arena.close()
        info["escaped_view_lifetime"] = "passed"
        print(json.dumps(info))
