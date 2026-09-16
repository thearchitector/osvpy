import ctypes
import gc
import json
import operator
import os
import statistics
import sys
import time
import tracemalloc
import types
import typing
from functools import reduce
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if os.environ.get("PYOSV_PROBE_DEPS"):
    sys.path.insert(0, os.environ["PYOSV_PROBE_DEPS"])
sys.path.insert(0, str(PROJECT_ROOT / "src"))
import msgspec
from osvpy._generated import Advisory, Package, PackageSource
from pydantic import BaseModel

from osvpy.models import FullScanResult, NativeResponse

converted = {}


def convert_type(t):
    if isinstance(t, type) and issubclass(t, BaseModel):
        if t not in converted:
            fields = []
            for name, field in t.model_fields.items():
                opts = {"name": field.alias or name}
                if not field.is_required():
                    if field.default_factory is not None:
                        opts["default_factory"] = field.default_factory
                    else:
                        opts["default"] = field.default
                fields.append((
                    name,
                    convert_type(field.annotation),
                    msgspec.field(**opts),
                ))
            converted[t] = msgspec.defstruct(t.__name__, fields, kw_only=True)
        return converted[t]
    origin = typing.get_origin(t)
    args = typing.get_args(t)
    if origin in (types.UnionType, typing.Union):
        return reduce(operator.or_, map(convert_type, args))
    if origin is list:
        return list[convert_type(args[0])]
    if origin is dict:
        return dict[convert_type(args[0]), convert_type(args[1])]
    return t


WireResponse = convert_type(NativeResponse)
json_decoder = msgspec.json.Decoder(WireResponse)
pack_decoder = msgspec.msgpack.Decoder(WireResponse)


def overridden(model, overrides, extra=()):
    fields = []
    for name, field in model.model_fields.items():
        opts = {"name": field.alias or name}
        if not field.is_required():
            opts["default"] = field.default
        fields.append((
            name,
            overrides.get(name, convert_type(field.annotation)),
            msgspec.field(**opts),
        ))
    return msgspec.defstruct(
        "Normalized" + model.__name__, fields + list(extra), kw_only=True
    )


RefPackage = overridden(Package, {"vulnerabilities": list[int] | None})
RefSource = overridden(PackageSource, {"packages": list[RefPackage] | None})
RefResult = overridden(
    FullScanResult,
    {"sources": list[RefSource] | None},
    [("advisories", list[convert_type(Advisory)])],
)
RefResponse = overridden(NativeResponse, {"result": RefResult | None})
LazyPackage = overridden(Package, {"vulnerabilities": list[msgspec.Raw] | None})
LazySource = overridden(PackageSource, {"packages": list[LazyPackage] | None})
LazyResult = overridden(FullScanResult, {"sources": list[LazySource] | None})
LazyResponse = overridden(NativeResponse, {"result": LazyResult | None})


def normalize(data):
    # Work on independent JSON objects so repeated Python fixture references do
    # not affect the transformation; this setup is excluded from measurements.
    data = json.loads(json.dumps(data))
    table = []
    index = {}
    for source in data["result"]["results"]:
        for package in source["packages"]:
            refs = []
            for advisory in package.get("vulnerabilities") or []:
                key = json.dumps(advisory, sort_keys=True)
                if key not in index:
                    index[key] = len(table)
                    table.append(advisory)
                refs.append(index[key])
            package["vulnerabilities"] = refs
    data["result"]["advisories"] = table
    return data


def fixture(shape):
    raw = json.loads((PROJECT_ROOT / "tests/data/complete_response.json").read_text())
    result = {"image": "fixture", "metadata": raw["metadata"], **raw["result"]}
    if shape == "repeated":
        result["results"][0]["packages"] *= 2000
    elif shape == "details":
        result["results"][0]["packages"][0]["vulnerabilities"][0]["details"] = "x" * (
            4 * 1024 * 1024
        )
    elif shape == "unique":
        template = result["results"][0]["packages"][0]
        packages = []
        for i in range(2000):
            p = json.loads(json.dumps(template))
            p["package"]["name"] = f"package-{i}"
            p["vulnerabilities"][0]["id"] = f"TEST-{i}"
            p["vulnerabilities"][0]["details"] = f"Unique advisory {i}"
            p["vulnerabilities"][0]["affected"][0]["package"]["name"] = f"package-{i}"
            packages.append(p)
        result["results"][0]["packages"] = packages
    return {"abi_version": 3, "ok": True, "result": result}


if __name__ == "__main__":
    shape, mode = sys.argv[1:3]
    data = fixture(shape)
    normalized = mode.startswith("normalized_")
    lazy = mode.startswith("lazy_")
    if lazy:
        mode = mode.removeprefix("lazy_")
    if normalized:
        mode = mode.removeprefix("normalized_")
        data = normalize(data)
    wire = (
        msgspec.msgpack.encode(data) if mode == "msgpack" else msgspec.json.encode(data)
    )
    # A ctypes allocation models an existing native-owned serialized buffer.
    native = ctypes.create_string_buffer(wire)
    view = memoryview(
        (ctypes.c_ubyte * len(wire)).from_address(ctypes.addressof(native))
    )
    size = len(wire)
    del data, wire
    if mode == "pydantic":
        owned = bytes(view)
        decode = lambda: NativeResponse.model_validate_json(owned)
    else:
        decoder = (
            (
                msgspec.msgpack.Decoder(RefResponse)
                if mode == "msgpack"
                else msgspec.json.Decoder(RefResponse)
            )
            if normalized
            else (pack_decoder if mode == "msgpack" else json_decoder)
        )
        if lazy:
            decoder = (
                msgspec.msgpack.Decoder(LazyResponse)
                if mode == "msgpack"
                else msgspec.json.Decoder(LazyResponse)
            )
        decode = lambda: decoder.decode(view)
    sample = decode()
    advisory = (
        sample.result.advisories[0]
        if normalized
        else sample.result.sources[0].packages[0].vulnerabilities[0]
    )
    if lazy:
        advisory = (msgspec.msgpack if mode == "msgpack" else msgspec.json).decode(
            advisory, type=convert_type(Advisory)
        )
    assert advisory.modified == "2026-02-02T00:00:00.123456789Z"
    del advisory
    del sample
    elapsed = []
    for _ in range(5):
        gc.collect()
        start = time.perf_counter()
        model = decode()
        elapsed.append((time.perf_counter() - start) * 1000)
        del model
    gc.collect()
    tracemalloc.start()
    model = decode()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps({
            "shape": shape,
            "mode": ("normalized_" if normalized else "lazy_" if lazy else "") + mode,
            "wire_MiB": size / 2**20,
            "retained_MiB": current / 2**20,
            "peak_MiB": peak / 2**20,
            "decode_ms": statistics.median(elapsed),
        })
    )
