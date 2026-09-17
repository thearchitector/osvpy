"""Isolated bridge workspaces and native-library builds for local experiments."""

import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from .processes import ROOT

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


@contextmanager
def bridge_workspace(
    *,
    source: Path = ROOT / "go",
    extra_files: "Iterable[Path]" = (),
    include_tests: bool = False,
) -> "Iterator[Path]":
    """Copy the flat Go bridge module to a temporary directory and clean it up.

    Add package-main Go probes with extra_files. Production tests are excluded
    unless requested. The yielded copy may be edited freely by an investigation.
    """
    with tempfile.TemporaryDirectory(prefix="osvpy-explore-") as directory:
        workspace = Path(directory)
        for path in source.iterdir():
            if path.name in {"go.mod", "go.sum"} or (
                path.suffix == ".go"
                and (include_tests or not path.name.endswith("_test.go"))
            ):
                shutil.copy2(path, workspace / path.name)
        for path in extra_files:
            target = workspace / path.name
            if target.exists():
                raise FileExistsError(target)
            shutil.copy2(path, target)
        yield workspace


def build_library(
    workspace: Path, output: Path, *, race: bool = False, timeout: float = 300
) -> Path:
    """Build a shared library without installing it or changing Python globals.

    Standalone go test -race remains necessary; loading a race-instrumented
    library in Python is not supported by every ThreadSanitizer environment.
    """
    if sys.platform not in {"linux", "darwin"}:
        raise RuntimeError("shared libraries are supported on Linux and macOS")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "go",
            "build",
            "-mod=readonly",
            "-buildvcs=false",
            "-buildmode=c-shared",
            *(["-race"] if race else []),
            "-o",
            str(output),
            ".",
        ],
        cwd=workspace,
        env=os.environ | {"CGO_ENABLED": "1"},
        check=True,
        timeout=timeout,
    )
    return output
