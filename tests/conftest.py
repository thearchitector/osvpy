import os
import sys
import sysconfig
from contextlib import ExitStack
from typing import TYPE_CHECKING

import pytest

from explore_toolkit.images import registry_resources, serve_registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@pytest.fixture(autouse=True)
def verify_gil_state() -> "Iterator[None]":
    def check() -> None:
        if os.environ.get("OSVPY_EXPECT_FREE_THREADED") == "1":
            assert sysconfig.get_config_var("Py_GIL_DISABLED") == 1
            assert not sys._is_gil_enabled()

    check()
    yield
    check()


@pytest.fixture
def registry_factory() -> "Iterator[Callable[..., str]]":
    resources = registry_resources()
    with ExitStack() as stack:
        yield lambda **options: stack.enter_context(
            serve_registry(resources, **options)
        )


@pytest.fixture
def package_image() -> "Iterator[str]":
    if os.environ.get("OSVPY_TEST_SERVICES") != "1":
        pytest.fail("Run with python -m tests to start controlled advisory services")
    resources = registry_resources({
        "etc/os-release": b"ID=ubuntu\nVERSION_ID=24.04\n",
        "usr/lib/python3/site-packages/example-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: example\nVersion: 1.0\n",
    })
    with serve_registry(resources) as image:
        yield image
