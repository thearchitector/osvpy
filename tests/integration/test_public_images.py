import asyncio

import pytest

import osvpy

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("image", ["ubuntu:latest", "debian:12", "python:3.12-slim"])
def test_dockerhub_image_has_inventory(image: str) -> None:
    result = asyncio.run(osvpy.scan(image, all_packages=True))
    assert result.packages
    assert result.complete
    assert result.images[0].metadata.image_digest
