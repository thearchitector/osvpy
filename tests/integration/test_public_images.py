import pytest

import osvpy

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("image", ["ubuntu:latest", "debian:12", "python:3.12-slim"])
def test_dockerhub_image_has_inventory(image: str) -> None:
    result = osvpy.scan_image(image, all_packages=True)
    assert result.packages
    assert result.metadata.image_digest is not None
