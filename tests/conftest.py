from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

import pytest


def base_path() -> Path:
    return Path(__file__).parent


def open_file(file: Path, mode: str = "rb") -> Iterator[BinaryIO]:
    with file.open(mode) as f:
        yield f


@pytest.fixture
def wddh_mimikatz() -> Iterator[BinaryIO]:
    yield from open_file(base_path() / "data"/"94BBE9CF-CDEB-4885-9178-CC93FB10822D")


@pytest.fixture(
    params=list(
        f
        for f in (base_path() / "data" / "DFIRArtifactMuseum" / "files").rglob("*")
        if f.is_file()
    )
)
def wddh_dfir_museum(request) -> Iterator[BinaryIO]:
    file_path = request.param
    if file_path.is_file():
        with file_path.open("rb") as f:
            yield f
