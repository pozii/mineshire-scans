"""Builders for the real zips and pictures the tests feed to the scanner."""

import io
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from PIL import Image

MCMETA = '{"pack":{"pack_format":34,"description":"A test pack"}}'


def png(size: tuple[int, int] = (16, 16), color: tuple[int, int, int] = (10, 20, 30)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, color).save(out, "PNG")
    return out.getvalue()


def good_files() -> dict[str, bytes | str]:
    """A small pack that passes every check."""
    return {
        "pack.mcmeta": MCMETA,
        "pack.png": png((64, 64)),
        "assets/minecraft/textures/block/stone.png": png((16, 16), (1, 2, 3)),
        "assets/minecraft/lang/en_us.json": '{"block.minecraft.stone": "Stone"}',
        "LICENSE": "MIT",
    }


def make_zip(path: Path, files) -> Path:
    """Writes a zip. `files` is a dict, or a list of (name, data) pairs when the same name must appear twice."""
    pairs = files.items() if isinstance(files, dict) else files
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about a duplicate name, which some tests want on purpose
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in pairs:
                archive.writestr(name, data)
    return path


class InTempDir(unittest.TestCase):
    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.dir = Path(holder.name)

    def zip(self, files) -> Path:
        return make_zip(self.dir / "pack.zip", files)
