"""Unpacks the files of a checked pack into a folder, never trusting the names or sizes the zip claims."""

import shutil
import zipfile
import zlib
from pathlib import Path

import rules


def extract(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], folder: Path) -> list[Path]:
    """Writes each file under `folder`, counting the bytes really read (a zip can lie about its sizes) and looking at
    what the bytes are (a file must be what its name says)."""
    root = folder.resolve()
    written, total = [], 0
    for info in infos:
        target = (folder / info.filename).resolve()
        if root not in target.parents:
            raise rules.Refused("It has a file with an unsafe path.")
        target.parent.mkdir(parents=True, exist_ok=True)
        watch = rules.Watch(info.filename)
        size = 0
        try:
            with archive.open(info) as source, open(target, "wb") as out:
                chunk = source.read(16)
                while True:
                    size += len(chunk)
                    total += len(chunk)
                    if size > rules.MAX_ONE or total > rules.MAX_UNPACKED:
                        raise rules.Refused("The pack grows far too large once unpacked.")
                    watch.feed(chunk)
                    out.write(chunk)
                    if not (chunk := source.read(1 << 20)):
                        break
        except (zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError, EOFError):
            # A member that can't be read would otherwise fail at every run and keep the pack waiting for good.
            raise rules.Refused("The zip file is damaged.")
        written.append(target)
    return written


def clear(folder: Path) -> None:
    shutil.rmtree(folder, ignore_errors=True)
