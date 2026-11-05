"""The structure rules for a resource pack. The API service already applied them when the file arrived; they are
applied again here to the file that is really going to be published, because the upload link stays valid for a few
minutes after the first check and the file could have been replaced in that time.

Same rules as api/src/packs/inspect.ts. Keep the two in step."""

import re
import zipfile

ALLOWED = {"png", "json", "mcmeta", "ogg", "txt", "md", "properties", "lang", "fsh", "vsh", "glsl", "ttf", "otf", "license"}
PLAIN = {"license", "licence", "readme", "credits", "notice", "copying", "authors"}
# A licence-like name may carry any ending (LICENSE.ASSETS, LICENSE-CODE), except one that is a program or an archive.
LICENSE_LIKE = re.compile(r"^(license|licence|readme|credits|notice|copying|authors)([-_.][a-z0-9_.-]*)?$")
NEVER = {"exe", "dll", "so", "dylib", "jar", "class", "zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "bat", "cmd", "com", "scr", "msi", "ps1", "sh", "js", "vbs", "py", "lnk", "apk", "dmg", "iso", "bin"}
JUNK = {"thumbs.db", ".ds_store", "desktop.ini"}
MAX_FILES = 20_000
MAX_UNPACKED = 1_000_000_000
MAX_ONE = 150_000_000


class Refused(Exception):
    """The pack is not allowed. The message is shown to the person who uploaded it."""


def kind_of(name: str) -> str | None:
    """The file type a name counts as, or None for something a pack may not hold."""
    base = name.rsplit("/", 1)[-1].lower()
    if base in JUNK:
        return "junk"
    dot = base.rfind(".")
    ending = base[dot + 1 :] if dot > 0 else ""
    if ending in ALLOWED:
        return ending
    if dot <= 0 and base in PLAIN:
        return "license"
    return "license" if LICENSE_LIKE.match(base) and ending not in NEVER else None


def safe(name: str) -> bool:
    return not ("\\" in name or name.startswith("/") or ".." in name.split("/") or re.match(r"^[a-zA-Z]:", name) or "\0" in name)


def check(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Returns the files to look at, or raises Refused."""
    infos = archive.infolist()
    if not infos:
        raise Refused("The zip file is empty.")
    if len(infos) > MAX_FILES:
        raise Refused(f"It holds more than {MAX_FILES} files.")
    kept, total, has_meta = [], 0, False
    for info in infos:
        name = info.filename
        if not safe(name):
            raise Refused("It has a file with an unsafe path.")
        if info.flag_bits & 1:
            raise Refused("The zip file is password protected.")
        if name.endswith("/") or name.startswith("__MACOSX/"):
            continue
        kind = kind_of(name)
        if kind == "junk":
            continue
        if kind is None:
            shown = name if len(name) <= 60 else name[:57] + "…"
            raise Refused(f"A resource pack can't hold “{shown}”. Only pictures, sounds, fonts, text and settings files are allowed.")
        if info.file_size > MAX_ONE:
            raise Refused(f"{name} is too large.")
        total += info.file_size
        if total > MAX_UNPACKED:
            raise Refused("The pack grows far too large once unpacked.")
        has_meta = has_meta or name == "pack.mcmeta"
        kept.append(info)
    if not has_meta:
        raise Refused("There is no pack.mcmeta at the top of the zip.")
    return kept


def check_magic(name: str, head: bytes) -> None:
    """A file named .png or .ogg must start like one, so a program can't hide under a picture's name."""
    lower = name.lower()
    if lower.endswith(".png") and not head.startswith(b"\x89PNG\r\n\x1a\n"):
        raise Refused(f"{name} is not a real picture.")
    if lower.endswith(".ogg") and not head.startswith(b"OggS"):
        raise Refused(f"{name} is not a real sound file.")
