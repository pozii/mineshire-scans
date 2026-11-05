"""The structure rules for a resource pack. The API service already applied them when the file arrived; they are
applied again here to the file that is really going to be published, because the upload link stays valid for a few
minutes after the first check and the file could have been replaced in that time.

The name rules (which files a pack may hold, the same file twice) are the same as in api/src/packs/inspect.ts. Keep the
two in step. What a file's bytes look like (`Watch`) is only checked here: the API never reads the whole file."""

import re
import zipfile

ALLOWED = {"png", "json", "json5", "mcmeta", "ogg", "txt", "md", "properties", "lang", "fsh", "vsh", "glsl", "ttf", "otf", "license"}
PLAIN = {"license", "licence", "readme", "credits", "notice", "copying", "authors"}
# A licence-like name may carry any ending (LICENSE.ASSETS, LICENSE-CODE), except one that is a program or an archive.
LICENSE_LIKE = re.compile(r"^(license|licence|readme|credits|notice|copying|authors)([-_.][a-z0-9_.-]*)?$")
NEVER = {"exe", "dll", "so", "dylib", "jar", "class", "zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "bat", "cmd", "com", "scr", "msi", "ps1", "sh", "js", "vbs", "py", "lnk", "apk", "dmg", "iso", "bin"}
JUNK = {"thumbs.db", ".ds_store", "desktop.ini"}
MAX_FILES = 20_000
MAX_UNPACKED = 1_000_000_000
MAX_ONE = 150_000_000

# Files that are plain text. Their bytes are checked too, because a program can hide under a text file's name.
TEXT = {"txt", "md", "json", "json5", "mcmeta", "properties", "lang", "fsh", "vsh", "glsl", "license"}
# How programs, other archives and compressed files begin. Real text never starts like this.
BINARY_STARTS = (
    b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b\x08", b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"\xfd7zXZ\x00",
    b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"%PDF-",
)
FONT_STARTS = (b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf")


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


def shown(name: str) -> str:
    return name if len(name) <= 60 else name[:57] + "…"


def check(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Returns the files to look at, or raises Refused."""
    infos = archive.infolist()
    if not infos:
        raise Refused("The zip file is empty.")
    if len(infos) > MAX_FILES:
        raise Refused(f"It holds more than {MAX_FILES} files.")
    kept, total, has_meta = [], 0, False
    # The same name twice is how a zip can show one file to a checker and another to the game. Capital letters count as
    # the same name, because on many systems they are.
    seen: set[str] = set()
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
            raise Refused(f"A resource pack can't hold “{shown(name)}”. Only pictures, sounds, fonts, text and settings files are allowed.")
        if name.lower() in seen:
            raise Refused(f"A resource pack can't hold “{shown(name)}” more than once.")
        seen.add(name.lower())
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


class Watch:
    """Looks at the bytes of one file while it is unpacked. A file must be what its name says: a picture starts like a
    picture, a sound like a sound, a font like a font, and a text file holds text, so a program can't hide under a name
    (the structure rules only see names)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.kind = kind_of(name)
        self.first = True
        self.utf16 = False

    def feed(self, chunk: bytes) -> None:
        if self.first:
            self.first = False
            self._head(chunk[:16])
        if self.kind in TEXT and not self.utf16 and b"\0" in chunk:
            raise Refused(f"{shown(self.name)} is not a text file; it holds binary data.")

    def _head(self, head: bytes) -> None:
        if self.kind == "png" and not head.startswith(b"\x89PNG\r\n\x1a\n"):
            raise Refused(f"{shown(self.name)} is not a real picture.")
        if self.kind == "ogg" and not head.startswith(b"OggS"):
            raise Refused(f"{shown(self.name)} is not a real sound file.")
        if self.kind in ("ttf", "otf") and not head.startswith(FONT_STARTS):
            raise Refused(f"{shown(self.name)} is not a real font.")
        if self.kind in TEXT:
            # Text saved as UTF-16 has a zero byte between letters, which is fine when it says so at the start.
            self.utf16 = head.startswith((b"\xff\xfe", b"\xfe\xff"))
            if head.startswith(BINARY_STARTS):
                raise Refused(f"{shown(self.name)} is not a text file; it holds a program or an archive.")
