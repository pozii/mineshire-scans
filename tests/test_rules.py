import unittest
import zipfile
from unittest import mock

import rules
from tests.helpers import InTempDir, good_files, png


class KindOf(unittest.TestCase):
    def test_what_a_pack_may_hold(self):
        for name, kind in {
            "pack.png": "png",
            "assets/a/b/C.PNG": "png",
            "sounds/x.ogg": "ogg",
            "lang/en_us.json": "json",
            "assets/adorn/color_palettes/drawer.json5": "json5",
            "textures/a.png.mcmeta": "mcmeta",
            "shaders/core/x.fsh": "fsh",
            "fonts/a.ttf": "ttf",
            "LICENSE": "license",
            "README": "license",
            "license.txt": "txt",
            "assets/betterend/LICENSE.ASSETS": "license",
            "LICENSE-CODE": "license",
            "Thumbs.db": "junk",
            "x/.DS_Store": "junk",
        }.items():
            with self.subTest(name):
                self.assertEqual(rules.kind_of(name), kind)

    def test_programs_and_archives_never_pass_by_name(self):
        for name in ["mod.exe", "a/b.jar", "x.zip", "run.sh", "evil.assets", "LICENSE.exe", "license.jar", "credits.sh", "readme.bat", "notes", "licensefoo.assets"]:
            with self.subTest(name):
                self.assertIsNone(rules.kind_of(name))


class Check(InTempDir):
    def check(self, files):
        with zipfile.ZipFile(self.zip(files)) as archive:
            return rules.check(archive)

    def refused(self, files) -> str:
        with self.assertRaises(rules.Refused) as caught:
            self.check(files)
        return str(caught.exception)

    def test_a_good_pack_passes(self):
        kept = self.check(good_files())
        self.assertEqual(len(kept), 5)

    def test_junk_and_folders_are_ignored(self):
        files = good_files() | {"__MACOSX/._pack.png": b"x", "Thumbs.db": b"x", "assets/": b""}
        self.assertEqual(len(self.check(files)), 5)

    def test_a_program_refuses_the_pack(self):
        self.assertIn("can't hold", self.refused(good_files() | {"tools/run.exe": b"MZ"}))

    def test_an_archive_inside_refuses_the_pack(self):
        self.assertIn("can't hold", self.refused(good_files() | {"extra.jar": b"PK"}))

    def test_a_licence_file_named_like_a_program_is_refused(self):
        self.assertIn("can't hold", self.refused(good_files() | {"LICENSE.exe": b"MZ"}))

    def test_no_mcmeta(self):
        files = good_files()
        del files["pack.mcmeta"]
        self.assertIn("pack.mcmeta", self.refused(files))

    def test_the_mcmeta_must_be_at_the_top(self):
        files = {f"folder/{name}": data for name, data in good_files().items()}
        self.assertIn("pack.mcmeta", self.refused(files))

    def test_an_empty_zip(self):
        self.assertIn("empty", self.refused({}))

    def test_unsafe_paths(self):
        # (A backslash can't be tried here: zipfile on Windows turns it into a slash before writing.)
        for name in ["../evil.txt", "/abs.txt", "a/../../b.txt", "C:/x.txt"]:
            with self.subTest(name):
                self.assertIn("unsafe", self.refused(good_files() | {name: b"x"}))

    def test_the_same_name_twice(self):
        files = list(good_files().items()) + [("assets/minecraft/lang/en_us.json", "{}")]
        self.assertIn("more than once", self.refused(files))

    def test_the_same_name_in_other_capitals(self):
        files = list(good_files().items()) + [("PACK.PNG", png())]
        self.assertIn("more than once", self.refused(files))

    def test_a_password_protected_file(self):
        with zipfile.ZipFile(self.zip(good_files())) as archive:
            archive.infolist()[1].flag_bits |= 1
            with self.assertRaises(rules.Refused) as caught:
                rules.check(archive)
        self.assertIn("password", str(caught.exception))

    def test_too_many_files(self):
        with mock.patch.object(rules, "MAX_FILES", 3):
            self.assertIn("more than 3", self.refused(good_files()))

    def test_one_file_too_large(self):
        with mock.patch.object(rules, "MAX_ONE", 10):
            self.assertIn("too large", self.refused(good_files()))

    def test_too_large_in_total(self):
        with mock.patch.object(rules, "MAX_UNPACKED", 100):
            self.assertIn("too large", self.refused(good_files()))


class WatchBytes(unittest.TestCase):
    def watch(self, name, *chunks):
        watch = rules.Watch(name)
        for chunk in chunks:
            watch.feed(chunk)

    def test_real_files_pass(self):
        self.watch("a.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 20)  # a picture may hold zero bytes
        self.watch("a.ogg", b"OggS\0\x02")
        self.watch("a.ttf", b"\x00\x01\x00\x00rest")
        self.watch("a.otf", b"OTTO\0\0")
        self.watch("a.txt", b"plain text\n", b"more text")
        self.watch("a.json", b'{"a": 1}')
        self.watch("empty.txt", b"")

    def test_utf16_text_is_text(self):
        self.watch("a.txt", "héllo".encode("utf-16"))

    def test_a_program_under_a_picture_name(self):
        with self.assertRaisesRegex(rules.Refused, "not a real picture"):
            self.watch("a.png", b"MZ\x90\x00\x03")

    def test_a_program_under_a_sound_name(self):
        with self.assertRaisesRegex(rules.Refused, "not a real sound"):
            self.watch("a.ogg", b"MZ\x90\x00\x03")

    def test_a_program_under_a_font_name(self):
        with self.assertRaisesRegex(rules.Refused, "not a real font"):
            self.watch("a.ttf", b"MZ\x90\x00\x03")

    def test_binary_data_in_a_text_file(self):
        with self.assertRaisesRegex(rules.Refused, "binary"):
            self.watch("a.txt", b"MZ\x90\x00\x03\x00\x00\x00")

    def test_binary_data_later_in_a_text_file(self):
        with self.assertRaisesRegex(rules.Refused, "binary"):
            self.watch("a.json", b"{}" * 100, b"more\0data")

    def test_an_archive_under_a_text_name(self):
        for head in [b"PK\x03\x04", b"\x1f\x8b\x08\x00", b"Rar!\x1a\x07\x00", b"\x7fELF\x02", b"%PDF-1.7"]:
            with self.subTest(head), self.assertRaisesRegex(rules.Refused, "program or an archive"):
                self.watch("a.lang", head + b"x")

    def test_a_licence_file_with_a_strange_ending_is_still_text(self):
        with self.assertRaisesRegex(rules.Refused, "program or an archive"):
            self.watch("LICENSE.ASSETS", b"PK\x03\x04")


if __name__ == "__main__":
    unittest.main()
