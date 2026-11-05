import zipfile
from unittest import mock

import rules
import unpack
from tests.helpers import MCMETA, InTempDir, good_files


class Extract(InTempDir):
    def extract(self, files, infos=None):
        folder = self.dir / "files"
        with zipfile.ZipFile(self.zip(files)) as archive:
            return unpack.extract(archive, infos if infos is not None else rules.check(archive), folder)

    def refused(self, files) -> str:
        with self.assertRaises(rules.Refused) as caught:
            self.extract(files)
        return str(caught.exception)

    def test_a_good_pack_is_written_out(self):
        written = self.extract(good_files())
        self.assertEqual(len(written), 5)
        self.assertEqual((self.dir / "files" / "LICENSE").read_text(), "MIT")

    def test_a_program_renamed_to_a_picture(self):
        self.assertIn("not a real picture", self.refused(good_files() | {"assets/x.png": b"MZ\x90\x00\x03\x00"}))

    def test_a_program_renamed_to_a_sound(self):
        self.assertIn("not a real sound", self.refused(good_files() | {"assets/x.ogg": b"MZ\x90\x00\x03\x00"}))

    def test_binary_data_in_a_settings_file(self):
        self.assertIn("binary", self.refused(good_files() | {"assets/x.json": b'{"a":1}\0\0\0'}))

    def test_an_archive_in_a_text_file(self):
        self.assertIn("program or an archive", self.refused(good_files() | {"assets/x.txt": b"PK\x03\x04\x14\x00"}))

    def test_utf16_text_is_accepted(self):
        self.extract(good_files() | {"assets/readme.txt": "héllo wörld".encode("utf-16")})

    def test_an_empty_picture_is_not_a_picture(self):
        self.assertIn("not a real picture", self.refused(good_files() | {"assets/empty.png": b""}))

    def test_an_empty_text_file_is_fine(self):
        self.extract(good_files() | {"assets/empty.txt": b""})

    def test_a_path_out_of_the_folder_is_refused_when_writing(self):
        with zipfile.ZipFile(self.zip(good_files())) as archive:
            evil = zipfile.ZipInfo("../evil.txt")
            with self.assertRaisesRegex(rules.Refused, "unsafe"):
                unpack.extract(archive, [evil], self.dir / "files")
        self.assertFalse((self.dir / "evil.txt").exists())

    def test_the_real_size_counts_not_the_claimed_one(self):
        # check() trusts the sizes a zip claims; extract() counts the bytes it really reads.
        with mock.patch.object(rules, "MAX_UNPACKED", 100):
            with zipfile.ZipFile(self.zip(good_files())) as archive:
                with self.assertRaisesRegex(rules.Refused, "too large"):
                    unpack.extract(archive, archive.infolist(), self.dir / "files")

    def test_one_file_that_grows_too_large(self):
        with mock.patch.object(rules, "MAX_ONE", 100):
            with zipfile.ZipFile(self.zip(good_files())) as archive:
                with self.assertRaisesRegex(rules.Refused, "too large"):
                    unpack.extract(archive, archive.infolist(), self.dir / "files")

    def test_a_damaged_member_is_a_refusal_not_a_crash(self):
        path = self.dir / "damaged.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("pack.mcmeta", MCMETA)
            archive.writestr("notes.txt", "a" * 50)
        data = bytearray(path.read_bytes())
        data[data.find(b"a" * 50)] = ord("b")  # the stored bytes no longer match the checksum the zip keeps
        path.write_bytes(bytes(data))
        with zipfile.ZipFile(path) as archive:
            with self.assertRaisesRegex(rules.Refused, "damaged"):
                unpack.extract(archive, rules.check(archive), self.dir / "files")
