"""The whole run, from the list of waiting packs to the verdicts, against a fake API and real zips."""

import hashlib
import io
import itertools
import os
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import rules
import scan
import virus
from tests.helpers import InTempDir, good_files, make_zip, png
from tests.test_pictures import FakeClassifier


class FakeService:
    def __init__(self, packs: dict[str, bytes | Exception]) -> None:
        self.packs = packs
        self.verdicts: dict[str, tuple] = {}

    def waiting(self):
        return [{"id": pack_id} for pack_id in self.packs if pack_id not in self.verdicts]

    def download(self, pack_id, target):
        data = self.packs[pack_id]
        if isinstance(data, Exception):
            raise data
        target.write_bytes(data)
        return hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest(), f"etag-{pack_id}"

    def approve(self, pack_id, sha1, sha256, etag):
        self.verdicts[pack_id] = ("approved", sha1, sha256, etag)

    def refuse(self, pack_id, reason):
        self.verdicts[pack_id] = ("refused", reason)


class Run(InTempDir):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch.object(virus, "scan", lambda folder: None)  # ClamAV is installed by the workflow, not here
        patch.start()
        self.addCleanup(patch.stop)
        self.classifier = FakeClassifier({})

    def zip_bytes(self, files) -> bytes:
        return make_zip(self.dir / "built.zip", files).read_bytes()

    def run_scan(self, packs, **options):
        service = FakeService(packs)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = scan.run(service, lambda: self.classifier, **options)
        return service, code, out.getvalue(), err.getvalue()

    def test_a_good_pack_is_approved_with_its_fingerprints(self):
        data = self.zip_bytes(good_files() | {"assets/big.png": png((300, 300))})
        service, code, out, _ = self.run_scan({"good": data})
        self.assertEqual(code, 0)
        verdict = service.verdicts["good"]
        self.assertEqual(verdict[0], "approved")
        self.assertEqual(verdict[1:], (hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest(), "etag-good"))
        self.assertIn("pictures:", out)
        self.assertIn("done: 1 approved, 0 refused, 0 could not be judged, 0 left", out)

    def test_a_pack_with_a_program_is_refused_with_the_reason(self):
        service, code, _, _ = self.run_scan({"bad": self.zip_bytes(good_files() | {"run.exe": b"MZ"})})
        self.assertEqual(code, 0)
        self.assertEqual(service.verdicts["bad"][0], "refused")
        self.assertIn("can't hold", service.verdicts["bad"][1])

    def test_a_file_that_is_not_a_zip(self):
        service, _, _, _ = self.run_scan({"junk": b"this is not a zip"})
        self.assertEqual(service.verdicts["junk"], ("refused", "This is not a zip file."))

    def test_a_program_hidden_under_a_picture_name(self):
        service, _, _, _ = self.run_scan({"hidden": self.zip_bytes(good_files() | {"assets/x.png": b"MZ\x90\x00"})})
        self.assertIn("not a real picture", service.verdicts["hidden"][1])

    def test_an_adult_picture_is_refused_and_the_score_is_logged(self):
        self.classifier = FakeClassifier({"big.png": 0.97})
        data = self.zip_bytes(good_files() | {"assets/big.png": png((300, 300))})
        service, _, out, _ = self.run_scan({"adult": data})
        self.assertEqual(service.verdicts["adult"][0], "refused")
        self.assertIn("adult content", service.verdicts["adult"][1])
        self.assertIn("highest 0.9700", out)

    def test_a_virus_is_refused(self):
        def infected(folder):
            raise rules.Refused("A virus scanner reported something harmful in this pack.")

        with mock.patch.object(virus, "scan", infected):
            service, _, _, _ = self.run_scan({"sick": self.zip_bytes(good_files())})
        self.assertIn("virus", service.verdicts["sick"][1])

    def test_a_broken_virus_scan_leaves_the_pack_waiting(self):
        def broken(folder):
            raise RuntimeError("clamscan failed (2)")

        with mock.patch.object(virus, "scan", broken):
            service, code, _, err = self.run_scan({"p": self.zip_bytes(good_files())})
        self.assertEqual((code, service.verdicts), (1, {}))
        self.assertIn("could not be judged", err)

    def test_one_failure_does_not_stop_the_others(self):
        packs = {"down": ConnectionError("network"), "fine": self.zip_bytes(good_files())}
        service, code, out, _ = self.run_scan(packs)
        self.assertEqual(code, 1)
        self.assertEqual(list(service.verdicts), ["fine"])
        self.assertIn("1 approved, 0 refused, 1 could not be judged", out)

    def test_a_failed_pack_is_not_tried_again_in_the_same_run(self):
        service = FakeService({"down": ConnectionError("network")})
        calls = []
        original = service.download
        service.download = lambda pack_id, target: (calls.append(pack_id), original(pack_id, target))[1]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            scan.run(service, lambda: self.classifier)
        self.assertEqual(calls, ["down"])

    def test_nothing_waiting(self):
        service, code, out, _ = self.run_scan({})
        self.assertEqual(code, 0)
        self.assertIn("0 pack(s) waiting", out)

    def test_the_time_budget_leaves_the_rest_for_the_next_run(self):
        data = self.zip_bytes(good_files())
        ticks = itertools.count(0, 100)  # every look at the clock is 100 s later
        service, code, out, _ = self.run_scan({"one": data, "two": data, "three": data}, budget=150, clock=lambda: next(ticks))
        self.assertEqual(code, 0)
        self.assertEqual(list(service.verdicts), ["one"])
        self.assertIn("2 left for the next run", out)

    def test_the_summary_table_is_written_for_the_run_page(self):
        target = self.dir / "summary.md"
        data = self.zip_bytes(good_files())
        with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(target)}):
            self.run_scan({"abcdef123456": data, "bad": self.zip_bytes(good_files() | {"x.exe": b"MZ"})})
        text = target.read_text(encoding="utf-8")
        self.assertIn("| `abcdef12` | approved |", text)
        self.assertIn("| `bad` | refused |", text)

    def test_no_summary_when_nothing_happened(self):
        target = self.dir / "summary.md"
        with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(target)}):
            self.run_scan({})
        self.assertFalse(target.exists())


class RealZipShape(InTempDir):
    def test_zipfile_is_what_the_scanner_reads(self):
        # A guard for the fakes above: the zips they build are ordinary zips.
        path = make_zip(self.dir / "p.zip", good_files())
        with zipfile.ZipFile(path) as archive:
            self.assertIn("pack.mcmeta", archive.namelist())
