from pathlib import Path
from unittest import mock

import pictures
import rules
from tests.helpers import InTempDir, png


class FakeClassifier:
    """Scores a picture by its file name, so a test decides what the model 'sees'."""

    def __init__(self, scores: dict[str, float], default: float = 0.01) -> None:
        self.scores, self.default, self.asked = scores, default, []

    def score(self, paths: list[Path]) -> list[float]:
        self.asked += [p.name for p in paths]
        return [self.scores.get(p.name, self.default) for p in paths]


class Choose(InTempDir):
    def put(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_the_icon_first_then_the_biggest_and_never_the_tiny(self):
        files = [
            self.put("tile.png", png((16, 16), (1, 1, 1))),
            self.put("small.png", png((64, 64), (2, 2, 2))),
            self.put("medium.png", png((200, 200), (3, 3, 3))),
            self.put("pack.png", png((64, 64), (4, 4, 4))),
            self.put("huge.png", png((512, 300), (5, 5, 5))),
            self.put("notes.txt", b"not a picture"),
        ]
        chosen = pictures.choose(files, self.dir)
        self.assertEqual([p.name for p, _ in chosen], ["pack.png", "huge.png", "medium.png"])

    def test_the_same_picture_under_two_names_is_looked_at_once(self):
        same = png((300, 300), (9, 9, 9))
        files = [self.put("a/one.png", same), self.put("b/two.png", same), self.put("c/other.png", png((300, 300), (8, 8, 8)))]
        chosen = pictures.choose(files, self.dir)
        self.assertEqual(len(chosen), 2)

    def test_the_cap(self):
        files = [self.put(f"big{i}.png", png((150 + i, 150), (i, i, i))) for i in range(6)]
        with mock.patch.object(pictures, "MAX_LOOKED_AT", 3):
            self.assertEqual(len(pictures.choose(files, self.dir)), 3)

    def test_a_damaged_picture_refuses_the_pack(self):
        files = [self.put("bad.png", b"\x89PNG\r\n\x1a\nthis is not a picture")]
        with self.assertRaisesRegex(rules.Refused, "damaged picture"):
            pictures.choose(files, self.dir)

    def test_a_pack_with_no_pictures(self):
        self.assertEqual(pictures.choose([self.put("a.txt", b"x")], self.dir), [])


class Scan(InTempDir):
    def chosen(self, names: list[str]) -> list[tuple[Path, int]]:
        paths = []
        for name in names:
            (self.dir / name).write_bytes(png((200, 200)))
            paths.append((self.dir / name, 40_000))
        return paths

    def test_a_clean_pack_reports_what_was_seen(self):
        chosen = self.chosen(["a.png", "b.png", "c.png"])
        report = pictures.scan(FakeClassifier({"b.png": 0.6, "c.png": 0.2}), chosen, self.dir)
        self.assertEqual((report.looked, report.near, report.highest, report.highest_path), (3, 1, 0.6, "b.png"))
        self.assertIn("highest 0.6000 (b.png)", report.line())

    def test_a_score_at_the_threshold_flags_the_pack(self):
        chosen = self.chosen(["a.png", "b.png", "c.png"])
        with self.assertRaises(pictures.Flagged) as caught:
            pictures.scan(FakeClassifier({"b.png": pictures.THRESHOLD}), chosen, self.dir)
        self.assertIsInstance(caught.exception, rules.Refused)
        self.assertIn("b.png", str(caught.exception))
        self.assertEqual(caught.exception.report.looked, 2)  # it stops at the first hit

    def test_a_score_just_under_the_threshold_passes(self):
        chosen = self.chosen(["a.png"])
        report = pictures.scan(FakeClassifier({"a.png": pictures.THRESHOLD - 0.001}), chosen, self.dir)
        self.assertEqual(report.near, 1)

    def test_batches_cover_every_picture(self):
        names = [f"p{i}.png" for i in range(35)]
        fake = FakeClassifier({})
        report = pictures.scan(fake, self.chosen(names), self.dir)
        self.assertEqual((report.looked, len(fake.asked)), (35, 35))
