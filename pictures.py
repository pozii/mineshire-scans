"""Picture check: finds adult pictures with an open image classifier (Falconsai/nsfw_image_detection, Apache-2.0).

Which pictures are looked at: pack.png always, then every picture with a side of 128 px or more (menu backgrounds,
panoramas, paintings, skins, maps), largest first, up to MAX_LOOKED_AT. Block and item tiles (16 to 64 px) are not
judged one by one: at that size a classifier can't tell, and tiny tiles can't show a photograph. This is a filter for
what is easy to see, not a guarantee."""

import hashlib
import os
from pathlib import Path

from PIL import Image

import rules

MODEL = "Falconsai/nsfw_image_detection"
# Most packs are decided by far fewer than this; the cap keeps a pack made of 20,000 big pictures from running for hours.
MAX_LOOKED_AT = 300
MIN_SIDE = 128
# The share of confidence at which a picture counts as adult. Tune it on real packs; a pixel-art pack can fool a photo model.
THRESHOLD = float(os.environ.get("PICTURE_THRESHOLD", "0.85"))

Image.MAX_IMAGE_PIXELS = 50_000_000  # PIL then refuses a "decompression bomb" instead of filling the memory


def choose(files: list[Path], root: Path) -> list[tuple[Path, int]]:
    """The pictures to classify, with their size, in the order they are looked at. Raises Refused for a broken picture."""
    sized = []
    for path in files:
        if path.suffix.lower() != ".png":
            continue
        try:
            with Image.open(path) as image:
                image.verify()
            with Image.open(path) as image:
                sized.append((path, image.width, image.height))
        except Exception:
            raise rules.Refused(f"{path.relative_to(root).as_posix()} is a damaged picture.")
    # The same picture saved under several names is looked at once (pack.png first, so it is the one that stays).
    sized.sort(key=lambda s: s[0].relative_to(root).as_posix() != "pack.png")
    seen: set[str] = set()
    unique = []
    for s in sized:
        digest = hashlib.sha1(s[0].read_bytes()).hexdigest()
        if digest not in seen:
            seen.add(digest)
            unique.append(s)
    sized = unique
    icon = [s for s in sized if s[0].relative_to(root).as_posix() == "pack.png"]
    big = sorted((s for s in sized if max(s[1], s[2]) >= MIN_SIDE and s not in icon), key=lambda s: s[1] * s[2], reverse=True)
    return [(p, w * h) for p, w, h in (icon + big)[:MAX_LOOKED_AT]]


class Classifier:
    def __init__(self) -> None:
        # Imported here so the structure checks run (and are tested) without the heavy libraries installed.
        import torch
        from transformers import AutoImageProcessor, AutoModelForImageClassification

        self.torch = torch
        self.processor = AutoImageProcessor.from_pretrained(MODEL)
        self.model = AutoModelForImageClassification.from_pretrained(MODEL).eval()
        names = {int(i): label.lower() for i, label in self.model.config.id2label.items()}
        found = [i for i, label in names.items() if label == "nsfw"]
        if not found:
            raise RuntimeError(f"The picture model has no 'nsfw' label (it has {sorted(names.values())}).")
        self.nsfw = found[0]

    def score(self, paths: list[Path]) -> list[float]:
        images = []
        for path in paths:
            try:
                with Image.open(path) as image:
                    # Transparent pixels would turn black; lay the picture on white like a viewer would.
                    rgba = image.convert("RGBA")
                    flat = Image.new("RGB", rgba.size, "white")
                    flat.paste(rgba, mask=rgba.getchannel("A"))
                    images.append(flat)
            except Exception:
                raise rules.Refused(f"{path.name} is a damaged picture.")
        with self.torch.inference_mode():
            logits = self.model(**self.processor(images=images, return_tensors="pt")).logits
        return self.torch.softmax(logits, dim=-1)[:, self.nsfw].tolist()


def scan(classifier: Classifier, chosen: list[tuple[Path, int]], root: Path) -> None:
    """Raises Refused at the first picture that looks adult."""
    paths = [p for p, _ in chosen]
    for start in range(0, len(paths), 16):
        batch = paths[start : start + 16]
        for path, score in zip(batch, classifier.score(batch)):
            if score >= THRESHOLD:
                raise rules.Refused(f"A picture in this pack ({path.relative_to(root).as_posix()}) looks like adult content.")
