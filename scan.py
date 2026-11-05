"""Checks every resource pack that waits for it, then approves or refuses it through the API.

Run by the "Scan packs" workflow (.github/workflows/scan-pack.yml). Needs PACKS_API_URL and PACKS_SCAN_SECRET.

For each pack: download (and fingerprint), structure rules, unpack, virus scan, picture scan, verdict. A pack that is
refused is told why in plain words. A pack that could not be judged because something broke (the network, the scanner
itself) gets no verdict at all and is picked up again by the next run."""

import os
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pictures
import rules
import unpack
import virus
from service import Service


def judge(service: Service, pack: dict, classifier_for) -> None:
    pack_id = pack["id"]
    started = last = time.monotonic()

    def lap(what: str) -> None:
        nonlocal last
        now = time.monotonic()
        print(f"{pack_id}: {what} took {now - last:.1f}s")
        last = now

    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        file = work / "pack.zip"
        sha1, sha256, etag = service.download(pack_id, file)
        lap("download")
        try:
            try:
                archive = zipfile.ZipFile(file)
            except zipfile.BadZipFile:
                raise rules.Refused("This is not a zip file.")
            with archive:
                kept = rules.check(archive)
                folder = work / "files"
                written = unpack.extract(archive, kept, folder)
            lap("structure and unpacking")
            chosen = pictures.choose(written, folder)
            lap(f"picking {len(chosen)} pictures")
            # The virus scan is a separate program, so it runs while the pictures are judged (and the model loads).
            with ThreadPoolExecutor(max_workers=1) as pool:
                scanning = pool.submit(virus.scan, folder)
                refused = None
                try:
                    if chosen:
                        pictures.scan(classifier_for(), chosen, folder)
                        lap("pictures")
                except rules.Refused as why:
                    refused = why
                # A broken virus scan must not hide a refusal the pictures already decided.
                try:
                    scanning.result()
                except rules.Refused as why:
                    refused = refused or why
                if refused:
                    raise refused
            lap("virus scan finished (waited)")
        except rules.Refused as why:
            print(f"{pack_id}: refused: {why}")
            service.refuse(pack_id, str(why))
            return
        service.approve(pack_id, sha1, sha256, etag)
        print(f"{pack_id}: approved ({len(chosen)} pictures looked at) in {time.monotonic() - started:.1f}s")


def main() -> int:
    service = Service(os.environ["PACKS_API_URL"], os.environ["PACKS_SCAN_SECRET"])
    waiting = service.waiting()
    print(f"{len(waiting)} pack(s) waiting")
    classifier = None

    def classifier_for():
        nonlocal classifier
        if classifier is None:
            classifier = pictures.Classifier()
        return classifier

    failed, tried = 0, set()
    # The list holds 20 at a time; ask again until nothing new is waiting (a pack that failed is not retried in this run).
    while waiting := [p for p in waiting if p["id"] not in tried]:
        for pack in waiting:
            tried.add(pack["id"])
            try:
                judge(service, pack, classifier_for)
            except Exception as error:  # nothing was decided: leave the pack waiting for the next run
                failed += 1
                print(f"{pack['id']}: could not be judged, left waiting: {type(error).__name__}: {error}", file=sys.stderr)
        waiting = service.waiting()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
