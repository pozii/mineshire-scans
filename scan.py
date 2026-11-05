"""Checks every resource pack that waits for it, then approves or refuses it through the API.

Run by the "Scan packs" workflow (.github/workflows/scan-pack.yml). Needs PACKS_API_URL and PACKS_SCAN_SECRET.

For each pack: download (and fingerprint), structure rules, unpack (looking at what the bytes are), virus scan, picture
scan, verdict. A pack that is refused is told why in plain words. A pack that could not be judged because something broke
(the network, the scanner itself) gets no verdict at all and is picked up again by the next run. The run stops starting
new packs after SCAN_BUDGET_SECONDS so the workflow's own time limit never cuts a scan in half; what is left waits."""

import os
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pictures
import rules
import unpack
import virus
from service import Service

BUDGET = float(os.environ.get("SCAN_BUDGET_SECONDS", 20 * 60))


@dataclass
class Outcome:
    pack_id: str
    verdict: str  # "approved" or "refused"
    detail: str
    seconds: float


def judge(service: Service, pack: dict, classifier_for) -> Outcome:
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
        report = None
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
                        report = pictures.scan(classifier_for(), chosen, folder)
                        print(f"{pack_id}: pictures: {report.line()}")
                        lap("pictures")
                except pictures.Flagged as why:
                    print(f"{pack_id}: pictures: {why.report.line()}")
                    refused = why
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
            return Outcome(pack_id, "refused", str(why), time.monotonic() - started)
        service.approve(pack_id, sha1, sha256, etag)
        seconds = time.monotonic() - started
        print(f"{pack_id}: approved ({len(chosen)} pictures looked at) in {seconds:.1f}s")
        return Outcome(pack_id, "approved", report.line() if report else "no pictures to look at", seconds)


def summarize(outcomes: list[Outcome], failed: list[tuple[str, str]], postponed: int) -> None:
    """One line in the log, and a table on the run's page when GitHub gives a file for it."""
    approved = sum(o.verdict == "approved" for o in outcomes)
    print(f"done: {approved} approved, {len(outcomes) - approved} refused, {len(failed)} could not be judged, {postponed} left for the next run")
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path or not (outcomes or failed or postponed):
        return
    rows = [f"| `{o.pack_id[:8]}` | {o.verdict} | {o.seconds:.0f} s | {o.detail} |" for o in outcomes]
    rows += [f"| `{pack_id[:8]}` | could not be judged | | {error} |" for pack_id, error in failed]
    with open(path, "a", encoding="utf-8") as out:
        out.write("| Pack | Result | Time | Detail |\n|---|---|---|---|\n" + "\n".join(rows) + "\n")
        if postponed:
            out.write(f"\n{postponed} pack(s) are left for the next run (time budget reached).\n")


def run(service, classifier_for, budget: float = BUDGET, clock=time.monotonic) -> int:
    started = clock()
    waiting = service.waiting()
    print(f"{len(waiting)} pack(s) waiting")
    outcomes: list[Outcome] = []
    failed: list[tuple[str, str]] = []
    tried: set[str] = set()
    postponed = 0
    # The list holds 20 at a time; ask again until nothing new is waiting (a pack that failed is not retried in this run).
    while waiting := [p for p in waiting if p["id"] not in tried]:
        for pack in waiting:
            if clock() - started > budget:
                postponed += 1
                continue
            tried.add(pack["id"])
            try:
                outcomes.append(judge(service, pack, classifier_for))
            except Exception as error:  # nothing was decided: leave the pack waiting for the next run
                failed.append((pack["id"], f"{type(error).__name__}: {error}"[:200]))
                print(f"{pack['id']}: could not be judged, left waiting: {type(error).__name__}: {error}", file=sys.stderr)
        if postponed:
            break
        waiting = service.waiting()
    summarize(outcomes, failed, postponed)
    return 1 if failed else 0


def main() -> int:
    service = Service(os.environ["PACKS_API_URL"], os.environ["PACKS_SCAN_SECRET"])
    classifier = None

    def classifier_for():
        nonlocal classifier
        if classifier is None:
            classifier = pictures.Classifier()
        return classifier

    return run(service, classifier_for)


if __name__ == "__main__":
    sys.exit(main())
