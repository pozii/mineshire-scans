"""Malware check with ClamAV (installed by the workflow). A resource pack that passed the structure rules holds no
programs, so this mostly catches a crafted picture or sound; it is cheap, so it runs on every pack anyway."""

import subprocess
from pathlib import Path

import rules


def scan(folder: Path) -> None:
    """Raises Refused when ClamAV reports something. Any other failure raises RuntimeError: the pack is not judged, it waits for the next run."""
    done = subprocess.run(
        ["clamscan", "--recursive", "--infected", "--no-summary", str(folder)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    # clamscan: 0 nothing found, 1 something found, anything else is an error.
    if done.returncode == 1:
        raise rules.Refused("A virus scanner reported something harmful in this pack.")
    if done.returncode != 0:
        raise RuntimeError(f"clamscan failed ({done.returncode}): {done.stderr.strip()[:300]}")
