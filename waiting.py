"""Counts the packs that wait and hands the number to the workflow. When it is 0 the workflow skips the heavy steps
(the Python packages, ClamAV, the picture model): the daily safety-net run usually finds nothing and would otherwise
spend more than a minute of Actions time to learn that. Uses only the standard library, so it needs no set-up."""

import os

from service import Service

count = len(Service(os.environ["PACKS_API_URL"], os.environ["PACKS_SCAN_SECRET"]).waiting())
print(f"{count} pack(s) waiting")
if path := os.environ.get("GITHUB_OUTPUT"):
    with open(path, "a", encoding="utf-8") as out:
        out.write(f"count={count}\n")
