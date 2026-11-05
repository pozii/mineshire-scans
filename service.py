"""Talking to the Mineshire API: which packs wait, where to read them, and the verdict."""

import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

MAX_DOWNLOAD = 100 * 1024 * 1024 + 1024
# Seconds to wait before the second and the third try. A blip in the network must not cost a whole scan: a pack that
# fails at the verdict would be downloaded and judged again from the start at the next run.
PAUSES = (2, 6)


def retrying(call):
    """Runs `call`, trying again after a short wait when the network fails or the server answers with an error of its
    own (5xx or 429). A refusal such as 401 or 404 is a real answer and is raised at once."""
    for pause in (*PAUSES, None):
        try:
            return call()
        except urllib.error.HTTPError as error:
            if error.code < 500 and error.code != 429:
                raise
            if pause is None:
                raise
            error.close()  # the answer is not wanted; release its connection before trying again
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if pause is None:
                raise
        time.sleep(pause)


class Service:
    def __init__(self, base: str, secret: str) -> None:
        self.base = base.rstrip("/")
        self.headers = {"authorization": f"Bearer {secret}", "user-agent": "mineshire-scanner"}

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None

        def once() -> dict:
            request = urllib.request.Request(
                self.base + path, data=data, method=method, headers={**self.headers, "content-type": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=60) as answer:
                return json.load(answer)

        return retrying(once)

    def waiting(self) -> list[dict]:
        return self._call("GET", "/internal/packs/waiting")["packs"]

    def download(self, pack_id: str, target: Path) -> tuple[str, str, str]:
        """Saves the pack and returns its SHA-1 (what Minecraft checks), its SHA-256 (what tells two packs apart) and its
        ETag (the storage's fingerprint of exactly these bytes)."""

        def once() -> tuple[str, str, str]:
            # The link is asked for again on every try: it is good for one use.
            link = self._call("GET", f"/internal/packs/{pack_id}/download")["url"]
            sha1, sha256, size = hashlib.sha1(), hashlib.sha256(), 0
            with urllib.request.urlopen(urllib.request.Request(link, headers={"user-agent": "mineshire-scanner"}), timeout=120) as answer:
                etag = (answer.headers.get("etag") or "").replace('"', "")
                with open(target, "wb") as out:
                    while chunk := answer.read(1 << 20):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD:
                            raise RuntimeError("The file is larger than a pack may be.")
                        sha1.update(chunk)
                        sha256.update(chunk)
                        out.write(chunk)
            if not etag:
                raise RuntimeError("The storage did not send an ETag.")
            return sha1.hexdigest(), sha256.hexdigest(), etag

        return retrying(once)

    def approve(self, pack_id: str, sha1: str, sha256: str, etag: str) -> None:
        self._call("POST", f"/internal/packs/{pack_id}/verdict", {"ok": True, "sha1": sha1, "sha256": sha256, "etag": etag})

    def refuse(self, pack_id: str, reason: str) -> None:
        self._call("POST", f"/internal/packs/{pack_id}/verdict", {"ok": False, "reason": reason})
