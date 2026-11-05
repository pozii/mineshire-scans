"""Talking to the Mineshire API: which packs wait, where to read them, and the verdict."""

import hashlib
import json
import urllib.request
from pathlib import Path

MAX_DOWNLOAD = 100 * 1024 * 1024 + 1024


class Service:
    def __init__(self, base: str, secret: str) -> None:
        self.base = base.rstrip("/")
        self.headers = {"authorization": f"Bearer {secret}", "user-agent": "mineshire-scanner"}

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers={**self.headers, "content-type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=60) as answer:
            return json.load(answer)

    def waiting(self) -> list[dict]:
        return self._call("GET", "/internal/packs/waiting")["packs"]

    def download(self, pack_id: str, target: Path) -> tuple[str, str, str]:
        """Saves the pack and returns its SHA-1 (what Minecraft checks), its SHA-256 (what tells two packs apart) and its
        ETag (the storage's fingerprint of exactly these bytes)."""
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

    def approve(self, pack_id: str, sha1: str, sha256: str, etag: str) -> None:
        self._call("POST", f"/internal/packs/{pack_id}/verdict", {"ok": True, "sha1": sha1, "sha256": sha256, "etag": etag})

    def refuse(self, pack_id: str, reason: str) -> None:
        self._call("POST", f"/internal/packs/{pack_id}/verdict", {"ok": False, "reason": reason})
