"""The calls to the API, against a small real HTTP server that answers from a script."""

import hashlib
import http.server
import json
import threading
import urllib.error
from unittest import mock

import service
from tests.helpers import InTempDir


class Scripted:
    """A local server. `script` maps (method, path) to the answers to give in turn; the last one repeats."""

    def __init__(self, script: dict[tuple[str, str], list[tuple[int, bytes, dict]]]) -> None:
        self.script, self.hits = script, {}
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def handle_any(self):
                key = (self.command, self.path)
                owner.hits[key] = owner.hits.get(key, 0) + 1
                answers = owner.script[key]
                status, body, headers = answers[min(owner.hits[key], len(answers)) - 1]
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.handle_any()

            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self.handle_any()

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def ok(payload) -> tuple[int, bytes, dict]:
    return 200, json.dumps(payload).encode(), {"content-type": "application/json"}


class Calls(InTempDir):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch.object(service, "PAUSES", (0, 0))  # no waiting between tries in tests
        patch.start()
        self.addCleanup(patch.stop)

    def serve(self, script) -> Scripted:
        fake = Scripted(script)
        self.addCleanup(fake.close)
        return fake

    def test_the_secret_goes_to_the_api_as_a_bearer_token(self):
        seen = {}
        fake = self.serve({("GET", "/internal/packs/waiting"): [ok({"packs": [{"id": "a"}]})]})
        original = service.urllib.request.urlopen

        def peek(request, timeout=None):
            seen["authorization"] = request.get_header("Authorization")
            return original(request, timeout=timeout)

        with mock.patch.object(service.urllib.request, "urlopen", peek):
            self.assertEqual(service.Service(fake.url, "s3cret").waiting(), [{"id": "a"}])
        self.assertEqual(seen["authorization"], "Bearer s3cret")

    def test_a_server_error_is_tried_again(self):
        fake = self.serve({("GET", "/internal/packs/waiting"): [(503, b"{}", {}), (502, b"{}", {}), ok({"packs": []})]})
        self.assertEqual(service.Service(fake.url, "s").waiting(), [])
        self.assertEqual(fake.hits[("GET", "/internal/packs/waiting")], 3)

    def test_it_gives_up_after_three_tries(self):
        fake = self.serve({("GET", "/internal/packs/waiting"): [(503, b"{}", {})]})
        with self.assertRaises(urllib.error.HTTPError):
            service.Service(fake.url, "s").waiting()
        self.assertEqual(fake.hits[("GET", "/internal/packs/waiting")], 3)

    def test_a_refusal_is_not_tried_again(self):
        fake = self.serve({("GET", "/internal/packs/waiting"): [(401, b"{}", {})]})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            service.Service(fake.url, "wrong").waiting()
        self.assertEqual(caught.exception.code, 401)
        self.assertEqual(fake.hits[("GET", "/internal/packs/waiting")], 1)

    def test_a_server_that_is_not_there_is_tried_three_times_then_fails(self):
        fake = Scripted({})
        url = fake.url
        fake.close()
        with mock.patch.object(service.time, "sleep") as slept, self.assertRaises(urllib.error.URLError):
            service.Service(url, "s").waiting()
        self.assertEqual(slept.call_count, 2)

    def test_a_verdict_is_retried_too(self):
        fake = self.serve({("POST", "/internal/packs/p1/verdict"): [(503, b"{}", {}), ok({"ok": True})]})
        service.Service(fake.url, "s").refuse("p1", "because")
        self.assertEqual(fake.hits[("POST", "/internal/packs/p1/verdict")], 2)

    def test_download_returns_the_fingerprints_and_asks_for_a_new_link_on_a_retry(self):
        body = b"zip bytes " * 1000
        fake = self.serve({})
        link = f"{fake.url}/file"
        fake.script = {
            ("GET", "/internal/packs/p1/download"): [ok({"url": link})],
            ("GET", "/file"): [(503, b"", {}), (200, body, {"ETag": '"abc123"'})],
        }
        target = self.dir / "out.zip"
        sha1, sha256, etag = service.Service(fake.url, "s").download("p1", target)
        self.assertEqual((sha1, sha256, etag), (hashlib.sha1(body).hexdigest(), hashlib.sha256(body).hexdigest(), "abc123"))
        self.assertEqual(target.read_bytes(), body)
        self.assertEqual(fake.hits[("GET", "/internal/packs/p1/download")], 2)

    def test_download_without_an_etag_fails(self):
        fake = self.serve({})
        fake.script = {
            ("GET", "/internal/packs/p1/download"): [ok({"url": f"{fake.url}/file"})],
            ("GET", "/file"): [(200, b"data", {})],
        }
        with self.assertRaisesRegex(RuntimeError, "ETag"):
            service.Service(fake.url, "s").download("p1", self.dir / "out.zip")

    def test_a_file_larger_than_a_pack_may_be(self):
        fake = self.serve({})
        fake.script = {
            ("GET", "/internal/packs/p1/download"): [ok({"url": f"{fake.url}/file"})],
            ("GET", "/file"): [(200, b"x" * 5000, {"ETag": '"e"'})],
        }
        with mock.patch.object(service, "MAX_DOWNLOAD", 1000), self.assertRaisesRegex(RuntimeError, "larger"):
            service.Service(fake.url, "s").download("p1", self.dir / "out.zip")
