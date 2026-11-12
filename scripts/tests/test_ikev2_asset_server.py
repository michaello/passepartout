# SPDX-License-Identifier: GPL-3.0

import base64
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


SCRIPT = Path(__file__).resolve().parents[1] / "ikev2-asset-server.py"


class AssetServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.key = self.directory / "server.key"
        self.cert = self.directory / "server.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.key), "-out", str(self.cert), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, capture_output=True)
        self.key.chmod(0o600)
        identity = self.directory / "identity.p12"
        subprocess.run(["openssl", "pkcs12", "-export", "-inkey", str(self.key),
                        "-in", str(self.cert), "-out", str(identity), "-passout", "pass:test-fixture"],
                       check=True, capture_output=True)
        self.asset = self.directory / "asset.json"
        self.asset.write_text(json.dumps({"Password": "test-fixture",
                                        "Identity": base64.b64encode(identity.read_bytes()).decode("ascii")}))
        self.asset.chmod(0o600)
        self.url_file = self.directory / "url.txt"
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0))
            self.port = connection.getsockname()[1]
        self.command = [sys.executable, str(SCRIPT), "--asset", str(self.asset),
                        "--tls-certificate", str(self.cert), "--tls-key", str(self.key),
                        "--port", str(self.port), "--origin", f"https://127.0.0.1:{self.port}",
                        "--url-file", str(self.url_file), "--expires-after", "3", "--max-downloads", "2"]
        self.context = ssl.create_default_context(cafile=str(self.cert))

    @contextmanager
    def running_server(self):
        process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not self.url_file.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    output, error = process.communicate(timeout=2)
                    self.fail(f"Server failed to become ready: {output} {error}")
                time.sleep(0.01)
            yield process, self.url_file.read_text().strip()
        finally:
            if process.poll() is None:
                process.terminate()
            output, error = process.communicate(timeout=5)
            self.assertNotIn("test-fixture", output + error)
            if self.url_file.exists():
                self.assertNotIn(self.url_file.read_text().strip().split("/")[-1], output + error)

    def request(self, url):
        return urllib.request.urlopen(url, context=self.context, timeout=3)

    def test_https_capability_and_download_limit(self):
        with self.running_server() as (_process, url):
            token = url.rsplit("/", 1)[1]
            self.assertGreaterEqual(len(token), 43)
            self.assertEqual(self.url_file.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                self.request(url + "-wrong")
            self.assertEqual(rejected.exception.code, 404)
            rejected.exception.close()
            for _ in range(2):
                with self.request(url) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), self.asset.read_bytes())
                    self.assertIn("no-store", response.headers["Cache-Control"])
            with self.assertRaises(urllib.error.HTTPError) as exhausted:
                self.request(url)
            self.assertEqual(exhausted.exception.code, 410)
            exhausted.exception.close()

    def test_expiration_stops_service(self):
        self.command[self.command.index("--expires-after") + 1] = "1"
        with self.running_server() as (process, url):
            process.wait(timeout=5)
            self.assertEqual(process.returncode, 0)
            with self.assertRaises(urllib.error.URLError):
                self.request(url)

    def test_plain_http_never_returns_identity(self):
        with self.running_server() as (_process, url):
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as connection:
                connection.sendall(f"GET /credential/{url.rsplit('/', 1)[1]} HTTP/1.0\r\n\r\n".encode())
                try:
                    response = connection.recv(65536)
                except ConnectionResetError:
                    response = b""
            self.assertNotIn(b"Identity", response)
            with self.request(url) as response:
                self.assertEqual(response.read(), self.asset.read_bytes())

    def test_readable_secret_file_is_rejected(self):
        self.asset.chmod(0o644)
        result = subprocess.run(self.command, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private file", result.stderr)
        self.assertFalse(self.url_file.exists())

    def test_existing_url_file_is_not_overwritten(self):
        self.url_file.write_text("existing")
        result = subprocess.run(self.command, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.url_file.read_text(), "existing")

    def test_short_token_is_rejected(self):
        token = self.directory / "token"
        token.write_text("predictable")
        token.chmod(0o600)
        result = subprocess.run(self.command + ["--token-file", str(token)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.url_file.exists())


if __name__ == "__main__":
    unittest.main()
