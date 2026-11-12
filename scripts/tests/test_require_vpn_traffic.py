import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "require-vpn-traffic.py"
SPEC = importlib.util.spec_from_file_location("require_vpn_traffic", SCRIPT)
traffic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(traffic)


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


class TrafficTests(unittest.TestCase):
    def exercise_loopback(self, address):
        with tempfile.TemporaryDirectory(prefix="require-vpn-test-") as directory:
            collected = Path(directory) / "collector.jsonl"
            sent = Path(directory) / "client.jsonl"
            collector = subprocess.Popen([sys.executable, str(SCRIPT), "collect", "--bind", address,
                                          "--port", "0", "--duration", "4", "--output", str(collected)],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready = None
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    ready = next((row for row in rows(collected) if row["event"] == "ready"), None)
                    if ready:
                        break
                    if collector.poll() is not None:
                        self.fail(collector.communicate()[1])
                    time.sleep(0.02)
                self.assertIsNotNone(ready)
                client = subprocess.run([sys.executable, str(SCRIPT), "send", "--target", address,
                                         "--port", str(ready["port"]), "--duration", "0.6",
                                         "--interval", "0.05", "--timeout", "0.5", "--output", str(sent)],
                                        capture_output=True, text=True, timeout=4)
                self.assertEqual(client.returncode, 0, client.stderr)
                collector.communicate(timeout=5)
                self.assertEqual(collector.returncode, 0)
                observed = [row for row in rows(collected) if row["event"] == "observed"]
                acknowledged = [row for row in rows(sent) if row["event"] == "acknowledged"]
                self.assertGreater(len(observed), 8)
                self.assertEqual(len(observed), len(acknowledged))
                modes = {row["probe"]["mode"] for row in observed}
                self.assertEqual(modes, {"persistent_tcp", "new_tcp", "persistent_udp", "new_udp"})
                for mode in modes:
                    probes = [row["probe"] for row in observed if row["probe"]["mode"] == mode]
                    sessions = {probe["session_id"] for probe in probes}
                    self.assertGreater(len(probes), 1)
                    self.assertEqual(len(sessions), 1 if mode.startswith("persistent") else len(probes))
                    self.assertEqual([probe["sequence"] for probe in probes], list(range(1, len(probes) + 1)))
                self.assertEqual({row["source"][0] for row in observed}, {address})
                self.assertEqual(len({row["probe"]["run_id"] for row in observed}), 1)
                self.assertTrue(rows(sent)[0]["os"]["build"])
            finally:
                if collector.poll() is None:
                    collector.terminate()
                    collector.communicate(timeout=3)

    def test_ipv4_existing_and_new_sessions(self):
        self.exercise_loopback("127.0.0.1")

    def test_ipv6_existing_and_new_sessions(self):
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
                connection.bind(("::1", 0))
        except OSError as error:
            self.skipTest(str(error))
        self.exercise_loopback("::1")

    def test_direct_dns_probe_uses_controlled_numeric_server(self):
        with tempfile.TemporaryDirectory(prefix="require-vpn-dns-test-") as directory:
            output = Path(directory) / "dns.jsonl"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.bind(("127.0.0.1", 0))
                server.settimeout(2)
                received = []

                def respond():
                    packet, peer = server.recvfrom(4096)
                    received.append(packet)
                    server.sendto(packet[:2] + struct.pack("!H", 0x8183) + packet[4:], peer)

                responder = threading.Thread(target=respond)
                responder.start()
                result = subprocess.run([sys.executable, str(SCRIPT), "send", "--dns-server", "127.0.0.1",
                                         "--dns-port", str(server.getsockname()[1]), "--duration", "0.2",
                                         "--interval", "1", "--timeout", "0.5", "--output", str(output)],
                                        capture_output=True, text=True, timeout=3)
                responder.join(2)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(received), 1)
                response = next(row for row in rows(output) if row["event"] == "dns_response")
                self.assertEqual(response["rcode"], 3)
                self.assertIn(response["run_id"].replace("-", ""), response["query"])

    def test_hostnames_are_rejected_before_networking(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            traffic.parse_args(["send", "--target", "vpn.example.com"])

    def test_quic_unavailable_never_uses_tcp_fallback(self):
        version = subprocess.CompletedProcess(["curl"], 0, "curl test\nFeatures: HTTP2 SSL\n", "")
        with mock.patch.object(traffic.shutil, "which", return_value="/test/curl"), mock.patch.object(
                traffic.subprocess, "run", return_value=version) as run:
            executable, detail = traffic.quic_capability()
        self.assertIsNone(executable)
        self.assertIn("no TCP fallback", detail)
        self.assertEqual(run.call_count, 1)

    def test_actual_curl_capability_is_reported_without_fallback(self):
        executable, detail = traffic.quic_capability()
        if executable:
            self.assertTrue(detail.startswith("curl "))
        else:
            self.assertTrue(detail)
            result = subprocess.run([sys.executable, str(SCRIPT), "send", "--quic-url",
                                     "https://probe.invalid/", "--quic-target", "127.0.0.1",
                                     "--duration", "0.01"], capture_output=True, text=True, timeout=7)
            self.assertEqual(result.returncode, 0, result.stderr)
            capability = next(json.loads(line) for line in result.stdout.splitlines()
                              if json.loads(line)["event"] == "quic_capability")
            self.assertFalse(capability["available"])
            self.assertNotIn("quic_result", result.stdout)

    def test_output_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="require-vpn-preserve-test-") as directory:
            output = Path(directory) / "existing.jsonl"
            output.write_text("preserve\n")
            result = subprocess.run([sys.executable, str(SCRIPT), "send", "--target", "127.0.0.1",
                                     "--duration", "0.01", "--output", str(output)],
                                    capture_output=True, text=True, timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "preserve\n")


if __name__ == "__main__":
    unittest.main()
