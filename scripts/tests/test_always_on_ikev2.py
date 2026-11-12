# SPDX-FileCopyrightText: 2026 Davide De Rosa
# SPDX-License-Identifier: GPL-3.0

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class AlwaysOnIKEv2Tests(unittest.TestCase):
    def test_generate_and_refuse_overwrite(self):
        script = Path(__file__).resolve().parents[1] / "always-on-ikev2.py"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "always-on.json"
            command = [sys.executable, str(script), "--server", "192.0.2.1",
                       "--local-identifier", "device@example.test",
                       "--remote-identifier", "vpn.example.test",
                       "--identity-asset", "test-certificate-asset",
                       "--identifier", "test-vpn", "--server-token", "test-version",
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertIn(str(output), result.stdout)
            self.assertGreater(output.stat().st_size, 0)
            config = json.loads(output.read_text())
            self.assertEqual(config["Type"], "com.apple.configuration.network.vpn.always-on")
            self.assertEqual(config["Identifier"], "test-vpn")
            payload = config["Payload"]
            for key in ("UIToggleEnabled", "AllowAllCaptiveNetworkPlugins", "AllowCaptiveWebSheet"):
                self.assertIs(payload[key], False)
            for key in ("AllowedCaptiveNetworkPlugins", "ApplicationExceptions", "ServiceExceptions"):
                self.assertEqual(payload[key], [])
            tunnel, = payload["TunnelConfigurations"]
            self.assertEqual(tunnel["ProtocolType"], "IKEv2")
            self.assertEqual(set(tunnel["Interfaces"]), {"Cellular", "WiFi"})
            self.assertEqual(tunnel["IKEV2"]["HostName"], "192.0.2.1")
            self.assertEqual(tunnel["IKEV2"]["Authentication"], {
                "Method": "Certificate", "IdentityAssetReference": "test-certificate-asset"})
            previous = output.read_bytes()
            retry = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(retry.returncode, 0)
            self.assertEqual(output.read_bytes(), previous)

    def test_missing_server_is_rejected(self):
        script = Path(__file__).resolve().parents[1] / "always-on-ikev2.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required", result.stderr)


if __name__ == "__main__":
    unittest.main()
