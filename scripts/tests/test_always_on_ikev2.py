# SPDX-FileCopyrightText: 2026 Davide De Rosa
# SPDX-License-Identifier: GPL-3.0

import json
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


class AlwaysOnIKEv2Tests(unittest.TestCase):
    def command(self, output):
        script = Path(__file__).resolve().parents[1] / "always-on-ikev2.py"
        return [sys.executable, str(script), "--server", "192.0.2.1",
                "--local-identifier", "device@example.test",
                "--remote-identifier", "vpn.example.test",
                "--identity-asset", "test-certificate-asset",
                "--identifier", "test-vpn", "--server-token", "test-version",
                "--output", str(output)]

    def asset(self):
        return {
            "Type": "com.apple.asset.credential.identity",
            "Identifier": "test-certificate-asset",
            "ServerToken": "asset-version",
            "Payload": {
                "Authentication": {"Type": "None"},
                "Reference": {
                    "DataURL": "https://vpn.example.test/identity.json",
                    "ContentType": "application/json",
                    "Hash-SHA-256": "a" * 64,
                    "Size": 100,
                },
            },
        }

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

    def test_local_profile_contains_closed_declaration_dependencies_and_strict_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "always-on.mobileconfig"
            asset_file = Path(directory) / "identity-asset.json"
            supplied_asset = self.asset()
            asset_file.write_text(json.dumps(supplied_asset))
            command = self.command(output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                              "--identity-asset-file", str(asset_file)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertIn(str(output), result.stdout)
            self.assertGreater(output.stat().st_size, 0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            profile = plistlib.loads(output.read_bytes())
            self.assertEqual(profile["PayloadType"], "Configuration")
            self.assertEqual(profile["PayloadVersion"], 1)
            self.assertIs(profile["PayloadRemovalDisallowed"], False)
            self.assertTrue(profile["PayloadUUID"])
            self.assertTrue(profile["PayloadIdentifier"])
            declarations_payload, = profile["PayloadContent"]
            self.assertEqual(declarations_payload["PayloadType"], "com.apple.declarations")
            self.assertEqual(declarations_payload["PayloadVersion"], 1)
            self.assertNotEqual(declarations_payload["PayloadUUID"], profile["PayloadUUID"])
            encoded = declarations_payload["Declarations"]
            self.assertTrue(all(isinstance(item, bytes) for item in encoded))
            declarations = [json.loads(item) for item in encoded]
            self.assertEqual(len(declarations), 3)
            by_type = {item["Type"]: item for item in declarations}
            vpn = by_type["com.apple.configuration.network.vpn.always-on"]
            asset = by_type["com.apple.asset.credential.identity"]
            activation = by_type["com.apple.activation.simple"]
            self.assertEqual(asset, supplied_asset)
            self.assertEqual(activation["Payload"]["StandardConfigurations"], [vpn["Identifier"]])
            self.assertEqual(len({item["Identifier"] for item in declarations}), 3)
            payload = vpn["Payload"]
            for key in ("UIToggleEnabled", "AllowAllCaptiveNetworkPlugins", "AllowCaptiveWebSheet"):
                self.assertIs(payload[key], False)
            for key in ("AllowedCaptiveNetworkPlugins", "ApplicationExceptions", "ServiceExceptions"):
                self.assertEqual(payload[key], [])
            tunnel, = payload["TunnelConfigurations"]
            self.assertEqual(tunnel["ProtocolType"], "IKEv2")
            self.assertEqual(set(tunnel["Interfaces"]), {"Cellular", "WiFi"})
            self.assertEqual(tunnel["IKEV2"]["Authentication"]["IdentityAssetReference"], asset["Identifier"])
            previous = output.read_bytes()
            retry = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(retry.returncode, 0)
            self.assertEqual(output.read_bytes(), previous)
            another_output = Path(directory) / "same-profile.mobileconfig"
            subprocess.run(self.command(another_output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                                          "--identity-asset-file", str(asset_file)],
                           capture_output=True, text=True, check=True)
            self.assertEqual(profile, plistlib.loads(another_output.read_bytes()))

    def test_local_profile_requires_identity_asset_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "always-on.mobileconfig"
            result = subprocess.run(self.command(output) + ["--format", "mobileconfig"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires --identity-asset-file", result.stderr)
            self.assertFalse(output.exists())

    def test_local_profile_requires_explicit_private_asset_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "always-on.mobileconfig"
            asset_file = Path(directory) / "identity-asset.json"
            asset_file.write_text(json.dumps(self.asset()))
            command = self.command(output) + ["--format", "mobileconfig", "--identity-asset-file", str(asset_file)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires --local-asset-delivery private-https", result.stderr)
            self.assertFalse(output.exists())

    def test_local_profile_rejects_invalid_identity_assets_without_creating_output(self):
        cases = [
            ("wrong type", ("Type",), "com.apple.asset.credential.userpassword"),
            ("wrong identifier", ("Identifier",), "different-asset"),
            ("missing identifier", ("Identifier",), None),
            ("missing server token", ("ServerToken",), None),
            ("default MDM authentication", ("Payload", "Authentication"), None),
            ("MDM authentication", ("Payload", "Authentication", "Type"), "MDM"),
            ("insecure URL", ("Payload", "Reference", "DataURL"), "http://vpn.example.test/identity.json"),
            ("missing URL", ("Payload", "Reference", "DataURL"), None),
            ("URL credentials", ("Payload", "Reference", "DataURL"), "https://user:password@vpn.example.test/identity.json"),
            ("URL whitespace", ("Payload", "Reference", "DataURL"), "https://vpn.example.test/identity file.json"),
            ("wrong content type", ("Payload", "Reference", "ContentType"), "application/x-pkcs12"),
            ("malformed hash", ("Payload", "Reference", "Hash-SHA-256"), "bad-hash"),
            ("zero size", ("Payload", "Reference", "Size"), 0),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "always-on.mobileconfig"
            asset_file = Path(directory) / "identity-asset.json"
            for name, path, value in cases:
                with self.subTest(name=name):
                    asset = self.asset()
                    parent = asset
                    for key in path[:-1]:
                        parent = parent[key]
                    if value is None:
                        del parent[path[-1]]
                    else:
                        parent[path[-1]] = value
                    asset_file.write_text(json.dumps(asset))
                    command = self.command(output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                                      "--identity-asset-file", str(asset_file)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())

    def test_local_profile_rejects_identifier_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "always-on.mobileconfig"
            asset_file = Path(directory) / "identity-asset.json"
            asset_file.write_text(json.dumps(self.asset()))
            command = self.command(output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                              "--identity-asset-file", str(asset_file),
                                              "--identifier", "test-certificate-asset"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be distinct", result.stderr)
            self.assertFalse(output.exists())

    def test_local_profile_can_include_validated_pem_or_der_server_ca(self):
        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl, "OpenSSL is needed to verify the optional CA input end-to-end")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "ca.cnf"
            config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
                              "[dn]\nCN=Require VPN Test CA\n[extensions]\nbasicConstraints=critical,CA:true\n"
                              "keyUsage=critical,keyCertSign,cRLSign\n")
            ca_pem = root / "ca.pem"
            ca_der = root / "ca.der"
            subprocess.run([openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-keyout", str(root / "test-ca.key"), "-out", str(ca_pem), "-config", str(config)],
                           capture_output=True, check=True)
            subprocess.run([openssl, "x509", "-in", str(ca_pem), "-outform", "DER", "-out", str(ca_der)],
                           capture_output=True, check=True)
            asset_file = root / "identity-asset.json"
            asset_file.write_text(json.dumps(self.asset()))
            for source in (ca_pem, ca_der):
                with self.subTest(format=source.suffix):
                    output = root / (source.suffix + ".mobileconfig")
                    command = self.command(output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                                      "--identity-asset-file", str(asset_file),
                                                      "--server-ca-certificate", str(source)]
                    subprocess.run(command, capture_output=True, text=True, check=True)
                    profile = plistlib.loads(output.read_bytes())
                    self.assertEqual(len(profile["PayloadContent"]), 2)
                    ca, declarations = profile["PayloadContent"]
                    self.assertEqual(ca["PayloadType"], "com.apple.security.root")
                    self.assertEqual(ca["PayloadContent"], ca_der.read_bytes())
                    self.assertEqual(declarations["PayloadType"], "com.apple.declarations")
                    self.assertEqual(len(declarations["Declarations"]), 3)
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            invalid = root / "invalid-ca.pem"
            for data in (b"not a certificate", (root / "test-ca.key").read_bytes(),
                         ca_pem.read_bytes() + (root / "test-ca.key").read_bytes()):
                invalid.write_bytes(data)
                output = root / "invalid.mobileconfig"
                command = self.command(output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                                  "--identity-asset-file", str(asset_file),
                                                  "--server-ca-certificate", str(invalid)]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
            config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
                              "[dn]\nCN=Require VPN Test Leaf\n[extensions]\nbasicConstraints=critical,CA:false\n"
                              "keyUsage=critical,digitalSignature\n")
            leaf = root / "leaf.pem"
            subprocess.run([openssl, "req", "-new", "-x509", "-key", str(root / "test-ca.key"),
                            "-days", "1", "-out", str(leaf), "-config", str(config)],
                           capture_output=True, check=True)
            output = root / "leaf.mobileconfig"
            command = self.command(output) + ["--format", "mobileconfig", "--local-asset-delivery", "private-https",
                                              "--identity-asset-file", str(asset_file),
                                              "--server-ca-certificate", str(leaf)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CA:TRUE", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
