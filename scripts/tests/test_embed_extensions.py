# SPDX-License-Identifier: GPL-3.0

import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest


class EmbedExtensionsTests(unittest.TestCase):
    script = Path(__file__).resolve().parents[2] / "app-apple/Passepartout/Scripts/embed-extensions.sh"
    app_id = "com.example.TestVPN"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vpn embed ")
        self.addCleanup(self.temporary.cleanup)
        self.products = Path(self.temporary.name) / "build products"
        self.products.mkdir()
        self.app = self.products / "Test VPN.app"
        self.app.mkdir()
        self.make_bundle("PassepartoutLoginItem.app", self.app_id + ".LoginItem")
        self.make_bundle("PassepartoutTunnel.appex", self.app_id + ".Tunnel")
        self.make_bundle(self.app_id + ".Tunnel.systemextension", self.app_id + ".Tunnel")
        self.guard = self.make_bundle(self.app_id + ".NetworkGuard.systemextension", self.app_id + ".NetworkGuard")
        self.environment = {
            **os.environ,
            "BUILT_PRODUCTS_DIR": str(self.products),
            "PRODUCT_NAME": "Test VPN",
            "PLATFORM_NAME": "macosx",
            "CONFIGURATION": "ReleaseMac",
            "CFG_APP_ID": self.app_id,
            "CFG_TUNNEL_ID": self.app_id + ".Tunnel",
            "CFG_GUARD_ID": self.app_id + ".NetworkGuard",
            "CFG_EMBED_NETWORK_GUARD": "NO",
        }

    def make_bundle(self, name, identifier):
        bundle = self.products / name
        (bundle / "Contents/MacOS").mkdir(parents=True)
        (bundle / "Contents/MacOS/fixture").write_bytes(b"fixture executable")
        with (bundle / "Contents/Info.plist").open("wb") as output:
            plistlib.dump({"CFBundleIdentifier": identifier}, output)
        return bundle

    def run_script(self, **overrides):
        return subprocess.run(["/bin/sh", str(self.script)], env={**self.environment, **overrides},
                              capture_output=True, text=True)

    def test_opt_in_embeds_separate_guard_with_derived_identifier(self):
        result = self.run_script(CFG_EMBED_NETWORK_GUARD="YES")
        self.assertEqual(result.returncode, 0, result.stderr)
        extensions = self.app / "Contents/Library/SystemExtensions"
        self.assertEqual({path.name for path in extensions.iterdir()}, {
            self.app_id + ".Tunnel.systemextension", self.app_id + ".NetworkGuard.systemextension"})
        guard = extensions / self.guard.name
        self.assertEqual((guard / "Contents/MacOS/fixture").read_bytes(), b"fixture executable")
        with (guard / "Contents/Info.plist").open("rb") as source:
            self.assertEqual(plistlib.load(source)["CFBundleIdentifier"], self.app_id + ".NetworkGuard")
        self.assertTrue((self.app / "Contents/Library/LoginItems/PassepartoutLoginItem.app").is_dir())

    def test_incremental_copy_removes_old_files_and_opt_out_removes_only_guard(self):
        self.assertEqual(self.run_script(CFG_EMBED_NETWORK_GUARD="YES").returncode, 0)
        extensions = self.app / "Contents/Library/SystemExtensions"
        guard = extensions / self.guard.name
        (guard / "obsolete").write_text("old extension content")
        self.assertEqual(self.run_script(CFG_EMBED_NETWORK_GUARD="YES").returncode, 0)
        self.assertFalse((guard / "obsolete").exists())
        unrelated = extensions / "unrelated.systemextension"
        unrelated.mkdir()
        self.assertEqual(self.run_script().returncode, 0)
        self.assertFalse(guard.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((extensions / (self.app_id + ".Tunnel.systemextension")).is_dir())

    def test_missing_guard_fails_before_embedding_any_bundles(self):
        result = self.run_script(CFG_EMBED_NETWORK_GUARD="YES", CFG_APP_ID="com.example.Missing",
                                 CFG_GUARD_ID="com.example.Missing.NetworkGuard")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing bundle", result.stderr)
        self.assertEqual(list(self.app.iterdir()), [])

    def test_mismatched_guard_identifier_fails_before_embedding(self):
        with (self.guard / "Contents/Info.plist").open("wb") as output:
            plistlib.dump({"CFBundleIdentifier": "com.example.Unrelated"}, output)
        result = self.run_script(CFG_EMBED_NETWORK_GUARD="YES")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Guard bundle identifier", result.stderr)
        self.assertEqual(list(self.app.iterdir()), [])

    def test_guard_opt_in_rejects_other_platforms_and_configurations(self):
        for overrides in ({"PLATFORM_NAME": "iphoneos"}, {"CONFIGURATION": "Debug"}):
            with self.subTest(overrides=overrides):
                result = self.run_script(CFG_EMBED_NETWORK_GUARD="YES", **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires macOS ReleaseMac", result.stderr)
        self.assertEqual(list(self.app.iterdir()), [])

    def test_normal_mac_and_ios_keep_packet_tunnel_app_extension_packaging(self):
        result = self.run_script(CONFIGURATION="Debug")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.app / "Contents/PlugIns/PassepartoutTunnel.appex").is_dir())
        self.assertFalse((self.app / "Contents/Library/SystemExtensions").exists())
        result = self.run_script(CONFIGURATION="Debug", PLATFORM_NAME="iphoneos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.app / "PlugIns/PassepartoutTunnel.appex").is_dir())


if __name__ == "__main__":
    unittest.main()
