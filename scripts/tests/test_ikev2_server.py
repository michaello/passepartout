# SPDX-License-Identifier: GPL-3.0

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SCRIPT = Path(__file__).resolve().parents[1] / "ikev2-server.py"
DOCKER = shutil.which("docker")


def generate(path):
    subprocess.run([sys.executable, str(SCRIPT), "--endpoint", "192.0.2.10", "--client-id",
                    "phone@example.test", "--dns", "9.9.9.9", "--egress-interface", "eth0",
                    "--output", str(path)], check=True, capture_output=True, text=True)


class IKEv2ServerTests(unittest.TestCase):
    def test_private_bundle_crypto_and_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "vpn"
            generate(bundle)
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o700)
            for path in bundle.rglob("*"):
                if path.is_file():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.name.endswith(".sh") else 0o600)
            self.assertFalse((bundle / "server/ca-key.pem").exists())
            self.assertFalse((bundle / "server/device-key.pem").exists())
            credential = json.loads((bundle / "client/credential.json").read_text())
            self.assertEqual(base64.b64decode(credential["Identity"]), (bundle / "client/identity.p12").read_bytes())
            self.assertEqual(credential["Password"], (bundle / "client/identity-password.txt").read_text().strip())
            result = subprocess.run(["openssl", "pkcs12", "-in", str(bundle / "client/identity.p12"),
                                     "-passin", "file:" + str(bundle / "client/identity-password.txt"),
                                     "-noout"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            certificate = subprocess.check_output(["openssl", "x509", "-in", str(bundle / "server/swanctl/x509/server.pem"),
                                                   "-noout", "-ext", "subjectAltName,extendedKeyUsage"], text=True)
            self.assertIn("192.0.2.10", certificate)
            self.assertIn("TLS Web Server Authentication", certificate)
            previous = (bundle / "private/ca-key.pem").read_bytes()
            with self.assertRaises(subprocess.CalledProcessError):
                generate(bundle)
            self.assertEqual((bundle / "private/ca-key.pem").read_bytes(), previous)

    def test_rejects_hostname_and_shell_injection(self):
        for endpoint, device, interface in (("vpn.example.test", "phone@example.test", "eth0"),
                                             ("192.0.2.10", "phone@example.test\n}", "eth0"),
                                             ("192.0.2.10", "phone@example.test", "eth0;false")):
            result = subprocess.run([sys.executable, str(SCRIPT), "--endpoint", endpoint, "--client-id", device,
                                     "--dns", "9.9.9.9", "--egress-interface", interface, "--output", "/unused"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("error:", result.stderr)

    @unittest.skipUnless(DOCKER and os.environ.get("REQUIRE_VPN_DOCKER_TESTS") == "1",
                         "Set REQUIRE_VPN_DOCKER_TESTS=1 for isolated Linux installer and IPsec tests")
    def test_linux_installer_and_authenticated_dual_stack_tunnel(self):
        suffix = uuid.uuid4().hex[:10]
        server, client, collector, network = ("require-vpn-server-" + suffix, "require-vpn-client-" + suffix,
                                              "require-vpn-collector-" + suffix, "require-vpn-net-" + suffix)

        def docker(*args, check=True):
            result = subprocess.run([DOCKER, *args], capture_output=True, text=True, timeout=180)
            if check and result.returncode:
                self.fail(result.stdout + result.stderr)
            return result

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "vpn"
            generate(bundle)
            docker("build", "-q", "-t", "passepartout-ikev2-test", "-f",
                   str(SCRIPT.with_name("ikev2-server-test.Dockerfile")), str(SCRIPT.parent))
            try:
                docker("network", "create", "--subnet", "192.0.2.0/24", network)
                docker("run", "-d", "--name", server, "--privileged", "--cgroupns=private", "--tmpfs", "/run",
                       "--tmpfs", "/run/lock", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-v",
                       str(bundle / "server") + ":/bundle:ro", "passepartout-ikev2-test", "/sbin/init")
                for _ in range(100):
                    if docker("exec", server, "test", "-d", "/run/systemd/system", check=False).returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("Container systemd did not start")
                installed = docker("exec", server, "/bin/sh", "/bundle/install.sh")
                self.assertIn("Gateway configuration loaded", installed.stdout)
                self.assertIn("active", docker("exec", server, "systemctl", "is-active", "strongswan").stdout)
                rules = docker("exec", server, "iptables", "-S", "REQUIRE_VPN").stdout
                docker("exec", server, "/etc/require-vpn/firewall.sh")
                self.assertEqual(docker("exec", server, "iptables", "-S", "REQUIRE_VPN").stdout, rules)
                second = docker("exec", server, "/bin/sh", "/bundle/install.sh", check=False)
                self.assertNotEqual(second.returncode, 0)
                self.assertIn("Refusing existing deployment", second.stderr)
                docker("network", "connect", "--ip", "192.0.2.10", network, server)
                docker("exec", server, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
                docker("run", "-d", "--name", client, "--network", network, "--ip", "192.0.2.20",
                       "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                       "--sysctl", "net.ipv6.conf.default.disable_ipv6=0", "-v", str(bundle / "client") + ":/client:ro",
                       "passepartout-ikev2-test", "sleep", "infinity")
                config = """connections {
  test {
    version = 2
    remote_addrs = 192.0.2.10
    vips = 0.0.0.0, ::
    proposals = aes256-sha256-modp2048
    send_cert = always
    encap = yes
    local {
      auth = pubkey
      id = phone@example.test
      certs = device.pem
    }
    remote {
      auth = pubkey
      id = 192.0.2.10
      cacerts = ca.pem
    }
    children {
      internet {
        local_ts = dynamic
        remote_ts = 0.0.0.0/0, ::/0
        esp_proposals = aes256-sha256
      }
    }
  }
}
"""
                # Build the client from the generated enrollment identity, not server keys.
                client_config = Path(directory) / "client.conf"
                client_config.write_text(config)
                docker("cp", str(client_config), client + ":/etc/swanctl/swanctl.conf")
                result = docker("exec", client, "sh", "-ec", """cp /client/ca.pem /etc/swanctl/x509ca/ca.pem
cp /client/device.pem /etc/swanctl/x509/device.pem
cp /client/device-key.pem /etc/swanctl/private/device-key.pem
/usr/sbin/charon-systemd >/tmp/charon.log 2>&1 &
count=0
until test -S /var/run/charon.vici; do count=$((count+1)); test "$count" -lt 50; sleep .1; done
swanctl --load-all >/tmp/load.log 2>&1
swanctl --initiate --child internet --timeout 20
swanctl --list-sas
""")
                self.assertIn("authentication of '192.0.2.10'", result.stdout)
                self.assertIn("ESTABLISHED, IKEv2", result.stdout)
                self.assertIn("INSTALLED, TUNNEL-in-UDP", result.stdout)
                self.assertIn("10.88.0.1/32 fd42:1582:1::1/128", result.stdout)
                self.assertIn("remote 0.0.0.0/0 ::/0", result.stdout)
                # A collector on the server's other network proves IPv4 forwarding
                # and source NAT, rather than only an established control channel.
                echo = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',18080));open('/tmp/echo.ready','w').close();" \
                       "\nwhile True:\n d,p=s.recvfrom(4096);s.sendto(d+b' source='+p[0].encode(),p)"
                docker("run", "-d", "--name", collector, "passepartout-ikev2-test", "python3", "-u", "-c", echo)
                for _ in range(30):
                    if docker("exec", collector, "test", "-f", "/tmp/echo.ready", check=False).returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("IPv4 collector did not start")
                collector_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", collector).stdout.strip()
                server_ip = docker("inspect", "-f", '{{(index .NetworkSettings.Networks "bridge").IPAddress}}', server).stdout.strip()
                probe = """import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(5)
s.bind(('10.88.0.1',0))
s.sendto(b'authenticated-ipv4',(sys.argv[1],18080))
data,_=s.recvfrom(4096)
assert data == b'authenticated-ipv4 source='+sys.argv[2].encode(),data
print('IPv4 forwarded and NAT source verified')
"""
                self.assertIn("NAT source verified", docker("exec", client, "python3", "-c", probe, collector_ip, server_ip).stdout)
                # An IPv6 endpoint on the gateway verifies encrypted IPv6 payload
                # delivery even when Docker's outside network has no IPv6 route.
                docker("exec", server, "ip", "-6", "addr", "add", "fd99:1582::1/128", "dev", "lo")
                echo6 = "import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('fd99:1582::1',18080));open('/tmp/echo6.ready','w').close();" \
                        "\nwhile True:\n d,p=s.recvfrom(4096);s.sendto(d,p)"
                docker("exec", "-d", server, "python3", "-u", "-c", echo6)
                for _ in range(30):
                    if docker("exec", server, "test", "-f", "/tmp/echo6.ready", check=False).returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("IPv6 collector did not start")
                # The Linux fixture needs a route to this synthetic test endpoint;
                # the negotiated XFRM policy carries it over the IPv4 outer tunnel.
                docker("exec", client, "ip", "-6", "route", "replace", "fd99:1582::1/128", "dev", "eth0",
                       "src", "fd42:1582:1::1")
                probe6 = """import socket
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
s.settimeout(5)
s.bind(('fd42:1582:1::1',0))
s.sendto(b'authenticated-ipv6',('fd99:1582::1',18080))
assert s.recv(4096) == b'authenticated-ipv6'
print('IPv6 encrypted payload verified')
"""
                self.assertIn("IPv6 encrypted payload verified", docker("exec", client, "python3", "-c", probe6).stdout)
            finally:
                docker("rm", "-f", collector, client, server, check=False)
                docker("network", "rm", network, check=False)


if __name__ == "__main__":
    unittest.main()
