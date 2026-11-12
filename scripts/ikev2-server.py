#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
"""Prepare a new private strongSwan bundle; never deploy or install it automatically.

The endpoint must already be assigned to the intended fresh Linux VPN server.
Only the server/ directory is copied to that server. CA and device private keys
remain under private/ and client/. An iOS profile must separately trust ca.pem.
See https://docs.strongswan.org/docs/latest/interop/ios.html .
"""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess


def numeric(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError("Expected a provisioned numeric IP address") from error


def identity(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*@[A-Za-z0-9][A-Za-z0-9.-]*", value):
        raise argparse.ArgumentTypeError("Expected a device email identity")
    return value


def interface(value):
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value):
        raise argparse.ArgumentTypeError("Invalid Linux network interface")
    return value


def write(path, data, mode=0o600):
    with path.open("x", encoding="utf-8", newline="\n") as output:
        output.write(data)
    path.chmod(mode)


def run(openssl, *args):
    subprocess.run([openssl, *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)


def prepare(args):
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl is required")
    output = args.output.resolve()
    # Exclusive directory creation also prevents silently rotating deployed keys.
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    for directory in ("private", "client", "server", "server/swanctl",
                      "server/swanctl/private", "server/swanctl/x509", "server/swanctl/x509ca"):
        (output / directory).mkdir(mode=0o700)
    ca_key = output / "private/ca-key.pem"
    ca = output / "client/ca.pem"
    run(openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", ca_key)
    run(openssl, "req", "-new", "-x509", "-sha256", "-days", "3650", "-key", ca_key,
        "-subj", "/CN=Require VPN Device CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", ca)
    run(openssl, "x509", "-in", ca, "-outform", "DER", "-out", output / "client/ca.der")
    server_key = output / "server/swanctl/private/server-key.pem"
    server_cert = output / "server/swanctl/x509/server.pem"
    client_key = output / "client/device-key.pem"
    client_cert = output / "client/device.pem"
    for name, key, certificate, san, usage in (
        ("server", server_key, server_cert, "IP:" + args.endpoint, "serverAuth"),
        ("device", client_key, client_cert, "email:" + args.client_id, "clientAuth"),
    ):
        request = output / ("private/" + name + ".csr")
        extension = output / ("private/" + name + ".ext")
        write(extension, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
              f"extendedKeyUsage={usage}\nsubjectAltName={san}\n")
        run(openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", key)
        run(openssl, "req", "-new", "-sha256", "-key", key, "-subj", "/CN=Require VPN " + name,
            "-out", request)
        run(openssl, "x509", "-req", "-sha256", "-days", "365", "-in", request,
            "-CA", ca, "-CAkey", ca_key, "-set_serial", str(secrets.randbits(128)),
            "-extfile", extension, "-out", certificate)
    password = output / "client/identity-password.txt"
    write(password, secrets.token_urlsafe(32) + "\n")
    # Apple's documented PKCS#12 interoperability uses the legacy KDF and 3DES.
    run(openssl, "pkcs12", "-export", "-inkey", client_key, "-in", client_cert,
        "-certfile", ca, "-name", "Require VPN device", "-keypbe", "PBE-SHA1-3DES",
        "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1", "-passout", "file:" + str(password),
        "-out", output / "client/identity.p12")
    # This file is private enrollment input, never served or uploaded by this tool.
    write(output / "client/credential.json", json.dumps({
        "Password": password.read_text().strip(),
        "Identity": base64.b64encode((output / "client/identity.p12").read_bytes()).decode("ascii"),
    }) + "\n")
    shutil.copyfile(ca, output / "server/swanctl/x509ca/ca.pem")
    config = f"""connections {{
  require-vpn {{
    version = 2
    local_addrs = %any
    pools = require-vpn-v4, require-vpn-v6
    proposals = aes256-sha256-modp2048
    fragmentation = yes
    mobike = yes
    encap = yes
    send_cert = always
    dpd_delay = 30s
    local {{
      auth = pubkey
      id = {args.endpoint}
      certs = server.pem
    }}
    remote {{
      auth = pubkey
      id = {args.client_id}
      cacerts = ca.pem
    }}
    children {{
      internet {{
        local_ts = 0.0.0.0/0, ::/0
        remote_ts = dynamic
        esp_proposals = aes256-sha256
        reqid = 15821
      }}
    }}
  }}
}}
pools {{
  require-vpn-v4 {{
    addrs = 10.88.0.0/24
    dns = {", ".join(args.dns)}
  }}
  require-vpn-v6 {{
    addrs = fd42:1582:1::/64
  }}
}}
"""
    write(output / "server/swanctl/swanctl.conf", config)
    firewall = f"""#!/bin/sh
set -eu
rule() {{
    tool=$1; table=$2; chain=$3; shift 3
    "$tool" -w -t "$table" -C "$chain" "$@" 2>/dev/null || "$tool" -w -t "$table" -A "$chain" "$@"
}}
for tool in iptables ip6tables; do
    "$tool" -w -t filter -n -L REQUIRE_VPN >/dev/null 2>&1 || "$tool" -w -t filter -N REQUIRE_VPN
    "$tool" -w -t nat -n -L REQUIRE_VPN_NAT >/dev/null 2>&1 || "$tool" -w -t nat -N REQUIRE_VPN_NAT
    if [ "$tool" = iptables ]; then pool=10.88.0.0/24; else pool=fd42:1582:1::/64; fi
    rule "$tool" filter REQUIRE_VPN -s "$pool" -m policy --dir in --pol ipsec --reqid 15821 -j ACCEPT
    rule "$tool" filter REQUIRE_VPN -d "$pool" -m policy --dir out --pol ipsec --reqid 15821 -j ACCEPT
    rule "$tool" filter REQUIRE_VPN -s "$pool" -j DROP
    rule "$tool" filter REQUIRE_VPN -d "$pool" -j DROP
    rule "$tool" nat REQUIRE_VPN_NAT -s "$pool" -o {args.egress_interface} -j MASQUERADE
    rule "$tool" filter FORWARD -j REQUIRE_VPN
    rule "$tool" nat POSTROUTING -j REQUIRE_VPN_NAT
done
"""
    write(output / "server/firewall.sh", firewall, 0o700)
    write(output / "server/forwarding.conf", "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"
          f"net.ipv6.conf.{args.egress_interface}.accept_ra=2\n")
    shutil.copyfile(Path(__file__).with_name("ikev2-server-install.sh"), output / "server/install.sh")
    (output / "server/install.sh").chmod(0o700)
    write(output / "connection.json", json.dumps({
        "endpoint": args.endpoint, "server_id": args.endpoint, "client_id": args.client_id,
        "dns": args.dns, "ipv4_pool": "10.88.0.0/24", "ipv6_pool": "fd42:1582:1::/64",
        "ikev2_port": 500, "nat_t_port": 4500,
        "ipv6_egress": "Requires an IPv6 route on the server; otherwise tunneled IPv6 fails closed",
    }, indent=2) + "\n")
    for path in output.rglob("*"):
        if path.is_file() and path.name not in ("install.sh", "firewall.sh"):
            path.chmod(0o600)
    run(openssl, "verify", "-CAfile", ca, server_cert, client_cert)
    print("Saved: " + str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", type=numeric, required=True)
    parser.add_argument("--client-id", type=identity, required=True)
    parser.add_argument("--dns", type=numeric, action="append", required=True)
    parser.add_argument("--egress-interface", type=interface, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    previous_umask = os.umask(0o077)
    try:
        prepare(args)
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    main()
