#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

"""Temporarily deliver a local-enrollment identity asset over trusted HTTPS.

The iPhone must already trust the TLS certificate. This does not enroll a device
or install a VPN. Authentication.Type=None in Apple's local asset declaration
does not authenticate HTTP requests, so this server requires a secret capability
path, expires quickly, limits downloads, and never logs request URLs or secrets.
Use the generated URL only in the privately delivered enrollment profile.
"""

import argparse
import base64
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
from urllib.parse import urlsplit


def private_file(path):
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"A private file (mode 0600 or stricter) is required: {path}")
    return path.read_bytes()


def read_asset(path):
    data = private_file(path)
    value = json.loads(data)
    if not isinstance(value, dict) or not isinstance(value.get("Password"), str):
        raise ValueError("Identity asset requires a Password string")
    identity = value.get("Identity")
    if not isinstance(identity, str) or not base64.b64decode(identity, validate=True):
        raise ValueError("Identity asset requires base64 PKCS#12 data")
    return data


def write_url(path, url):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(url + "\n")


def server_for(address, port, context, asset, token, expires_after, downloads):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            expected = "/credential/" + token
            valid_path = hmac.compare_digest(self.path.encode("utf-8"), expected.encode("ascii"))
            if time.monotonic() >= self.server.expires_at:
                self.send_error(410)
                return
            if not valid_path:
                self.send_error(404)
                return
            if self.server.remaining <= 0:
                self.send_error(410)
                return
            self.server.remaining -= 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(asset)))
            self.send_header("Cache-Control", "no-store, private")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(asset)

    class Server(HTTPServer):
        allow_reuse_address = True

        def get_request(self):
            connection, peer = super().get_request()
            connection.settimeout(2)
            try:
                return context.wrap_socket(connection, server_side=True), peer
            except Exception:
                connection.close()
                raise

    if ipaddress.ip_address(address).version == 6:
        import socket
        Server.address_family = socket.AF_INET6
    server = Server((address, port), Handler)
    # Bound both TLS handshake and request reads so a stalled peer cannot hold
    # the bootstrap server indefinitely.
    server.timeout = 0.25
    server.remaining = downloads
    server.expires_at = time.monotonic() + expires_after
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", type=ipaddress.ip_address)
    parser.add_argument("--port", default=8443, type=int)
    parser.add_argument("--origin", required=True, help="HTTPS origin reachable and trusted by the iPhone")
    parser.add_argument("--asset", required=True, type=Path)
    parser.add_argument("--tls-certificate", required=True, type=Path)
    parser.add_argument("--tls-key", required=True, type=Path)
    parser.add_argument("--url-file", required=True, type=Path, help="New private file receiving the secret URL")
    parser.add_argument("--token-file", type=Path, help="Existing private token file, otherwise generate a new token")
    parser.add_argument("--expires-after", type=int, default=300)
    parser.add_argument("--max-downloads", type=int, default=3)
    args = parser.parse_args()
    origin = urlsplit(args.origin)
    try:
        valid_port = origin.port is None or 1 <= origin.port <= 65535
        if (origin.scheme != "https" or not origin.hostname or not origin.hostname.isascii()
                or origin.path not in ("", "/") or origin.query or origin.fragment
                or origin.username or origin.password or not valid_port):
            raise ValueError("origin must be a trusted HTTPS origin without a path or credentials")
        if not 0 <= args.port <= 65535 or not 1 <= args.expires_after <= 900 or not 1 <= args.max_downloads <= 5:
            raise ValueError("Port, expiration (1-900 seconds), or download limit (1-5) is invalid")
        asset = read_asset(args.asset)
        private_file(args.tls_key)
        token = private_file(args.token_file).decode("ascii").strip() if args.token_file else secrets.token_urlsafe(32)
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
            raise ValueError("Token must contain at least 43 URL-safe random characters")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_certificate, args.tls_key)
        with server_for(str(args.bind), args.port, context, asset, token, args.expires_after, args.max_downloads) as server:
            write_url(args.url_file, args.origin.rstrip("/") + "/credential/" + token)
            print("Saved: " + str(args.url_file.resolve()), flush=True)
            print("HTTPS bootstrap ready; URLs and identity contents are not logged", flush=True)
            while time.monotonic() < server.expires_at:
                server.handle_request()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
