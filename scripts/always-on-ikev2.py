#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Davide De Rosa
# SPDX-License-Identifier: GPL-3.0

"""Generate a separate iOS 27 Always-On IKEv2 declaration or local profile.

Requires a provisioned IKEv2 server and certificate identity asset. A local
profile may be installed manually without MDM enrollment. User enrollment and
ordinary app installation cannot apply this declaration. Nothing is installed
by this script, and this does not configure Passepartout's tunnel.
Schema: https://developer.apple.com/documentation/devicemanagement/networkvpnalwayson
"""

import argparse
import base64
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
from urllib.parse import urlsplit
import uuid


def nonempty(value):
    if not value.strip() or any(ord(char) < 32 for char in value):
        raise argparse.ArgumentTypeError("Expected a nonempty value without control characters")
    return value


def declaration(args):
    return {
        "Type": "com.apple.configuration.network.vpn.always-on",
        "Identifier": args.identifier,
        "ServerToken": args.server_token,
        "Payload": {
            "VisibleName": args.name,
            "UIToggleEnabled": False,
            "AllowAllCaptiveNetworkPlugins": False,
            "AllowCaptiveWebSheet": False,
            "AllowedCaptiveNetworkPlugins": [],
            "ApplicationExceptions": [],
            "ServiceExceptions": [],
            "TunnelConfigurations": [{
                "ProtocolType": "IKEv2",
                "Interfaces": ["Cellular", "WiFi"],
                "IKEV2": {
                    "HostName": args.server,
                    "LocalIdentifier": args.local_identifier,
                    "RemoteIdentifier": args.remote_identifier,
                    "Authentication": {
                        "Method": "Certificate",
                        "IdentityAssetReference": args.identity_asset,
                    },
                },
            }],
        },
    }


def identity_asset(path, expected_identifier):
    asset = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(asset, dict) or asset.get("Type") != "com.apple.asset.credential.identity":
        raise ValueError("identity-asset-file must contain a com.apple.asset.credential.identity declaration")
    if asset.get("Identifier") != expected_identifier:
        raise ValueError("identity-asset-file Identifier must match --identity-asset")
    token = asset.get("ServerToken")
    if not isinstance(token, str) or not token.strip() or any(ord(char) < 32 for char in token):
        raise ValueError("identity asset requires a nonempty ServerToken")
    payload = asset.get("Payload")
    if not isinstance(payload, dict):
        raise ValueError("identity asset requires a Payload dictionary")
    # The absent/default MDM authentication cannot fetch assets for a local profile.
    if payload.get("Authentication") != {"Type": "None"}:
        raise ValueError("local identity asset must explicitly set Authentication.Type to None")
    reference = payload.get("Reference")
    if not isinstance(reference, dict) or not isinstance(reference.get("DataURL"), str):
        raise ValueError("identity asset requires Reference.DataURL")
    if any(ord(char) < 33 for char in reference["DataURL"]):
        raise ValueError("identity asset DataURL must not contain whitespace or control characters")
    url = urlsplit(reference["DataURL"])
    try:
        valid_port = url.port is None or 1 <= url.port <= 65535
    except ValueError:
        valid_port = False
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.fragment or not valid_port):
        raise ValueError("identity asset DataURL must be HTTPS without credentials or a fragment")
    if reference.get("ContentType", "application/json") != "application/json":
        raise ValueError("identity asset ContentType must be application/json")
    if "Hash-SHA-256" in reference and not re.fullmatch(r"[0-9a-fA-F]{64}", str(reference["Hash-SHA-256"])):
        raise ValueError("identity asset Hash-SHA-256 must be 64 hexadecimal characters")
    if "Size" in reference and (type(reference["Size"]) is not int or reference["Size"] <= 0):
        raise ValueError("identity asset Size must be a positive integer when specified")
    if payload.get("Accessible", "Default") not in ("Default", "AfterFirstUnlock"):
        raise ValueError("identity asset Accessible must be Default or AfterFirstUnlock")
    return asset


def server_ca_certificate(path):
    data = path.read_bytes()
    if b"-----BEGIN" in data:
        certificate = re.fullmatch(
            rb"\s*-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*", data)
        if certificate is None:
            raise ValueError("server CA input must contain exactly one PEM certificate and no private key")
        data = base64.b64decode(re.sub(rb"\s+", b"", certificate[1]), validate=True)
    openssl = shutil.which("openssl")
    if openssl is None:
        raise ValueError("OpenSSL is required to validate a supplied server CA certificate")
    result = subprocess.run([openssl, "x509", "-inform", "DER", "-noout", "-text"],
                            input=data, capture_output=True, timeout=10)
    if result.returncode != 0 or not re.search(
            rb"X509v3 Basic Constraints:[^\n]*\n\s+CA:TRUE(?:,|[\s\r\n])", result.stdout):
        raise ValueError("server CA input must be an X.509 CA certificate with CA:TRUE")
    return data


def local_profile(args, asset, server_ca=None):
    vpn = declaration(args)
    activation_identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, args.identifier + "/activation"))
    if asset["Identifier"] in (vpn["Identifier"], activation_identifier):
        raise ValueError("VPN, activation and identity asset identifiers must be distinct")
    activation = {
        "Type": "com.apple.activation.simple",
        "Identifier": activation_identifier,
        "ServerToken": args.server_token,
        "Payload": {"StandardConfigurations": [vpn["Identifier"]]},
    }
    profile_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, args.identifier + "/profile"))
    declarations_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, args.identifier + "/declarations"))
    profile_identifier = "io.partout.require-vpn." + profile_uuid
    # plistlib serializes bytes as plist <data>, as required by com.apple.declarations.
    # No asset data or private key is fetched or embedded by this generator.
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadUUID": profile_uuid,
        "PayloadIdentifier": profile_identifier,
        "PayloadDisplayName": args.name,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [{
            "PayloadType": "com.apple.declarations",
            "PayloadVersion": 1,
            "PayloadUUID": declarations_uuid,
            "PayloadIdentifier": profile_identifier + ".declarations",
            "PayloadDisplayName": args.name,
            "Declarations": [json.dumps(item).encode("utf-8") for item in (vpn, asset, activation)],
        }],
    }
    if server_ca is not None:
        # Payload order does not prove CA trust is ready before the asset fetch.
        # Private-CA bootstrap/trust sequencing needs explicit device validation.
        profile["PayloadContent"].insert(0, {
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, args.identifier + "/server-ca")),
            "PayloadIdentifier": profile_identifier + ".server-ca",
            "PayloadDisplayName": args.name + " server CA",
            "PayloadCertificateFileName": "server-ca.cer",
            "PayloadContent": server_ca,
        })
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=nonempty)
    parser.add_argument("--local-identifier", required=True, type=nonempty)
    parser.add_argument("--remote-identifier", required=True, type=nonempty)
    parser.add_argument("--identity-asset", required=True, type=nonempty,
                        help="Identifier of the separately deployed identity asset declaration")
    parser.add_argument("--name", default="Always-On VPN", type=nonempty)
    parser.add_argument("--identifier", default=str(uuid.uuid4()), type=nonempty,
                        help="Reuse this identifier when updating an existing declaration")
    parser.add_argument("--server-token", default=str(uuid.uuid4()), type=nonempty)
    parser.add_argument("--format", choices=("json", "mobileconfig"), default="json",
                        help="JSON declaration or manually installable local declaration profile")
    parser.add_argument("--identity-asset-file", type=Path,
                        help="Existing identity asset JSON; required for mobileconfig")
    parser.add_argument("--local-asset-delivery", choices=("private-https",),
                        help="Confirm identity URL uses private, temporary HTTPS bootstrap delivery; "
                             "the delivery service must enforce URL secrecy, access and expiry")
    parser.add_argument("--server-ca-certificate", type=Path,
                        help="Optional PEM/DER server CA for the local profile; manual trust and "
                             "bootstrap ordering still require device validation")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.format == "mobileconfig" and args.identity_asset_file is None:
        parser.error("mobileconfig requires --identity-asset-file")
    if args.format == "mobileconfig" and args.local_asset_delivery is None:
        parser.error("mobileconfig requires --local-asset-delivery private-https")
    if args.format == "json" and args.identity_asset_file is not None:
        parser.error("identity-asset-file is only used with --format mobileconfig")
    if args.format == "json" and (args.local_asset_delivery is not None or args.server_ca_certificate is not None):
        parser.error("local asset delivery and server CA options require --format mobileconfig")
    profile = None
    if args.format == "mobileconfig":
        try:
            asset = identity_asset(args.identity_asset_file, args.identity_asset)
            ca = server_ca_certificate(args.server_ca_certificate) if args.server_ca_certificate else None
            profile = local_profile(args, asset, ca)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            parser.error(str(error))
    # Exclusive creation avoids silently replacing a deployment configuration.
    if profile is not None:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            plistlib.dump(profile, output, fmt=plistlib.FMT_XML)
    else:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(declaration(args), output, indent=2)
            output.write("\n")
    print("Saved: " + str(args.output.resolve()))


if __name__ == "__main__":
    main()
