#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Davide De Rosa
# SPDX-License-Identifier: GPL-3.0

"""Generate a separate iOS 27 device-management declaration, never install it.

Requires a provisioned IKEv2 server, certificate identity asset, and supervised,
device, or local enrollment. User enrollment and ordinary app installation
cannot apply this declaration. This does not configure Passepartout's tunnel.
Schema: https://developer.apple.com/documentation/devicemanagement/networkvpnalwayson
"""

import argparse
import json
from pathlib import Path
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
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    # Exclusive creation avoids silently replacing a deployment configuration.
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(declaration(args), output, indent=2)
        output.write("\n")
    print("Saved: " + str(args.output.resolve()))


if __name__ == "__main__":
    main()
