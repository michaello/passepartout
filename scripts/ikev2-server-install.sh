#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# Run as root on a fresh Debian 12/Ubuntu host after copying only server/ there.
# Does not change cloud firewall rules. UDP 500 and 4500 must be reachable.
set -eu
[ "$(id -u)" = 0 ] || { echo "Root is required" >&2; exit 1; }
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
command -v apt-get >/dev/null || { echo "A Debian/Ubuntu host is required" >&2; exit 1; }
[ -d /run/systemd/system ] || { echo "An active systemd host is required" >&2; exit 1; }
for path in /etc/require-vpn /etc/systemd/system/require-vpn-network.service /etc/sysctl.d/90-require-vpn.conf; do
    [ ! -e "$path" ] || { echo "Refusing existing deployment: $path" >&2; exit 1; }
done
if command -v nft >/dev/null && [ -n "$(nft list ruleset)" ]; then
    echo "Refusing a host with existing nftables rules" >&2
    exit 1
fi
for tool in iptables-save ip6tables-save; do
    if command -v "$tool" >/dev/null; then
        if "$tool" | awk '/^:/ && $2 != "ACCEPT" { found=1 } /^-A/ { found=1 } END { exit !found }'; then
            echo "Refusing a host with existing firewall rules or restrictive policies" >&2
            exit 1
        fi
    fi
done
for path in /etc/swanctl/conf.d /etc/swanctl/private /etc/swanctl/x509 /etc/swanctl/x509ca; do
    [ ! -d "$path" ] || [ -z "$(ls -A "$path")" ] || {
        echo "Refusing existing VPN credentials/configuration: $path" >&2; exit 1;
    }
done
[ ! -f /etc/swanctl/swanctl.conf ] || [ -z "$(sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d;/^[[:space:]]*include conf.d\/\*.conf[[:space:]]*$/d' /etc/swanctl/swanctl.conf)" ] || {
    echo "Refusing an existing root swanctl configuration" >&2; exit 1;
}
[ ! -e /etc/ipsec.conf ] || { echo "Refusing an existing legacy IPsec configuration" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends charon-systemd strongswan-swanctl libcharon-extra-plugins libstrongswan-standard-plugins iptables procps
install -d -m 700 /etc/require-vpn
install -m 700 "$bundle/firewall.sh" /etc/require-vpn/firewall.sh
install -m 600 "$bundle/forwarding.conf" /etc/sysctl.d/90-require-vpn.conf
for directory in private x509 x509ca; do
    install -d -m 700 "/etc/swanctl/$directory"
    for file in "$bundle/swanctl/$directory/"*; do
        install -m 600 "$file" "/etc/swanctl/$directory/$(basename "$file")"
    done
done
install -d -m 700 /etc/swanctl/conf.d
install -m 600 "$bundle/swanctl/swanctl.conf" /etc/swanctl/conf.d/require-vpn.conf
cat > /etc/systemd/system/require-vpn-network.service <<'UNIT'
[Unit]
Description=Require VPN gateway forwarding and NAT
After=network-pre.target
Before=strongswan.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/sysctl --system
ExecStart=/etc/require-vpn/firewall.sh

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now require-vpn-network.service
systemctl enable --now strongswan.service
swanctl --load-all
swanctl --list-conns
iptables -S REQUIRE_VPN
ip6tables -S REQUIRE_VPN
echo "Gateway configuration loaded; verify public reachability and an iPhone tunnel before relying on it"
