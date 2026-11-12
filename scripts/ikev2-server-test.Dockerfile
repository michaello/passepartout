FROM debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    charon-systemd strongswan-swanctl libcharon-extra-plugins libstrongswan-standard-plugins \
    iproute2 iptables nftables openssl python3 systemd systemd-sysv procps \
    && rm -rf /var/lib/apt/lists/*
