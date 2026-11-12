#!/usr/bin/env python3
"""Controlled probes and an external collector. Client success alone is not leak evidence."""

import argparse
import datetime
import ipaddress
import json
import math
import os
import platform
import shutil
import socket
import socketserver
import struct
import subprocess
import threading
import time
import urllib.parse
import uuid

MAGIC = "passepartout-require-vpn-v1"
MAX_PACKET = 16384


def numeric(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError("A provisioned numeric IP address is required") from error


def family(address):
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def os_build():
    result = {"platform": platform.platform(), "release": platform.release()}
    if platform.system() == "Darwin":
        result["product_version"] = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], text=True).strip()
        result["build"] = subprocess.check_output(["/usr/bin/sw_vers", "-buildVersion"], text=True).strip()
    else:
        result["build"] = platform.version()
    return result


class Journal:
    def __init__(self, path):
        self.file = open(path, "x", buffering=1) if path else None
        self.lock = threading.Lock()

    def record(self, event, **fields):
        row = {"event": event, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "monotonic_ns": time.monotonic_ns(), **fields}
        with self.lock:
            print(json.dumps(row, sort_keys=True), file=self.file, flush=True)

    def close(self):
        if self.file:
            self.file.close()


def receive_probe(data, source, transport, journal):
    try:
        probe = json.loads(data)
        if (not isinstance(probe, dict) or probe.get("magic") != MAGIC
                or not isinstance(probe.get("sequence"), int)
                or probe.get("mode") not in {"persistent_tcp", "new_tcp", "persistent_udp", "new_udp"}):
            raise ValueError("Invalid probe")
        uuid.UUID(probe["run_id"])
        uuid.UUID(probe["session_id"])
    except (ValueError, TypeError, KeyError, UnicodeError):
        journal.record("rejected", source=list(source), transport=transport)
        return None
    journal.record("observed", source=list(source), transport=transport, probe=probe)
    return (json.dumps({"ack": probe["sequence"], "run_id": probe["run_id"]}) + "\n").encode()


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            try:
                packet = self.rfile.readline(MAX_PACKET + 1)
                if not packet or len(packet) > MAX_PACKET or not packet.endswith(b"\n"):
                    return
                ack = receive_probe(packet, self.client_address, "tcp", self.server.journal)
                if ack:
                    self.wfile.write(ack)
                    self.wfile.flush()
            except (OSError, ValueError):
                return


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        if len(data) > MAX_PACKET:
            return
        ack = receive_probe(data, self.client_address, "udp", self.server.journal)
        if ack:
            connection.sendto(ack, self.client_address)


def collect(args, journal, stop):
    servers = []
    port = args.port
    try:
        for address in args.bind:
            for base, handler in [(socketserver.ThreadingTCPServer, TCPHandler),
                                  (socketserver.UDPServer, UDPHandler)]:
                class Server(base):
                    address_family = family(address)
                    daemon_threads = True
                    allow_reuse_address = True

                    def server_bind(self):
                        if self.address_family == socket.AF_INET6:
                            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        super().server_bind()

                server = Server((address, port), handler)
                port = server.server_address[1]
                server.journal = journal
                servers.append(server)
                threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        journal.record("ready", addresses=args.bind, port=port,
                       evidence="Compare observed source addresses with known VPN and physical egress addresses")
        stop.wait(args.duration or None)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def probe_worker(args, journal, stop, target, mode):
    persistent = mode.startswith("persistent")
    tcp = mode.endswith("tcp")
    connection = reader = None
    sequence = 0
    session = None
    try:
        while not stop.is_set():
            sequence += 1
            try:
                if connection is None:
                    connection = socket.socket(family(target), socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
                    connection.settimeout(args.timeout)
                    connection.connect((target, args.port))
                    session = str(uuid.uuid4())
                    if tcp:
                        reader = connection.makefile("rb")
                probe = {"magic": MAGIC, "run_id": args.run_id, "sequence": sequence,
                         "mode": mode, "session_id": session, "target": target,
                         "sent_monotonic_ns": time.monotonic_ns()}
                packet = (json.dumps(probe) + "\n").encode()
                if tcp:
                    connection.sendall(packet)
                    response = reader.readline(MAX_PACKET)
                else:
                    connection.send(packet)
                    response = connection.recv(MAX_PACKET)
                ack = json.loads(response)
                if ack.get("run_id") != args.run_id or ack.get("ack") != sequence:
                    raise ValueError("Invalid acknowledgment")
                journal.record("acknowledged", probe=probe, local=list(connection.getsockname()))
            except (OSError, ValueError) as error:
                journal.record("probe_failed", run_id=args.run_id, target=target, mode=mode,
                               sequence=sequence, session_id=session, error=str(error))
                if reader:
                    reader.close()
                    reader = None
                if connection:
                    connection.close()
                    connection = None
            finally:
                if not persistent:
                    if reader:
                        reader.close()
                        reader = None
                    if connection:
                        connection.close()
                        connection = None
            stop.wait(args.interval)
    finally:
        if reader:
            reader.close()
        if connection:
            connection.close()


def dns_worker(args, journal, stop, target):
    sequence = 0
    while not stop.is_set():
        sequence += 1
        name = f"{sequence}.{args.run_id.replace('-', '')}.{args.dns_name.rstrip('.')}"
        query_id = int.from_bytes(os.urandom(2), "big")
        question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
        packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
        try:
            with socket.socket(family(target), socket.SOCK_DGRAM) as connection:
                connection.settimeout(args.timeout)
                connection.connect((target, args.dns_port))
                connection.send(packet)
                response = connection.recv(65535)
                if len(response) < 12:
                    raise ValueError("Truncated DNS response")
                response_id, flags = struct.unpack("!HH", response[:4])
                if response_id != query_id or not flags & 0x8000:
                    raise ValueError("Mismatched DNS response")
                journal.record("dns_response", run_id=args.run_id, target=target, sequence=sequence,
                               query=name, query_type="A", rcode=flags & 15, bytes=len(response))
        except (OSError, ValueError) as error:
            journal.record("dns_failed", run_id=args.run_id, target=target, sequence=sequence, query=name, error=str(error))
        stop.wait(args.interval)


def quic_capability():
    curl = shutil.which("curl")
    if not curl:
        return None, "curl unavailable"
    try:
        result = subprocess.run([curl, "--disable", "--version"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"curl capability check failed: {error}"
    features = next((line.split(":", 1)[1].split() for line in result.stdout.splitlines()
                     if line.startswith("Features:")), [])
    if result.returncode != 0 or "HTTP3" not in features:
        return None, "curl lacks HTTP3; no TCP fallback attempted"
    return curl, result.stdout.splitlines()[0]


def quic_worker(args, journal, stop, curl):
    sequence = 0
    url = urllib.parse.urlsplit(args.quic_url)
    port = url.port or 443
    address = f"[{args.quic_target}]" if family(args.quic_target) == socket.AF_INET6 else args.quic_target
    while not stop.is_set():
        sequence += 1
        query = urllib.parse.parse_qsl(url.query) + [("require_vpn_run", args.run_id), ("require_vpn_seq", str(sequence))]
        request_url = url._replace(query=urllib.parse.urlencode(query)).geturl()
        try:
            result = subprocess.run([curl, "--disable", "--http3-only", "--noproxy", "*", "--resolve",
                                     f"{url.hostname}:{port}:{address}", "--max-time", str(args.timeout),
                                     "--silent", "--show-error", "--output", os.devnull,
                                     "--write-out", "%{remote_ip} %{http_code}", request_url],
                                    capture_output=True, text=True, timeout=args.timeout + 1)
            journal.record("quic_result", run_id=args.run_id, target=args.quic_target, sequence=sequence,
                           returncode=result.returncode, result=result.stdout, error=result.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            journal.record("quic_failed", run_id=args.run_id, sequence=sequence, error=str(error))
        stop.wait(args.interval)


def send(args, journal, stop):
    threads = []
    for target in args.target:
        for mode in ("persistent_tcp", "new_tcp", "persistent_udp", "new_udp"):
            threads.append(threading.Thread(target=probe_worker, args=(args, journal, stop, target, mode), daemon=True))
    for target in args.dns_server:
        threads.append(threading.Thread(target=dns_worker, args=(args, journal, stop, target), daemon=True))
    if args.quic_url:
        curl, detail = quic_capability()
        journal.record("quic_capability", available=curl is not None, detail=detail, persistent_sessions=False)
        if curl:
            threads.append(threading.Thread(target=quic_worker, args=(args, journal, stop, curl), daemon=True))
    for thread in threads:
        thread.start()
    try:
        stop.wait(args.duration or None)
    finally:
        stop.set()
        for thread in threads:
            thread.join(args.timeout + 2)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("collect", "send"):
        sub = commands.add_parser(command)
        sub.add_argument("--port", type=int, default=45000, help="TCP and UDP collector port")
        sub.add_argument("--duration", type=float, default=60, help="Seconds, or 0 for continuous operation")
        sub.add_argument("--output", help="New JSONL file; existing files are never overwritten")
        if command == "collect":
            sub.add_argument("--bind", type=numeric, action="append", required=True)
        else:
            sub.add_argument("--target", type=numeric, action="append", default=[])
            sub.add_argument("--run-id", default=str(uuid.uuid4()))
            sub.add_argument("--interval", type=float, default=0.5)
            sub.add_argument("--timeout", type=float, default=2)
            sub.add_argument("--dns-server", type=numeric, action="append", default=[])
            sub.add_argument("--dns-port", type=int, default=53)
            sub.add_argument("--dns-name", default="require-vpn.invalid")
            sub.add_argument("--quic-url", help="Controlled HTTPS endpoint; requests use new QUIC sessions")
            sub.add_argument("--quic-target", type=numeric)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535 or not math.isfinite(args.duration) or args.duration < 0:
        parser.error("Invalid port or duration")
    if args.command == "send":
        try:
            args.run_id = str(uuid.UUID(args.run_id))
        except ValueError:
            parser.error("run-id must be a UUID")
        if (args.port == 0 or not math.isfinite(args.timeout) or not math.isfinite(args.interval)
                or args.timeout <= 0 or args.interval <= 0 or not 1 <= args.dns_port <= 65535):
            parser.error("Send requires a positive port, timeout, and interval")
        labels = args.dns_name.rstrip(".").split(".")
        if (not labels or any(not label.isascii() or not 1 <= len(label) <= 63
                              or any(not (character.isalnum() or character == "-") for character in label)
                              for label in labels) or len(args.dns_name) > 180):
            parser.error("Invalid DNS probe suffix")
        if bool(args.quic_url) != bool(args.quic_target):
            parser.error("quic-url and numeric quic-target are required together")
        if args.quic_url:
            url = urllib.parse.urlsplit(args.quic_url)
            try:
                valid_port = url.port is None or 1 <= url.port <= 65535
            except ValueError:
                valid_port = False
            if (url.scheme != "https" or not url.hostname or not url.hostname.isascii()
                    or url.username or url.password or url.fragment or not valid_port):
                parser.error("quic-url must be an HTTPS URL without credentials or fragment")
        if not args.target and not args.dns_server and not args.quic_url:
            parser.error("At least one numeric target, DNS server, or QUIC endpoint is required")
    return args


def main(argv=None):
    args = parse_args(argv)
    journal = Journal(args.output)
    stop = threading.Event()
    journal.record("metadata", command=args.command, os=os_build(),
                   run_id=getattr(args, "run_id", None),
                   evidence="Client acknowledgments do not prove absence of leaks; compare external collector and capture records")
    try:
        (collect if args.command == "collect" else send)(args, journal, stop)
    except KeyboardInterrupt:
        stop.set()
    finally:
        journal.record("stopped")
        journal.close()


if __name__ == "__main__":
    main()
