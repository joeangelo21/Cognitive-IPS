"""sentinel.py - capture layer. Sniffs IPv4 and IPv6 traffic, one log line per packet.

Line format (parsed by audit.py):
SRC: <ip> | DPORT: <port|-> | FLAGS: <tcp flags|-> | SIZE: <n>B | PAYLOAD: <text>

Usage:
    sudo python3 sentinel.py                      # default interface
    sudo python3 sentinel.py --iface eth0 --iface docker0
"""
import argparse
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from scapy.all import IP, TCP, UDP, IPv6, sniff

import config

logger = logging.getLogger("sentinel")
logger.setLevel(logging.INFO)
logger.propagate = False


def setup_logger():
    # One open handle + rotation, instead of open()/close() per packet.
    handler = RotatingFileHandler(config.LOG_FILE, maxBytes=5_000_000, backupCount=2)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def build_bpf():
    """Filter in the kernel (BPF) instead of in Python: far cheaper per packet.
    Works for IPv4 and IPv6 hosts/networks alike."""
    hosts = sorted(config.WHITELIST_IPS | config.LOCAL_IPS)
    nets = [str(n) for n in config.TRUSTED_NETWORKS]
    excluded = [f"src host {h}" for h in hosts] + [f"src net {n}" for n in nets]
    base = "(ip or ip6)"
    if not excluded:
        return base
    return f"{base} and not (" + " or ".join(excluded) + ")"


def packet_callback(packet):
    if IP in packet:
        ip = packet[IP].src
    elif IPv6 in packet:
        ip = packet[IPv6].src
    else:
        return
    if config.is_trusted(ip):  # defense in depth (BPF already filters)
        return

    dport, flags, payload = "-", "-", packet.summary()
    if TCP in packet:
        tcp = packet[TCP]
        dport = tcp.dport
        flags = str(tcp.flags) or "NULL"  # NULL scans have no flags at all
        raw = bytes(tcp.payload)
        if raw:
            payload = repr(raw[:100])
    elif UDP in packet:
        dport = packet[UDP].dport

    # Payload is attacker-controlled: keep it on a single line.
    payload = payload.replace("\r", " ").replace("\n", " ")
    logger.info(f"SRC: {ip} | DPORT: {dport} | FLAGS: {flags} | "
                f"SIZE: {len(packet)}B | PAYLOAD: {payload}")


def main():
    ap = argparse.ArgumentParser(description="Cognitive-IPS packet capture")
    ap.add_argument("--iface", action="append", default=None,
                    help="interface to sniff (repeatable). Default: scapy's default route "
                         "interface. Add docker0/br-* to also see container traffic.")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] sentinel needs root to capture packets (sudo python3 sentinel.py)")
    if not config.LOCAL_IPS:
        print("[!] Could not detect this host's own IPs ('hostname -I' failed). "
              "Outgoing traffic may be scored as if it were an attacker; add your "
              "IPs to WHITELIST_IPS in config.py.")
    setup_logger()
    bpf = build_bpf()
    print("[*] Sentinel running (IPv4 + IPv6)...")
    print(f"[*] Interfaces: {args.iface or 'default'}")
    print(f"[*] BPF filter: {bpf}")
    try:
        sniff(filter=bpf, prn=packet_callback, store=False, iface=args.iface)
    except KeyboardInterrupt:
        print("\n[*] Sentinel stopped by operator.")


if __name__ == "__main__":
    main()
