"""sentinel.py - capture layer. Sniffs IPv4 traffic and writes one line per packet.

Line format (parsed by audit.py):
SRC: <ip> | DPORT: <port|-> | FLAGS: <tcp flags|-> | SIZE: <n>B | PAYLOAD: <text>
"""
import ipaddress
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from scapy.all import IP, TCP, UDP, sniff

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
    """Filter in the kernel (BPF) instead of in Python: far cheaper per packet."""
    hosts = [ip for ip in (config.WHITELIST_IPS | config.LOCAL_IPS)
             if ipaddress.ip_address(ip).version == 4]
    nets = [str(n) for n in config.TRUSTED_NETWORKS if n.version == 4]
    excluded = [f"src host {h}" for h in sorted(hosts)] + [f"src net {n}" for n in nets]
    if not excluded:
        return "ip"
    return "ip and not (" + " or ".join(excluded) + ")"


def packet_callback(packet):
    if IP not in packet:
        return
    ip = packet[IP].src
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
    if os.geteuid() != 0:
        sys.exit("[!] sentinel needs root to capture packets (sudo python3 sentinel.py)")
    setup_logger()
    bpf = build_bpf()
    print("[*] Sentinel running...")
    print(f"[*] BPF filter: {bpf}")
    try:
        sniff(filter=bpf, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sentinel stopped by operator.")


if __name__ == "__main__":
    main()
