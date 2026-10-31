"""Shared configuration for sentinel.py, audit.py and firewall.py (single source of truth)."""
import ipaddress
import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "network_monitoring.log")
BAN_LOG = os.path.join(BASE_DIR, "bans.log")

# ==============================================================================
# PERIMETER
# Whitelist accepts IPv4 and IPv6. Also whitelist your DNS resolvers: source IPs
# can be spoofed, so an attacker could otherwise trick the IPS into banning them.
# If you sniff Docker bridges (--iface docker0), container IPs (172.16.0.0/12 by
# default) show up as sources too. Add them to TRUSTED_NETWORKS unless you WANT
# a compromised container to be quarantined (and accept that a scanner you run
# on purpose inside a container will be banned like anyone else).
# ==============================================================================
WHITELIST_IPS = {"192.168.1.5", "192.168.1.86", "192.168.1.254"}
TRUSTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),              # IPv6 "unspecified" (DAD probes)
    ipaddress.ip_network("140.82.112.0/20"),     # GitHub (IPv4)
    ipaddress.ip_network("192.30.252.0/22"),     # GitHub (IPv4)
    # GitHub IPv6 ranges: copy them from https://api.github.com/meta if you need them.
]


def _detect_local_ips():
    """Addresses of this very host (v4 + v6), so we never score/ban ourselves."""
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=2)
    except Exception:
        return set()
    found = set()
    for token in out.split():
        try:
            found.add(str(ipaddress.ip_address(token)))
        except ValueError:
            pass
    return found


LOCAL_IPS = _detect_local_ips()


def _parse_all(addrs):
    parsed = []
    for a in addrs:
        try:
            parsed.append(ipaddress.ip_address(a))
        except ValueError:
            pass
    return parsed


PROTECTED_ADDRS = _parse_all(WHITELIST_IPS | LOCAL_IPS)

# IPv6: a single host controls a whole /64 (2^64 addresses), so scoring and
# banning one /128 is useless. We aggregate by this prefix length.
IPV6_AGGREGATE_PREFIX = 64


def is_trusted(ip_str):
    if ip_str in WHITELIST_IPS or ip_str in LOCAL_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in TRUSTED_NETWORKS if ip.version == net.version)


def source_key(ip_str):
    """Key used for scoring AND as the ban target.

    IPv4 -> the address itself.
    IPv6 -> its /64, unless that /64 contains an address we protect (our own
            LAN prefix!). Banning it would cut off our own machines, so in
            that case we fall back to the single /128.
    """
    ip = ipaddress.ip_address(ip_str)
    if ip.version == 4:
        return str(ip)
    net = ipaddress.ip_network(f"{ip}/{IPV6_AGGREGATE_PREFIX}", strict=False)
    if any(p in net for p in PROTECTED_ADDRS if p.version == 6):
        return str(ip)
    if any(net.overlaps(t) for t in TRUSTED_NETWORKS if t.version == 6):
        return str(ip)
    return str(net)


# ==============================================================================
# DETECTION
# Raw packets/s is NOT a ban signal (a CDN download exceeds it easily). We look
# at probing behaviour: packets that open or poke connections without ACK
# (SYN, NULL, FIN, Xmas...). Three time scales catch three scan speeds:
#   1 s   -> fast scans (nmap -T4/-T5, SYN floods)
#   60 s  -> polite scans (nmap -T2, ~1 probe every 0.4 s)
#   900 s -> stealth scans (nmap -T1, 1 probe every ~15 s)
# ==============================================================================
WINDOW_SECONDS = 1.0
PROBE_LIMIT = 30           # probes from one source in one window
PORT_LIMIT = 15            # distinct dst ports probed in one window
SLOW_WINDOW_SECONDS = 60
SLOW_PORT_LIMIT = 20       # distinct dst ports probed within SLOW_WINDOW_SECONDS
LONG_WINDOW_SECONDS = 900
LONG_PORT_LIMIT = 30       # distinct dst ports probed within LONG_WINDOW_SECONDS

SIGNAL_POINTS = 4.0        # fast signals: points per window while active
SLOW_SIGNAL_POINTS = 2.0   # slow signals: points per window while active
SCORE_THRESHOLD = 10.0     # ban when score reaches this value
SCORE_DECAY_PER_SEC = 0.5  # old suspicion fades; no permanent "strikes"
BAN_SECONDS = 3600         # bans expire natively in the nftables set

# Memory bounds (spoofed-source floods must not exhaust RAM)
MAX_PORTS_TRACKED = 1024   # per source
MAX_TRACKED = 10000        # sources tracked at once

# ==============================================================================
# FIREWALL (nftables). Dedicated table, hooked at PREROUTING / priority raw
# (-300): it runs before conntrack, NAT and every iptables/Docker rule, so one
# rule covers INPUT, FORWARD and Docker published ports at once.
# ==============================================================================
NFT_FAMILY = "inet"
NFT_TABLE = "cognitive_ips"

# ==============================================================================
# LLM (Ollama)
# ==============================================================================
MODEL = "qwen2.5-coder:3b"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_TIMEOUT = 20
LLM_MAX_POINTS = 3.0       # one verdict can never ban a source on its own
SUSPICIOUS_KEYWORDS = (
    "union select", "../", "/etc/passwd", "<script", "cmd.exe", "/bin/sh",
    "nc -e", "wget ", "curl ", "base64", "sqlmap", "nikto", "nmap", "x-forwarded",
)
