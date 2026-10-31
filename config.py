"""Shared configuration for sentinel.py and audit.py (single source of truth)."""
import ipaddress
import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "network_monitoring.log")
BAN_LOG = os.path.join(BASE_DIR, "bans.log")

# ==============================================================================
# PERIMETER
# Tip: also whitelist your DNS resolver. Source IPs can be spoofed, so an
# attacker could otherwise trick the IPS into banning it (self-inflicted DoS).
# ==============================================================================
WHITELIST_IPS = {"192.168.1.5", "192.168.1.86", "192.168.1.254"}
TRUSTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("140.82.112.0/20"),  # GitHub
    ipaddress.ip_network("192.30.252.0/22"),  # GitHub
]


def _detect_local_ips():
    """IPs of this very host, so we never score/ban ourselves."""
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=2)
        return set(out.split())
    except Exception:
        return set()


LOCAL_IPS = _detect_local_ips()


def is_trusted(ip_str):
    if ip_str in WHITELIST_IPS or ip_str in LOCAL_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in TRUSTED_NETWORKS if ip.version == net.version)


# ==============================================================================
# DETECTION
# Raw packets/s is NOT used as a ban signal: a normal download from a CDN easily
# exceeds hundreds of packets/s. We look at behaviour instead (SYN rate, port
# spread) and let the LLM only add bounded evidence on top.
# ==============================================================================
WINDOW_SECONDS = 1.0
SYN_LIMIT = 30            # bare SYNs from one IP in one window
PORT_LIMIT = 15           # distinct destination ports from one IP in one window
SIGNAL_POINTS = 4.0       # points added per triggered signal per window
SCORE_THRESHOLD = 10.0    # ban when score reaches this value
SCORE_DECAY_PER_SEC = 0.5 # old suspicion fades; no permanent "strikes"
BAN_SECONDS = 3600        # bans expire (an IPS must be able to recover from mistakes)

# ==============================================================================
# LLM (Ollama)
# ==============================================================================
MODEL = "qwen2.5-coder:3b"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_TIMEOUT = 20
LLM_MAX_POINTS = 3.0      # one verdict can never ban an IP on its own
SUSPICIOUS_KEYWORDS = (
    "union select", "../", "/etc/passwd", "<script", "cmd.exe", "/bin/sh",
    "nc -e", "wget ", "curl ", "base64", "sqlmap", "nikto", "nmap", "x-forwarded",
)
