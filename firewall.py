"""firewall.py - nftables backend.

One dedicated table with two sets (IPv4 / IPv6) whose elements carry a native
timeout: the kernel removes expired bans by itself, so bans survive a restart
of audit.py and nothing needs to be "unbanned" by Python.

The chain hooks PREROUTING at priority -300 (raw): packets from a banned source
are dropped before conntrack, NAT, and any iptables/Docker rule, which covers
INPUT, FORWARD (containers) and Docker published ports with a single rule.
"""
import ipaddress
import json
import shutil
import subprocess

import config

FAMILY, TABLE = config.NFT_FAMILY, config.NFT_TABLE
SETS = {4: "blocklist4", 6: "blocklist6"}

RULESET = f"""
table {FAMILY} {TABLE} {{
    set blocklist4 {{
        type ipv4_addr
        flags timeout
    }}
    set blocklist6 {{
        type ipv6_addr
        flags interval, timeout
    }}
    chain prerouting {{
        type filter hook prerouting priority -300; policy accept;
        ip saddr @blocklist4 counter drop
        ip6 saddr @blocklist6 counter drop
    }}
}}
"""


class FirewallError(RuntimeError):
    pass


def _nft(args, stdin=None):
    return subprocess.run(["nft", *args], input=stdin, capture_output=True,
                          text=True, timeout=10)


def available():
    return shutil.which("nft") is not None


def ensure():
    """Create table/sets/chain if missing. Idempotent: never duplicates rules,
    never flushes existing bans."""
    if _nft(["list", "table", FAMILY, TABLE]).returncode == 0:
        return
    r = _nft(["-f", "-"], stdin=RULESET)
    if r.returncode != 0:
        raise FirewallError(r.stderr.strip() or "nft -f failed")


def _target(key):
    """key is '1.2.3.4', '2001:db8::1' or '2001:db8:1:1::/64' -> (version, element)."""
    net = ipaddress.ip_network(key, strict=False)
    if net.version == 4:
        return 4, str(net.network_address)
    return 6, str(net)  # interval set: '2001:db8::1/128' or '2001:db8:1:1::/64'


def block(key, seconds):
    version, elem = _target(key)
    r = _nft(["add", "element", FAMILY, TABLE, SETS[version],
              f"{{ {elem} timeout {int(seconds)}s }}"])
    return r.returncode == 0, r.stderr.strip()


def unblock(key):
    version, elem = _target(key)
    r = _nft(["delete", "element", FAMILY, TABLE, SETS[version], f"{{ {elem} }}"])
    return r.returncode == 0, r.stderr.strip()


def flush():
    """Remove every ban, keep the table."""
    ok = True
    for name in SETS.values():
        ok &= _nft(["flush", "set", FAMILY, TABLE, name]).returncode == 0
    return ok


def remove():
    """Remove the whole table (and with it every ban and the drop rules)."""
    return _nft(["delete", "table", FAMILY, TABLE]).returncode == 0


def _val_to_key(val):
    if isinstance(val, dict) and "prefix" in val:
        net = ipaddress.ip_network(f"{val['prefix']['addr']}/{val['prefix']['len']}",
                                   strict=False)
        return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    if isinstance(val, str):
        return str(ipaddress.ip_address(val))
    return None


def load_existing():
    """Bans already in the kernel -> {key: remaining_seconds}. Used on startup so
    the dashboard reflects reality after a restart."""
    found = {}
    for name in SETS.values():
        r = _nft(["-j", "list", "set", FAMILY, TABLE, name])
        if r.returncode != 0:
            continue
        try:
            data = json.loads(r.stdout)
        except ValueError:
            continue
        for item in data.get("nftables", []):
            for e in (item.get("set") or {}).get("elem", []):
                info = e.get("elem", e) if isinstance(e, dict) else {"val": e}
                try:
                    key = _val_to_key(info.get("val"))
                except (ValueError, KeyError, TypeError):
                    continue
                if key:
                    found[key] = int(info.get("expires", config.BAN_SECONDS))
    return found
