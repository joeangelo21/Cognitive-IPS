import sys, os, tempfile, time, random, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import config
tmp = tempfile.mkdtemp()
config.BAN_LOG = os.path.join(tmp, "bans.log")
config.LOG_FILE = os.path.join(tmp, "net.log")
import audit, firewall

def L(ip, dport, flags, payload="x"):
    return f"SRC: {ip} | DPORT: {dport} | FLAGS: {flags} | SIZE: 60B | PAYLOAD: {payload}\n"

def run(events, seconds, key, engine=None, t0=10_000.0):
    """events: list of (time_offset, line). Ticks every 1 s. Returns (engine, ban_second or None)."""
    e = engine or audit.Engine(enforce=False, use_llm=False)
    events = sorted(events, key=lambda x: x[0]); i = 0; ban_at = None
    for sec in range(1, seconds + 1):
        t = t0 + sec
        while i < len(events) and events[i][0] < sec:
            e.process_line(events[i][1], t0 + events[i][0]); i += 1
        e.tick(t, 1.0)
        st = e.states.get(key)
        if st and st.banned_until and ban_at is None:
            ban_at = sec
    return e, ban_at

# 1) fast scan (nmap -T4 style): 200 ports in 1 s
ev = [(0.5, L("10.0.0.99", 1000+p, "S")) for p in range(200)]
e, ban = run(ev, 10, "10.0.0.99")
print(f"1 fast scan        banned at t={ban}s"); assert ban and ban <= 3

# 2) polite scan (-T2): 1 probe / 0.4 s, distinct ports. 1s-window logic alone can NOT see this.
ev = [(i*0.4, L("10.0.0.98", 1+i, "S")) for i in range(300)]
e, ban = run(ev, 120, "10.0.0.98")
fired = e.states["10.0.0.98"].active
print(f"2 polite -T2 scan  banned at t={ban}s signals={sorted(fired)}"); assert ban and ban < 60
assert "burst" not in fired and "spread" not in fired

# 3) stealth scan (-T1): 1 probe / 15 s
ev = [(i*15, L("10.0.0.97", 1+i, "S")) for i in range(60)]
e, ban = run(ev, 900, "10.0.0.97")
print(f"3 stealth -T1 scan banned at t={ban}s"); assert ban and 400 < ban < 600

# 4) NULL / FIN / Xmas probes also count
ev = [(i*0.4, L("10.0.0.96", 1+i, ["NULL","F","FPU"][i%3])) for i in range(100)]
e, ban = run(ev, 60, "10.0.0.96")
print(f"4 NULL/FIN/Xmas    banned at t={ban}s"); assert ban

# 5) false positives: legit client on 3 ports for 20 min, CDN download, parallel browser SYNs
ev  = [(i*5, L("198.51.100.7", [22,80,443][i%3], "S")) for i in range(240)]
ev += [(i*5+0.1, L("198.51.100.7", [22,80,443][i%3], "A")) for i in range(240)]
e, ban = run(ev, 1200, "198.51.100.7"); print(f"5a legit 3-port client banned={ban}"); assert not ban
ev = [(s + k/3000, L("151.101.1.1", 443, "A")) for s in range(30) for k in range(3000)]
e, ban = run(ev, 30, "151.101.1.1"); print(f"5b CDN download 3000 pkt/s banned={ban}"); assert not ban
ev = [(s + k/20, L("203.0.113.50", 443, "S")) for s in range(60) for k in range(20)]
e, ban = run(ev, 60, "203.0.113.50"); print(f"5c 20 SYN/s to :443 banned={ban}"); assert not ban

# 6) IPv6: attacker rotates interface IDs inside one /64 -> aggregated to the /64
rnd = random.Random(1)
def v6(): return "2001:db8:1:1:" + ":".join(f"{rnd.randrange(65536):x}" for _ in range(4))
ev = [(i*0.4, L(v6(), 1+i, "S")) for i in range(300)]
e, ban = run(ev, 120, "2001:db8:1:1::/64")
print(f"6a IPv6 rotating IIDs: tracked keys={list(e.states)} banned at t={ban}s")
assert list(e.states) == ["2001:db8:1:1::/64"] and ban

# 6b) our own /64 is protected -> fall back to /128
config.PROTECTED_ADDRS.append(__import__("ipaddress").ip_address("2001:db8:99::10"))
k = config.source_key("2001:db8:99::beef"); print("6b protected /64 ->", k); assert k == "2001:db8:99::beef"
assert config.source_key("2001:db8:5::7") == "2001:db8:5::/64"
assert config.is_trusted("::1") and config.is_trusted("127.0.0.5") and not config.is_trusted("2001:db8::1")
# IPv4-style garbage and malformed v6 are ignored
e = audit.Engine(enforce=False, use_llm=False)
for bad in ["SRC: 999.1.1.1 | DPORT: 1 | FLAGS: S | SIZE: 1B | PAYLOAD: x\n", "SRC: ::g | DPORT: 1 | FLAGS: S | SIZE: 1B | PAYLOAD: x\n", "junk\n"]:
    e.process_line(bad, 1.0)
assert not e.states; print("6c malformed IPs ignored")

# 7) memory caps
config.MAX_TRACKED = 50
e = audit.Engine(enforce=False, use_llm=False)
for i in range(500): e.process_line(L(f"10.1.{i//250}.{i%250}", 80, "S"), 1.0)
print(f"7a tracked sources capped at {len(e.states)} (limit 50)"); assert len(e.states) == 50
config.MAX_TRACKED = 10000
e = audit.Engine(enforce=False, use_llm=False)
for p in range(1, 5000): e.process_line(L("10.2.2.2", p, "S"), 1.0)
print(f"7b ports tracked per source: {len(e.states['10.2.2.2'].slow_ports)} (limit {config.MAX_PORTS_TRACKED})")
assert len(e.states["10.2.2.2"].slow_ports) == config.MAX_PORTS_TRACKED

# 8) firewall command construction (subprocess mocked) + enforce path
calls = []
class P:
    def __init__(s, rc=0, out="", err=""): s.returncode, s.stdout, s.stderr = rc, out, err
def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
    calls.append((cmd, input)); return P()
firewall.subprocess.run = fake_run
firewall.block("203.0.113.5", 3600)
firewall.block("2001:db8:1:1::/64", 3600)
firewall.block("2001:db8:99::beef", 3600)
firewall.unblock("2001:db8:1:1::/64"); firewall.flush()
for c, _ in calls: print("  ", " ".join(c))
assert calls[0][0][-1] == "{ 203.0.113.5 timeout 3600s }" and calls[0][0][5] == "blocklist4"
assert calls[1][0][-1] == "{ 2001:db8:1:1::/64 timeout 3600s }" and calls[1][0][5] == "blocklist6"
assert calls[2][0][-1] == "{ 2001:db8:99::beef/128 timeout 3600s }"

# enforce flow: engine bans through firewall.block and logs it
calls.clear()
e = audit.Engine.__new__(audit.Engine)  # avoid _restore_bans reading real nft
audit.Engine.__init__(e, enforce=False, use_llm=False); e.enforce = True
ev = [(0.5, L("10.0.0.99", 1000+p, "S")) for p in range(200)]
run(ev, 4, "10.0.0.99", engine=e)
adds = [c for c, _ in calls if "add" in c]
print("8 enforce -> nft add element calls:", len(adds), "|", adds[0][-1]); assert len(adds) == 1
print("   ban log:", open(config.BAN_LOG).read().strip().splitlines()[-1])

# 9) load_existing parses libnftables-json (documented format, incl. prefix + /128)
sample4 = {"nftables":[{"metainfo":{}},{"set":{"name":"blocklist4","elem":[{"elem":{"val":"203.0.113.5","timeout":3600,"expires":3012}}]}}]}
sample6 = {"nftables":[{"set":{"name":"blocklist6","elem":[
    {"elem":{"val":{"prefix":{"addr":"2001:db8:1:1::","len":64}},"timeout":3600,"expires":100}},
    {"elem":{"val":{"prefix":{"addr":"2001:db8:99::beef","len":128}},"timeout":3600,"expires":50}}]}}]}
def fake_run2(cmd, **kw):
    return P(0, json.dumps(sample4 if "blocklist4" in cmd else sample6))
firewall.subprocess.run = fake_run2
got = firewall.load_existing(); print("9 restored bans:", got)
assert got == {"203.0.113.5": 3012, "2001:db8:1:1::/64": 100, "2001:db8:99::beef": 50}
print("ALL TESTS PASSED")
