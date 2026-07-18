import os
import re
import time
import subprocess
import ipaddress
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box

# ==============================================================================
# CONFIGURATIONS AND PERIMETER
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "network_monitoring.log")
BAN_LOG = os.path.join(BASE_DIR, "execution_bans.log")

# STRICT WHITELIST (Only authorized IPs)
WHITELIST_IPS = ["192.168.1.5", "192.168.1.86", "192.168.1.254"]

# Trusted service networks (GitHub and Local)
TRUSTED_NETWORKS = [
    ipaddress.ip_network('140.82.112.0/20'),
    ipaddress.ip_network('192.30.252.0/22'),
    ipaddress.ip_network('127.0.0.1/32')
]

console = Console()
banned = set()
history_ips = defaultdict(int)
alerts = defaultdict(int)

def is_trusted(ip_str):
    if ip_str in WHITELIST_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in TRUSTED_NETWORKS)
    except: return False

def generate_dashboard():
    table = Table(title="💀 SENTINEL | HOSTILE COMMAND CENTER 💀", 
                  box=box.DOUBLE, expand=True, header_style="bold magenta")
    
    table.add_column("🌐 MONITORED IP", style="yellow")
    table.add_column("⚡ Pkts/s", style="green")
    table.add_column("🧠 SECURITY STATUS", style="white")
    table.add_column("⚠️ RISK", style="red")

    for ip in sorted(history_ips.keys(), key=lambda x: history_ips[x], reverse=True):
        pkts = history_ips[ip]
        
        if ip in banned:
            status = "[bold blink red]⛔ ELIMINATED[/bold blink red]"
            risc = "CRITICAL"
        elif is_trusted(ip):
            status = "[bold cyan]🛡️ TRUSTED[/bold cyan]"
            risc = "NULL"
        elif alerts[ip] >= 2:
            status = "[bold yellow]🔥 HIGH ALERT[/bold yellow]"
            risc = "EXTREME"
        elif alerts[ip] == 1:
            status = "[bold orange]🔍 SUSPICIOUS[/bold orange]"
            risc = "MODERATE"
        else:
            status = "[bold green]✅ MONITORING[/bold green]"
            risc = "LOW"
            
        table.add_row(ip, str(pkts), status, risc)
        
    return Panel(table, title="[bold cyan]DEFENSE SYSTEM ACTIVE | HACKER MODE[/bold cyan]", border_style="blue")

def monitor_queue():
    last_check = time.time()
    if not os.path.exists(LOG_FILE): open(LOG_FILE, 'a').close()
    
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)
        with Live(generate_dashboard(), refresh_per_second=10, screen=True) as live:
            while True:
                line = f.readline()
                if line:
                    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                    if ip_match:
                        ip = ip_match.group(0)
                        if not is_trusted(ip) and ip not in banned:
                            history_ips[ip] += 1
                            
                            # Hostile Logic (Recurrence = Ban)
                            if history_ips[ip] > 60:
                                alerts[ip] += 1
                                if alerts[ip] >= 3:
                                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                                    banned.add(ip)
                                    with open(BAN_LOG, 'a') as b:
                                        b.write(f"{time.ctime()} | BANNED: {ip}\n")
                                    console.print(f"[bold red]⛔ TARGET ELIMINATED:[/bold red] {ip}")

                now = time.time()
                if now - last_check >= 1:
                    live.update(generate_dashboard())
                    # Reset pps, but keep history and alerts
                    for ip in history_ips:
                        history_ips[ip] = 0
                    last_check = now

if __name__ == "__main__":
    monitor_queue()
