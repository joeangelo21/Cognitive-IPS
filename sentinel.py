import os
from scapy.all import sniff, IP, TCP

# Path must match LOG_FILE in audit8.py (same folder)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "network_monitoring.log")
# Added 192.168.1.254 to whitelist to avoid gateway monitoring
WHITELIST = ["192.168.1.5", "192.168.1.86", "192.168.1.254"]

def log_to_audit(ip, size, payload):
    if ip in WHITELIST:
        return
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"SRC: {ip} | SIZE: {size}B | PAYLOAD: {payload}\n")
    except Exception as e:
        print(f"Logging error: {e}")

def packet_callback(packet):
    if IP not in packet:
        return

    ip = packet[IP].src
    if ip in WHITELIST:
        return

    size = len(packet)

    # If TCP with payload, extract secure summary;
    # otherwise uses default packet summary (covers UDP/ICMP/etc.)
    if TCP in packet and bytes(packet[TCP].payload):
        payload = str(bytes(packet[TCP].payload))[:100]
    else:
        payload = packet.summary()

    log_to_audit(ip, size, payload)

if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    open(LOG_FILE, 'a').close()

    print("[*] Sentinel running...")
    print(f"[*] Protecting: {WHITELIST}")

    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sentinel stopped by operator.")
