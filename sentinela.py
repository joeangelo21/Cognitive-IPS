import threading
import time
import os
import json
import logging
from collections import defaultdict
from scapy.all import sniff, IP

# =========================
# CONFIG
# =========================

BUFFER_DIR = "/tmp/traffic_buffer"
FEEDBACK_FILE = "feedback_ban.log"

WHITELIST = {"127.0.0.1", "192.168.1.1", "192.168.1.5"}
IP_BANNED = set()

IP_VOLUME_HISTORY = defaultdict(int)
data_lock = threading.Lock()

logging.basicConfig(
    filename="sentinela.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# =========================
# UTIL
# =========================

def validar_ip(ip):
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except:
        return False


def salvar_evento(evento):
    os.makedirs(BUFFER_DIR, exist_ok=True)

    filename = f"{BUFFER_DIR}/evt_{time.time_ns()}.json"

    with open(filename, "w") as f:
        json.dump(evento, f)


# =========================
# FEEDBACK LOOP
# =========================

def monitorar_feedback():
    while True:
        try:
            if os.path.exists(FEEDBACK_FILE):
                with open(FEEDBACK_FILE, "r") as f:
                    for line in f:
                        ip = line.strip()
                        if validar_ip(ip):
                            with data_lock:
                                IP_BANNED.add(ip)

                os.remove(FEEDBACK_FILE)

        except Exception as e:
            logging.error(f"feedback error: {e}")

        time.sleep(2)


# =========================
# CAPTURA
# =========================

def packet_callback(packet):
    try:
        if IP not in packet:
            return

        ip_src = packet[IP].src

        if not validar_ip(ip_src):
            return

        if ip_src in WHITELIST or ip_src in IP_BANNED:
            return

        evento = {
            "ip": ip_src,
            "size": len(packet),
            "summary": packet.summary(),
            "timestamp": time.time()
        }

        with data_lock:
            IP_VOLUME_HISTORY[ip_src] += evento["size"]

        salvar_evento(evento)

        logging.info(f"EVENT {ip_src} {evento['size']}B")

    except Exception as e:
        logging.error(f"packet error: {e}")


# =========================
# MAIN
# =========================

def iniciar():
    print("[*] Sentinela V2 ativo...")

    threading.Thread(target=monitorar_feedback, daemon=True).start()

    sniff(
        filter="ip",
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":
    iniciar()
