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
LOG_FILE = "sentinela.log"

WHITELIST = {"127.0.0.1", "192.168.1.1", "192.168.1.5"}
IP_BANNED = set()

IP_VOLUME = defaultdict(int)
lock = threading.Lock()

# =========================
# LOG CONFIG
# =========================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# =========================
# FUNÇÕES
# =========================

def validar_ip(ip):
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except:
        return False


def log(msg):
    print(msg)  # 👈 mostra na tela
    logging.info(msg)


def salvar_evento(evento):
    os.makedirs(BUFFER_DIR, exist_ok=True)
    path = f"{BUFFER_DIR}/evt_{time.time_ns()}.json"

    with open(path, "w") as f:
        json.dump(evento, f)


# =========================
# FEEDBACK LOOP
# =========================

def monitorar_feedback():
    feedback_file = "feedback_ban.log"

    while True:
        try:
            if os.path.exists(feedback_file):
                with open(feedback_file, "r") as f:
                    for line in f:
                        ip = line.strip()
                        if validar_ip(ip):
                            with lock:
                                IP_BANNED.add(ip)
                                log(f"[BAN] IP adicionado: {ip}")

                os.remove(feedback_file)

        except Exception as e:
            log(f"[FEEDBACK ERROR] {e}")

        time.sleep(2)


# =========================
# CAPTURA DE PACOTES
# =========================

def packet_callback(packet):
    try:
        if IP not in packet:
            return

        ip_src = packet[IP].src
        size = len(packet)

        if not validar_ip(ip_src):
            return

        if ip_src in WHITELIST or ip_src in IP_BANNED:
            return

        with lock:
            IP_VOLUME[ip_src] += size

        evento = {
            "ip": ip_src,
            "size": size,
            "summary": packet.summary(),
            "timestamp": time.time()
        }

        salvar_evento(evento)

        log(f"[EVENTO] {ip_src} - {size} bytes")

    except Exception as e:
        log(f"[ERRO PACKET] {e}")


# =========================
# MAIN
# =========================

def iniciar():
    log("[*] Sentinela iniciado...")

    threading.Thread(target=monitorar_feedback, daemon=True).start()

    sniff(
        filter="ip",
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":
    iniciar()
