import threading
import time
import os
import logging
from collections import defaultdict
from scapy.all import sniff, IP

# =========================
# CONFIGURAÇÕES
# =========================

LOG_FILE = "monitoramento_rede.log"
FEEDBACK_FILE = "feedback_ban.log"

WHITELIST = {
    "127.0.0.1",
    "192.168.1.1",
    "192.168.1.5"
}

IP_BANNED = set()
IP_VOLUME_HISTORY = defaultdict(int)

data_lock = threading.Lock()

# =========================
# LOGGING
# =========================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# =========================
# FUNÇÕES AUXILIARES
# =========================

def validar_ip(ip: str) -> bool:
    """Validação simples de IP IPv4."""
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except:
        return False


def registrar_log(msg: str):
    logging.info(msg)


# =========================
# THREAD: FEEDBACK LOOP
# =========================

def monitorar_feedback():
    """
    Lê arquivos de feedback externo (IA ou sistema) 
    e atualiza lista de IPs banidos.
    """
    while True:
        try:
            if os.path.exists(FEEDBACK_FILE):
                with open(FEEDBACK_FILE, "r") as f:
                    for line in f:
                        ip = line.strip()

                        if validar_ip(ip):
                            with data_lock:
                                IP_BANNED.add(ip)

                            registrar_log(f"[BAN ADDED] {ip}")

                os.remove(FEEDBACK_FILE)

        except Exception as e:
            registrar_log(f"[FEEDBACK ERROR] {e}")

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
        summary = packet.summary()

        if not validar_ip(ip_src):
            return

        with data_lock:
            # bloqueios
            if ip_src in WHITELIST:
                return

            if ip_src in IP_BANNED:
                return

            # histórico de volume
            IP_VOLUME_HISTORY[ip_src] += size

        msg = f"SRC={ip_src} SIZE={size}B SUMMARY={summary}"
        registrar_log(msg)

    except Exception as e:
        registrar_log(f"[PACKET ERROR] {e}")


# =========================
# THREAD: MONITOR PRINCIPAL
# =========================

def iniciar_monitoramento():
    print("[*] Sentinela ativo... monitorando tráfego de rede")

    sniff(
        filter="ip",
        prn=packet_callback,
        store=False
    )


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    # thread de feedback (IA ou sistema externo)
    t = threading.Thread(target=monitorar_feedback, daemon=True)
    t.start()

    # inicia sniffing
    iniciar_monitoramento()
