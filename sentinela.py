import threading
import time
import os
import logging
from queue import Queue
from collections import defaultdict, deque
from scapy.all import sniff, IP

# ==========================
# CONFIGURAÇÕES
# ==========================
LOG_FILE = "monitoramento_rede.log"
WHITELIST = {"127.0.0.1", "192.168.1.1", "192.168.1.5"}

# Configuração do Logger
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

IP_VOLUME_HISTORY = defaultdict(lambda: {"total": 0, "last_seen": time.time()})
data_lock = threading.Lock()
logs_conexao = deque(maxlen=10)

def packet_callback(packet):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            if ip_src in WHITELIST:
                return
            
            with data_lock:
                IP_VOLUME_HISTORY[ip_src]["total"] += len(packet)
                IP_VOLUME_HISTORY[ip_src]["last_seen"] = time.time()
                msg = f"Atividade: {ip_src} ({len(packet)} bytes)"
                logs_conexao.append(msg)
                logging.info(msg)
    except Exception as e:
        logging.error(f"Erro na captura: {e}")

def limpar_memoria():
    """Remove IPs inativos há mais de 60 segundos."""
    while True:
        time.sleep(60)
        with data_lock:
            agora = time.time()
            para_remover = [ip for ip, dados in IP_VOLUME_HISTORY.items() 
                            if agora - dados["last_seen"] > 60]
            for ip in para_remover:
                del IP_VOLUME_HISTORY[ip]

def iniciar_sniff():
    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except Exception as e:
        logging.critical(f"Sniffer parou: {e}")

def analyzer():
    while True:
        time.sleep(3)
        with data_lock:
            snapshot = dict(IP_VOLUME_HISTORY)
            exibicao = list(logs_conexao)
            
        print("\033[H\033[J", end="") 
        print("=================================================")
        print(f"            SENTINELA v3.2 [PROD READY]         ")
        print("=================================================")
        print(f"{'IP Remetente':<25} {'Tráfego (KB)':<15}")
        print("-" * 50)
        
        for ip, dados in snapshot.items():
            print(f"{ip:<25} {round(dados['total'] / 1024, 2):>10} KB")
            
        print("\n[MURAL DE EVENTOS]")
        print("-" * 50)
        for linha in exibicao: print(linha)

if __name__ == "__main__":
    # Thread de monitoramento
    threading.Thread(target=iniciar_sniff, daemon=True).start()
    # Thread de limpeza automática (Aging)
    threading.Thread(target=limpar_memoria, daemon=True).start()
    
    try:
        analyzer()
    except KeyboardInterrupt:
        print("\n[*] Sentinela desligado. Logs salvos em", LOG_FILE)
