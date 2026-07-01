import os
import re
import time
import requests
import subprocess
from collections import defaultdict, deque

# ==============================================================================
# CONFIGURAÇÕES (Variabilizadas para rodar em qualquer ambiente)
# ==============================================================================
# Logs salvos no diretório onde o script for executado
LOG_FILE = os.getenv("IPS_LOG_FILE", "monitoramento_rede.log")
ATAQUES_FILE = os.getenv("IPS_ATAQUES_FILE", "ataques_confirmados.log")
TEMP_LOG = os.getenv("IPS_TEMP_LOG", "telemetria.log")

# Defina a subnet local através de variável de ambiente ou padrão seguro
WHITELIST = {"127.0.0.1"} 
MY_SUBNET = os.getenv("IPS_MY_SUBNET", "192.168.0.") 
MODELO = "qwen2.5:3b"
SCORE_THRESHOLD = 3
PALAVRAS_SUSPEITAS = ["select", "union", "or 1=1", "script", "etc/passwd", "alert", "drop", "update", "insert"]

# Memória e Controle
historico_por_ip = defaultdict(lambda: deque(maxlen=6))
risk_score = defaultdict(int)
IP_VOLUME_HISTORY = defaultdict(int)
ultimos_vereditos = []
ULTIMA_RENDERIZACAO = 0

# ==============================================================================
# MÓDULOS DE SUPORTE
# ==============================================================================
def get_gpu_temp():
    try:
        return subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"]).decode("utf-8").strip()
    except Exception: return "N/A"

def bloquear_ip(ip, motivo):
    if ip == "Desconhecido" or ip in WHITELIST or ip.startswith(MY_SUBNET): return
    try:
        # Uso de sudo deve ser configurado no sistema do operador
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode != 0:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            ultimos_vereditos.append(f"[{time.strftime('%H:%M:%S')}] 🛡 KERNEL: {ip} BANIDO!")
    except Exception: pass

# ==============================================================================
# MOTOR COGNITIVO COM IA (MODELO LOCAL)
# ==============================================================================
def analisar_com_ia(linha, ip):
    if ip in WHITELIST or ip.startswith(MY_SUBNET) or ip == "Desconhecido": 
        return "NORMAL"

    payload_match = re.search(r'PAYLOAD: (.*?) \| TIME:', linha)
    conteudo = payload_match.group(1).lower() if payload_match else linha.lower()

    if not any(x in conteudo for x in PALAVRAS_SUSPEITAS):
        return "NORMAL"

    historico_por_ip[ip].append(conteudo)
    contexto = "\n".join(historico_por_ip[ip])

    url = "http://localhost:11434/api/generate"
    payload = {
        "model": MODELO, "stream": False, "options": {"temperature": 0.0},
        "prompt": f"[SYSTEM: Analise o conteúdo. Responda APENAS: ATAQUE_CRITICO, ATAQUE_FLOOD ou NORMAL.]\nConteúdo: {contexto}\nClassificacao:"
    }

    try:
        response = requests.post(url, json=payload, timeout=6)
        resposta = response.json().get('response', 'NORMAL').strip().upper()
        if "ATAQUE_CRITICO" in resposta: return "ATAQUE_CRITICO"
        if "ATAQUE_FLOOD" in resposta: return "ATAQUE_FLOOD"
        return "NORMAL"
    except Exception: return "NORMAL"

def processar_evento(ip, linha):
    size_match = re.search(r'SIZE: (\d+)B', linha)
    if size_match: IP_VOLUME_HISTORY[ip] += int(size_match.group(1))

    classificacao = analisar_com_ia(linha, ip)
    timestamp = time.strftime('%H:%M:%S')
    
    if classificacao == "ATAQUE_CRITICO":
        risk_score[ip] = SCORE_THRESHOLD
        msg = f"[{timestamp}] 🚨 CRÍTICO: {ip} | Payload Hostil!"
    elif classificacao == "ATAQUE_FLOOD":
        risk_score[ip] += 1
        msg = f"[{timestamp}] ⚠ SUSPEITO: {ip} | Flood ({risk_score[ip]}/{SCORE_THRESHOLD})"
    else:
        risk_score[ip] = max(0, risk_score[ip] - 1)
        msg = f"[{timestamp}] ✅ NORMAL: {ip} | Monitorado"

    ultimos_vereditos.append(msg)
    if len(ultimos_vereditos) > 10: ultimos_vereditos.pop(0)

    if risk_score[ip] >= SCORE_THRESHOLD:
        with open(ATAQUES_FILE, "a") as f:
            f.write(f"[{time.ctime()}] IP {ip} BANIDO - Classificacao: {classificacao}\n")
        bloquear_ip(ip, "Ataque detectado.")
        risk_score[ip] = 0

# ==============================================================================
# RENDERING E LOOP
# ==============================================================================
def renderizar_dashboard():
    global ULTIMA_RENDERIZACAO
    if (time.time() - ULTIMA_RENDERIZACAO) < 0.5: return
    ULTIMA_RENDERIZACAO = time.time()
    
    os.system('clear')
    print(f"=== MOTOR COGNITIVO IPS | MODELO: {MODELO} ===")
    print(f"🌡 GPU: {get_gpu_temp()}°C | THRESHOLD: {SCORE_THRESHOLD}")
    print("-" * 77)
    for ip, total_bytes in list(IP_VOLUME_HISTORY.items()):
        print(f"{ip:<25} | {round(total_bytes/1024, 2):<10} KB | Risco: {risk_score[ip]}")
    print("\n📜 ÚLTIMOS VEREDITOS:")
    if ultimos_vereditos: print("\n".join(reversed(ultimos_vereditos)))

def monitorar_fila():
    if not os.path.exists(LOG_FILE): open(LOG_FILE, 'a').close()
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            linha = f.readline()
            if not linha:
                time.sleep(0.1)
                renderizar_dashboard()
                continue
            ip_match = re.search(r'SRC: (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', linha)
            if ip_match:
                processar_evento(ip_match.group(1), linha)
            renderizar_dashboard()

if __name__ == "__main__":
    monitorar_fila()
