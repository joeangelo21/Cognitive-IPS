import os
import time
import json
import requests

BUFFER_DIR = "/tmp/traffic_buffer"
MODEL = "qwen2.5-coder:3b"

# =========================
# IA ANALYSIS
# =========================

def analisar(evento):
    prompt = f"""
Você é um sistema de segurança de rede.

Classifique o tráfego como:
- NORMAL
- ATAQUE (SQLi, XSS, Scan, Exploit, Flood)

Responda APENAS em JSON:

{{
  "tipo": "NORMAL ou ATAQUE",
  "categoria": "tipo de ataque ou none",
  "confianca": 0.0 a 1.0
}}

Evento:
{json.dumps(evento, indent=2)}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=15
        )

        resp = r.json().get("response", "")

        try:
            return json.loads(resp)
        except:
            return {"tipo": "ERRO_IA", "raw": resp}

    except Exception as e:
        return {"tipo": "ERRO_IA", "error": str(e)}


# =========================
# PROCESSADOR
# =========================

def processar(path):
    try:
        with open(path, "r") as f:
            evento = json.load(f)

        resultado = analisar(evento)

        print(f"\n[IA] {evento['ip']} -> {resultado}")

        # decisão de bloqueio
        if resultado.get("tipo") == "ATAQUE":
            ip = evento["ip"]

            with open("feedback_ban.log", "a") as f:
                f.write(ip + "\n")

            print(f"[!] BLOQUEIO ENVIADO: {ip}")

    except Exception as e:
        print(f"[ERRO] {e}")

    finally:
        try:
            os.remove(path)
        except:
            pass


# =========================
# LOOP
# =========================

def monitorar():
    os.makedirs(BUFFER_DIR, exist_ok=True)

    print("[*] IA Analyzer rodando...")

    vistos = set()

    while True:
        try:
            for file in os.listdir(BUFFER_DIR):
                path = os.path.join(BUFFER_DIR, file)

                if path in vistos:
                    continue

                processar(path)
                vistos.add(path)

        except Exception as e:
            print(f"[LOOP ERROR] {e}")

        time.sleep(1)


if __name__ == "__main__":
    monitorar()
