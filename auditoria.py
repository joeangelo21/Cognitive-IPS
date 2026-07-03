import os
import time
import json
import requests

WATCH_DIR = "/tmp/traffic_buffer"
MODELO = "qwen2.5-coder:3b"

# =========================
# IA ANALYSIS
# =========================

def analisar(evento):
    prompt = f"""
Você é um motor de análise de tráfego de rede.

Classifique o evento abaixo como:
- NORMAL
- ATAQUE (XSS, SQLi, Exploit, Flood, Scan)

Responda APENAS em JSON:

{{
  "tipo": "NORMAL ou ATAQUE",
  "categoria": "tipo do ataque ou none",
  "confianca": 0-1
}}

Evento:
{json.dumps(evento, indent=2)}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODELO,
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
# PROCESSAMENTO
# =========================

def processar_arquivo(path):
    try:
        with open(path, "r") as f:
            evento = json.load(f)

        resultado = analisar(evento)

        print(f"\n[*] EVENTO: {evento['ip']} -> {resultado}")

        if resultado.get("tipo") == "ATAQUE":
            ip = evento["ip"]

            with open("feedback_ban.log", "a") as f:
                f.write(ip + "\n")

            print(f"[!] BANIDO: {ip}")

    except Exception as e:
        print(f"[ERRO PROCESSAMENTO] {e}")

    finally:
        try:
            os.remove(path)
        except:
            pass


# =========================
# LOOP
# =========================

def monitorar():
    os.makedirs(WATCH_DIR, exist_ok=True)

    print(f"[*] IA V2 rodando em {WATCH_DIR}")

    vistos = set()

    while True:
        try:
            for file in os.listdir(WATCH_DIR):
                path = os.path.join(WATCH_DIR, file)

                if path in vistos:
                    continue

                processar_arquivo(path)
                vistos.add(path)

        except Exception as e:
            print(f"[LOOP ERROR] {e}")

        time.sleep(1)


if __name__ == "__main__":
    monitorar()
