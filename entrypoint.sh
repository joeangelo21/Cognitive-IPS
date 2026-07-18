#!/bin/bash
set -e

# Limpa o log a cada start (remova essa linha se quiser manter histórico entre reinícios)
> monitoramento_rede.log

echo "[*] Subindo sentinela.py (sniffer)..."
python sentinela.py &
SENTINELA_PID=$!

echo "[*] Subindo auditoria7.py (analisador)..."
python auditoria7.py &
AUDITORIA_PID=$!

# Se qualquer um dos dois morrer, derruba o container inteiro
wait -n $SENTINELA_PID $AUDITORIA_PID
