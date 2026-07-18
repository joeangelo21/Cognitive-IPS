#!/bin/bash
set -e

# Directory where install.sh is located
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo " Installer - Sentinel + Audit8 (Local IPS)"
echo " Project Directory: $DIR"
echo "=============================================="

# ------------------------------------------------------------
# 1. System Packages
# ------------------------------------------------------------
echo "[1/5] Updating repositories and installing system packages..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv iptables tcpdump curl

# ------------------------------------------------------------
# 2. Python Virtual Environment
# ------------------------------------------------------------
echo "[2/5] Creating virtual environment in $DIR/venv..."
python3 -m venv "$DIR/venv"
source "$DIR/venv/bin/activate"

# ------------------------------------------------------------
# 3. Python Dependencies
# ------------------------------------------------------------
echo "[3/5] Installing Python dependencies (scapy, requests)..."
pip install --upgrade pip
pip install scapy requests rich

# ------------------------------------------------------------
# 4. Ollama (Local AI) + qwen2.5-coder:3b model
# ------------------------------------------------------------
echo "[4/5] Checking Ollama..."
if ! command -v ollama &> /dev/null; then
    echo "Ollama not found. Installing..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "Ollama already installed."
fi

echo "Starting Ollama service in background..."
echo "  -> With OLLAMA_KEEP_ALIVE=-1, the model stays loaded in GPU memory"
echo "     (avoids delay of reloading the model for each analysis)."
if ! pgrep -x "ollama" > /dev/null; then
    OLLAMA_KEEP_ALIVE=-1 nohup ollama serve > /tmp/ollama.log 2>&1 &
    sleep 3
else
    echo "  -> Ollama was already running. To apply keep-alive,"
    echo "     stop the current service and start again with:"
    echo "     OLLAMA_KEEP_ALIVE=-1 ollama serve"
fi

echo "Pulling model qwen2.5-coder:3b (this may take a while)..."
ollama pull qwen2.5-coder:3b

# ------------------------------------------------------------
# 5. Prepare log/score files inside project directory
# ------------------------------------------------------------
echo "[5/5] Preparing log files inside $DIR..."
touch "$DIR/network_monitoring.log"
echo "{}" > "$DIR/risks.json"

echo ""
echo "=============================================="
echo " Installation completed!"
echo "=============================================="
echo ""
echo "To run (inside $DIR directory):"
echo ""
echo "  1) Activate the virtual environment in each new terminal:"
echo "     source venv/bin/activate"
echo ""
echo "  2) In one terminal, capture traffic (requires sudo for scapy):"
echo "     sudo venv/bin/python3 sentinel.py"
echo ""
echo "  3) In another terminal, run the analysis engine:"
echo "     python3 audit.py"
echo ""
echo "  Note: 'audit.py' uses 'sudo iptables' to ban IPs automatically,"
echo "  it may ask for your password upon the first ban."
echo ""
echo "  If Ollama is running as a systemd service (ollama.service),"
echo "  the correct way to keep the model loaded in GPU is:"
echo ""
echo "     sudo systemctl edit ollama.service"
echo ""
echo "  Add these lines to the file:"
echo ""
echo "     [Service]"
echo "     Environment=\"OLLAMA_KEEP_ALIVE=-1\""
echo ""
echo "  Then restart the service:"
echo ""
echo "     sudo systemctl restart ollama"
echo ""
