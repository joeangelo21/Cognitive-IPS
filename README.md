# 🛡️ Cognitive-IPS — Local Cognitive Intrusion Prevention System

Experimental Intrusion Detection and Prevention System (IDS/IPS) that runs entirely on your local machine, with no cloud dependency. It captures network traffic in real-time, filters suspicious packets, and leverages a local Large Language Model (via Ollama) to classify and automatically ban hostile IPs if necessary.

## 🧠 Architecture
```text
       Network Traffic
              │
              ▼
    ┌────────────────────┐
    │    sentinel.py     │ Captures packets & applies whitelist
    └──────────┬─────────┘
               │ Writes logs
               ▼
    ┌──────────────────────┐
    │ network_monitoring.log│
    └──────────┬───────────┘
               │ Reads log
               ▼
    ┌────────────────────┐
    │      audit.py      │ AI Analysis
    └──────────┬─────────┘
               │
               ▼
    ┌────────────────────┐
    │    Ollama (LLM)    │ Classifies payload
    └──────────┬─────────┘
               │
               ▼
    ┌────────────────────┐
    │      iptables      │ Automatic Ban
    └────────────────────┘

## ⚙️ Components

### 🔹 sentinel.py — Capture
* Captures IP/TCP packets in real-time using Scapy.
* Ignores WHITELIST addresses at the capture layer.
* Extracts a secure summary of the TCP payload (up to 100 bytes) for analysis.
* Records events to `network_monitoring.log`.

### 🔹 audit.py — Cognitive Engine
* Continuously monitors the log file.
* Extracts and validates the IP of each entry.
* Applies a fast pre-filter for keywords before triggering AI analysis.
* Sends data to the local `qwen2.5-coder:3b` model via Ollama.
* Maintains a risk score per IP and bans via `iptables` when reaching `SCORE_THRESHOLD`.
* Displays a live terminal dashboard.

### 🔹 install.sh — Automated Setup
* Installs system dependencies.
* Creates a Python virtual environment.
* Installs libraries (scapy, requests, rich).
* Pulls the `qwen2.5-coder:3b` model.

### 🔹 start.sh — Automated Execution
* Automatically opens two terminals for `sentinel.py` and `audit.py`.

## 📂 Project Structure

```text
.
├── sentinel.py              # Packet capture
├── audit.py                 # Cognitive engine
├── install.sh               # Install dependencies
├── start.sh                 # Start system
├── .gitignore               # Ignore venv/, logs, and runtime files
└── README.md


🚀 Execution
1. Installation (One-time)
Bash

chmod +x install.sh
./install.sh

2. Run the System
Bash

chmod +x start.sh
./start.sh

🔧 Configuration

Key parameters are defined at the top of audit.py and sentinel.py:

    WHITELIST: IPs that are never logged, analyzed, or banned.

    MODEL: Ollama model (default: qwen2.5-coder:3b).

    SCORE_THRESHOLD: Risk score at which the IP is banned.

⚠️ Disclaimer: This project is experimental for educational purposes. Use only in controlled environments.

👨‍💻 Author: Joelson Angelo | Cybersecurity & Systems Development
