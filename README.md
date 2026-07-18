🛡️ SentinelIA — Local Cognitive IPS with AIExperimental Intrusion Detection and Prevention System (IDS/IPS) that runs entirely on your local machine, with no cloud dependency. It captures network traffic in real-time, filters suspicious packets, and leverages a local Large Language Model (via Ollama) to classify and automatically ban hostile IPs if necessary.🧠 Architecture        Network Traffic
               │
               ▼
      ┌─────────────────┐
      │   sentinel.py   │  Captures packets (Scapy) and applies whitelist
      └────────┬────────┘
               │ Writes log entries
               ▼
     network_monitoring.log
               │
               ▼
      ┌─────────────────┐
      │     audit.py    │  Reads log in real-time (tail -f)
      └────────┬────────┘
               │ If payload contains suspicious terms
               ▼
      ┌─────────────────┐
      │  Ollama (Local) │  qwen2.5-coder:3b classifies the payload
      └────────┬────────┘
               │ NORMAL / FLOOD_ATTACK / CRITICAL_ATTACK
               ▼
    Risk score per IP (persisted in risks.json)
               │
               ▼
    Threshold reached? ──► Automatic ban via iptables

Both programs run in parallel, as independent processes, connected only by the log file — this keeps packet capture (which requires root privileges) isolated from the AI analysis.⚙️ Components🔹 sentinel.py — CaptureCaptures IP/TCP packets in real-time using Scapy.Ignores WHITELIST addresses at the capture layer.Extracts a secure summary of the TCP payload (up to 100 bytes) for analysis.Records events to network_monitoring.log in the format:SRC: <ip> | SIZE: <bytes>B | PAYLOAD: <summary>
🔹 audit.py — Cognitive EngineContinuously monitors the log file.Extracts and validates the IP of each entry (Regex-based verification).Applies a fast pre-filter for keywords (select, union, or 1=1, script, etc/passwd, alert, drop) before triggering AI analysis.When a suspicious payload is detected, it sends data to the local qwen2.5-coder:3b model via Ollama API, which responds with:NORMALFLOOD_ATTACKCRITICAL_ATTACKMaintains a risk score per IP, persisted in risks.json.Automatically bans via iptables when reaching the SCORE_THRESHOLD.Displays a live terminal dashboard with traffic volume, risk scores, and recent verdicts.🔹 install.sh — Automated SetupPrepares the environment in a single run:Installs system dependencies (python3, iptables, tcpdump, curl).Creates a Python virtual environment (venv/) within the project folder.Installs required libraries (scapy, requests, rich).Installs/verifies Ollama and pulls the qwen2.5-coder:3b model.Initializes log/score files.🔹 start.sh — Automated ExecutionAutomatically opens two terminals (detects mate-terminal, gnome-terminal, xfce4-terminal, konsole, or xterm), one for sentinel.py and one for audit.py, automatically activating the virtual environment.📂 Project Structure.
├── sentinel.py              # Packet capture and log generation
├── audit.py                 # Cognitive engine (AI + score + auto-ban)
├── install.sh               # Install dependencies
├── start.sh                 # Start system automatically
├── .gitignore               # Ignore venv/, logs, and runtime files
└── README.md
Generated at runtime (ignored by Git):venv/                        # Python virtual environment
network_monitoring.log       # Network events log
risks.json                   # Persisted risk score per IP
🚀 Execution1. Installation (One-time)Bashchmod +x install.sh
./install.sh
2. Keep model loaded in GPU (Recommended)If Ollama runs as a systemd service:Bashsudo systemctl edit ollama.service
Ini, TOML[Service]
Environment="OLLAMA_KEEP_ALIVE=-1"
Bashsudo systemctl restart ollama
3. Run the SystemBashchmod +x start.sh
./start.sh
Or manually:Bash# Terminal 1 — Capture (requires sudo)
sudo venv/bin/python3 sentinel.py

# Terminal 2 — AI Analysis
venv/bin/python3 audit.py
🔧 ConfigurationKey parameters are defined at the top of audit.py and sentinel.py:ParameterDescriptionWHITELISTIPs that are never logged, analyzed, or bannedMODELOllama model used for classification (qwen2.5-coder:3b)SCORE_THRESHOLDRisk score at which the IP is bannedSUSPICIOUS_KEYWORDSTerms that trigger AI analysis⚠️ DisclaimerThis project is experimental and designed for educational purposes regarding network security, IDS/IPS, and local LLM integration. Use only in controlled environments (lab, VM, or private network). Automatic banning via iptables modifies system firewall rules — review the WHITELIST carefully before deployment.👨‍💻 AuthorJoelson AngeloCybersecurity & Systems Development
WHITELIST	IPs that are never logged, analyzed, or banned
MODEL	Ollama model used for classification (qwen2.5-coder:3b)
SCORE_THRESHOLD	Risk score at which the IP is banned
SUSPICIOUS_KEYWORDS	Terms that trigger AI analysis

⚠️ Disclaimer

This project is experimental and designed for educational purposes regarding network security, IDS/IPS, and local LLM integration. Use only in controlled environments (lab, VM, or private network). Automatic banning via iptables modifies system firewall rules — review the WHITELIST carefully before deployment.
👨‍💻 Author

Joelson Angelo
Cybersecurity & Systems Development
