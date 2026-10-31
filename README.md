# Cognitive IPS (Cognitive-IPS)

A high-performance, modular Intrusion Prevention System (IPS) engineered in Python. It combines low-level packet capture via BPF filtering, behavioral heuristic analysis (such as SYN bursts and port spreading), and bounded local Large Language Model (Ollama) security triage to dynamically mitigate network threats via `iptables`.

## 🛡️ Key Features

* **Kernel-Level BPF Filtering:** Offloads initial traffic filtering directly to the kernel to maximize packet capture performance and minimize CPU overhead.
* **Behavioral Threat Scoring:** Evaluates traffic streams using sliding-window metrics (SYN rate tracking, distinct port spreads, and exponential score decay) rather than raw packet volume alone.
* **Local AI Triage Integration:** Leverages a local Ollama instance (e.g., `qwen2.5-coder:3b`) to perform asynchronous, bounded security analysis on suspicious payload data with strict prompt-injection defenses.
* **Idempotent Firewall Enforcement:** Automatically manages rule priorities at the top of the `iptables` INPUT chain (`-I 1`) with built-in dry-run safety modes.
* **Rich Terminal Telemetry Dashboard:** Features a live, real-time reactive command-line interface powered by the `rich` library, displaying active threat statuses, scores, and recent event logs.
* **Self-DoS Prevention:** Automatically discovers local host interfaces and respects configurable white-lists and trusted network definitions.

## 🚀 Architecture \& Workflow

1. **Capture Layer (`sentinel.py`):** Sniffs incoming IPv4 streams, formats payload details, and writes log events efficiently using rotating file handlers.
2. **Analysis \& Decision Engine (`audit.py`):** Tails the sentinel log stream in real time, aggregates behavioral heuristics, and queries the local LLM when specific suspicious keywords are detected.
3. **Enforcement Subsystem:** Automatically escalates scores past safety thresholds to trigger temporary or permanent IP blocking rules via firewall interfaces.

## 🛠️ Usage \& Execution

### Prerequisites

* Linux Operating System with administrative privileges (`sudo`) and `iptables` installed.
* Python 3.x
* Ollama service running locally (for AI-assisted threat triage).
* Dependencies: `scapy`, `requests`, `rich`, `psutil`.

### Installation

```bash
pip install scapy requests rich psutil
```

### Execution

To run the capture engine in the background:

```bash
sudo python3 sentinel.py
```

To run the analysis dashboard (Dry-Run mode by default):

```bash
python3 audit.py
```

To run with active firewall enforcement enabled:

```bash
sudo python3 audit.py --enforce
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```

eof

---

Prontinho, Joelson! O `README.md` ficou completo, técnico e alinhado com o padrão sênior dos nossos outros repositórios. 

Podes commitar e enviar tudo para o repositório \\\*\\\*`Cognitive-IPS`\\\*\\\* no GitHub quando quiseres. Assim que estiver pronto, é só me avisar para darmos início ao próximo da lista, o \\\*\\\*`ReconEngine`\\\*\\\*!




