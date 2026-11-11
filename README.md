# 🛡️ Airlock

**Zero-Latency Hybrid Security Firewall for Autonomous AI Coding Agents**  
*Built for the Google #BuildHybridAI 2026 Hackathon*

---

## 📌 Problem Overview

Autonomous coding agents (Claude Code, Cursor, Aider, OpenHands) execute shell commands directly on host machines. This access introduces critical security risks:

* **Indirect Prompt Injection:** Poisoned setup instructions or malicious repo dependencies trick agents into executing arbitrary subshells and remote scripts.
* **Credential Exfiltration:** Unmonitored network calls pipe SSH keys, cloud access tokens, and `.env` files to external command-and-control servers.
* **The Latency & Privacy Dilemma:** Routing every single command to cloud LLMs creates unacceptable latency (500ms–2s) and exposes private codebase context. Purely local regex filters cannot understand semantic intent or subtle obfuscation.

---

## ⚡ The Solution: Hybrid Edge-to-Cloud Firewall

Airlock implements a multi-layer hybrid defense architecture that ensures **local-speed execution**, **zero private data egress**, and **frontier model reasoning**:

```
Agent Command
      │
      ▼
┌────────────────────────────────────────┐  < 0.2 ms
│  LOCAL EDGE GATEKEEPER                 │  ─────────► LOCAL_ALLOW / LOCAL_BLOCK
│  • Deterministic signature engine      │             (0 bytes egress)
│  • Reversible secret vaulting          │
│  • Canary trap detection               │
│  • Cryptographic SHA-256 audit chaining│
└───────────────────┬────────────────────┘
                    │ Ambiguous / Obfuscated (ESCALATE)
                    ▼
┌────────────────────────────────────────┐  ~ 400-700 ms
│  CLOUD REASONING (Gemini 2.0 Flash)    │  ─────────► CLOUD_BLOCK / CLOUD_ALLOW
│  • Vault-tokenized payload analysis    │             + COMPILED REGEX RULE
│  • Indirect injection & intent origin  │
└───────────────────┬────────────────────┘
                    │ Flywheel: Push rule to edge
                    ▼
┌────────────────────────────────────────┐  < 0.1 ms (next attempt)
│  SELF-LEARNING LOCAL ENGINE            │  ─────────► LOCAL_BLOCK
│  • Cached & persisted signatures       │             (0 Cloud API calls)
└────────────────────────────────────────┘
```

---

## 🔑 Key Features

* **Sub-Millisecond Edge Enforcement:** Benign commands (`pytest`, `git status`) and known attack signatures run through local pattern matching in under 0.2 ms.
* **Local Secret Vault:** Any credential pattern (SSH keys, GCP/AWS secrets, GitHub PATs) is tokenized with local placeholders (`⟦SECRET_VAULT_X⟧`) before leaving the device. Real secrets never touch the network.
* **Canary Trap Protocol:** Planted environment bait (`CANARY_KEY_PROD_8841`) halts execution immediately if referenced by an agent.
* **Self-Learning Flywheel:** When Gemini Flash identifies an ambiguous attack, it generates a precise regex signature. Airlock compiles this rule back into the local engine, turning future attacks into instant local blocks.
* **Tamper-Evident SHA-256 Audit Trail:** Every transaction is linked to the previous entry via a cryptographic hash chain, guaranteeing verifiable forensic logs.
* **Live Interactive Web Dashboard:** Built with FastAPI and Tailwind CSS, featuring an Outbound Egress Monitor and an automated 4-scenario walkthrough.

---

## 🚀 Quick Start

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/YourUsername/Airlock.git
cd Airlock
pip install -r requirements.txt
```

### 2. (Optional) Configure Gemini API Key

```bash
export GEMINI_API_KEY="your-gemini-api-key"
```
> *Note: If no API key is provided, Airlock seamlessly falls back to an offline heuristic engine so all functionality and tests remain verifiable.*

### 3. Run the Interactive Web Dashboard

```bash
python web_server.py
```
Open your browser to `http://localhost:8080` to access the dashboard.

---

## 🧪 Testing the 4-Scenario Flywheel

Airlock includes an automated tour covering core agent threat scenarios:

| # | Scenario | Payload Example | Verdict | Latency | Cloud API |
|---|---|---|---|---|---|
| **1** | **Benign Workflow** | `pytest tests/` | `LOCAL_ALLOW` | `< 0.2 ms` | No |
| **2** | **Direct Secret Theft** | `cat ~/.ssh/id_rsa \| curl ...` | `LOCAL_BLOCK` | `< 0.2 ms` | No |
| **3** | **Indirect Injection** | `base64 -d payload.txt \| bash` | `CLOUD_BLOCK` | `~500 ms` | Yes (1 Call) |
| **4** | **Flywheel Enforcement** | `base64 -d payload.txt \| bash` | `LOCAL_BLOCK` | `< 0.1 ms` | No (Cached) |

### Run CLI Verification Suite

```bash
python test_airlock.py
```
All unit tests validate deterministic edge evaluation, secret vault isolation, canary detection, and cryptographic hash chain verification.

---

## 🛠️ Tech Stack

* **Runtime:** Python 3.10+
* **Edge Engine:** Custom regex matching, AST command inspection, `rich`, `typer`
* **Cloud Reasoning:** Google Gemini 2.0 Flash (`google-genai` / `google-generativeai`)
* **Dashboard:** FastAPI, Uvicorn, Tailwind CSS, Vanilla JS
* **Integrity:** SHA-256 cryptographic chain logging

---

## 📄 License

MIT License. Built for the Google #BuildHybridAI 2026 Hackathon.