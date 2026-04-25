<p align="center">
  <img src="logo.ico" width="64" alt="NexoraGuard Logo"/>
</p>

<h1 align="center">NexoraGuard</h1>
<p align="center"><strong>Enterprise XDR Security Platform — Built for Windows</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square&logo=fastapi"/>
  <img src="https://img.shields.io/badge/AI-LLaMA%203.3%2070B-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows"/>
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=flat-square"/>
</p>

---

## What is NexoraGuard?

NexoraGuard is a full-stack **Extended Detection and Response (XDR)** security platform built from scratch in Python. It correlates endpoint (EDR) and network (NDR) signals into unified incidents, tracks attacker progression through **MITRE ATT&CK kill chain stages**, and fires automated response playbooks — all without requiring enterprise infrastructure.

> Built as a serious alternative to CrowdStrike and SentinelOne for small-to-medium businesses that can't afford $15,000+/year licensing.

---

## Features

### Core Detection
| Module | Description |
|--------|-------------|
| **EDR Engine** | Process monitoring, file integrity, registry changes, USB events |
| **NDR Engine** | Network traffic analysis, DDoS detection, brute force guard |
| **UEBA** | User behavior analytics — detects anomalous login hours and processes |
| **Ransomware Detector** | File entropy analysis, mass modification, shadow copy deletion detection |
| **Zero-Day Detector** | Heuristic process anomaly detection |
| **Lateral Movement** | Detects credential reuse and internal scanning patterns |
| **Vuln Scanner** | Software version checks against known EOL/CVE database |

### XDR Platform
| Feature | Description |
|---------|-------------|
| **XDR Incident Correlation** | Union-find algorithm merges EDR + NDR alerts by shared entity (IP/user) within 5-minute windows |
| **Kill Chain Tracker** | MITRE ATT&CK 12-stage progression with next-move prediction |
| **Playbook Engine** | 12 pre-built response scenarios — auto-executes IP blocks, process kills, network isolation |
| **Attacker Profiling** | Classifies threat actor type: APT / Ransomware Operator / Script Kiddie |

### Dashboard & Reporting
- Dark-themed web dashboard with 10+ pages
- Real-time WebSocket updates
- PDF + Excel security reports
- MITRE ATT&CK heatmap
- JWT-authenticated access control

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  NexoraGuard Agent                  │
├──────────────┬──────────────────┬───────────────────┤
│  EDR Engine  │   NDR Engine     │   AI Analysis     │
│  (psutil)    │   (scapy/win)    │   (LLaMA 3.3 70B) │
├──────────────┴──────────────────┴───────────────────┤
│              XDR Correlation Engine                 │
│         Kill Chain Tracker  │  Playbook Engine      │
├─────────────────────────────────────────────────────┤
│           FastAPI Backend  (port 8080)              │
├─────────────────────────────────────────────────────┤
│          Web Dashboard  (HTML/CSS/JS)               │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

### Requirements
- Windows 10/11 (64-bit)
- Python 3.11+
- Run as **Administrator** (required for network monitoring)

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/nexoraguard.git
cd nexoraguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env
# Edit .env and add your GROQ_API_KEY (free at console.groq.com)

# 4. Run (as Administrator)
python launcher.py
```

Dashboard opens automatically at `http://127.0.0.1:8080/dashboard`

**Default credentials:** Contact your administrator (first-run setup creates credentials)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, uvicorn |
| AI Engine | Groq API (LLaMA 3.3 70B — free tier) |
| System Monitoring | psutil, pywin32, winreg |
| Frontend | Vanilla JS, Chart.js, WebSockets |
| Desktop App | pywebview (Edge WebView2) |
| Auth | JWT (python-jose), PBKDF2-SHA256 passwords |
| Reports | fpdf2 (PDF), openpyxl (Excel) |

---

## Comparison

| Feature | NexoraGuard | CrowdStrike | SentinelOne | Wazuh |
|---------|:-----------:|:-----------:|:-----------:|:-----:|
| XDR Correlation | ✅ | ✅ | ✅ | ❌ |
| Kill Chain Tracking | ✅ | ✅ | ✅ | ❌ |
| Auto Response Playbooks | ✅ | ✅ | ✅ | Partial |
| MITRE ATT&CK Mapping | ✅ | ✅ | ✅ | ✅ |
| AI Threat Analysis | ✅ | ✅ | ✅ | ❌ |
| Ransomware Detection | ✅ | ✅ | ✅ | ❌ |
| Windows Native | ✅ | ✅ | ✅ | ❌ |
| **Cost/month** | **Affordable** | $15k+/yr | $12k+/yr | Free (self-host) |

---

## Project Structure

```
nexoraguard/
├── backend/
│   ├── main.py              # FastAPI server + all API routes
│   ├── auth.py              # JWT authentication
│   ├── xdr_engine.py        # EDR+NDR correlation
│   ├── kill_chain_tracker.py # MITRE ATT&CK progression
│   ├── playbook_engine.py   # Automated response
│   ├── detection_engine.py  # Core threat analysis
│   ├── ueba.py              # User behavior analytics
│   ├── ransomware_detector.py
│   ├── lateral_movement.py
│   ├── vuln_scanner.py
│   └── report_generator.py  # PDF + Excel reports
├── dashboard/
│   └── index.html           # Full web dashboard
├── .env.example             # Environment template
├── requirements.txt
└── launcher.py              # Entry point
```

---

## Screenshots

> Dashboard, login page, XDR incidents, kill chain view — add screenshots here

---

## License

Proprietary — All rights reserved. Contact for licensing inquiries.

---

<p align="center">Built by <strong>Adil</strong> — Nexora Cyber Tech</p>
