<div align="center">

# 🛡️ SentinelTrace AI
### *Understand the risk before the click.*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Engine Status](https://img.shields.io/badge/Engine-Offline%20First-success.svg)]()
[![Security](https://img.shields.io/badge/Zero--Leak-Private-critical.svg)]()

**An Explainable, Offline-First Email Forensic & Fraud Intelligence Engine designed for real-time Business Email Compromise (BEC) and phishing defense.**

</div>

---

## 🚀 Overview

**SentinelTrace AI** ingest raw emails (`.eml`) or payloads to provide an instant, explainable risk verdict in milliseconds. Built with a robust heuristic engine, it computes a transparent risk score and surfaces precise threat indicators without relying on vulnerable external third-party API dependencies.

---

## ⚡ Key Features

* **🔍 Deep Header & MIME Parsing:** Analyzes SPF, DKIM, and DMARC authentication protocols directly from message headers.
* **🕵️ Impersonation Detection:** Flags lookalike/homoglyph typosquat domains, display-name executive impersonation, and Reply-To mismatches.
* **🧠 Heuristic Explainability:** Uses a noisy-OR scoring model ($\text{score} = 1 - \prod(1 - w_i)$) so every point of risk maps directly back to a human-readable reason in the UI.
* **🔗 Advanced Link & Attachment Inspection:** Evaluates IP hosts, URL shorteners, punycode tricks, link-text discrepancies, and performs attachment hash matching.
* **🔒 Privacy-First & Offline:** Zero external network calls required for core analysis—your sensitive email data never leaves your infrastructure.
* **📊 Case Management & Auditing:** Fully integrated SQLite storage for tracking investigations, case notes, tamper-evident evidence re-hashing, and exportable reports.

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask, Gunicorn
* **Database & State:** SQLite, SQL DAO patterns
* **Frontend:** HTML5, CSS3, JavaScript, Jinja2 Templates
* **Containerization:** Docker & Render Blueprint support

---

## ⚙️ Quick Start & Local Development

Get the project running on your machine in under a minute:

```bash
# Clone the repository
git clone [https://github.com/HackIndiaXYZ/hackindia-ai-cybertech-hackathon-2026-logic-flux.git](https://github.com/HackIndiaXYZ/hackindia-ai-cybertech-hackathon-2026-logic-flux.git)
cd sentineltrace-ai

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python wsgi.py
