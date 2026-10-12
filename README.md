<<<<<<< HEAD
# SentinelTrace AI — Email Forensic & Fraud Intelligence

> Understand the risk before the click.

Paste or upload a raw email (`.eml`) and get an **explainable** verdict in milliseconds: risk score, threat
classification, the exact reasons behind it, and a recommended action. Everything runs on your server — no email
content is sent to any third party, and the analysis engine makes **no network calls**, so it cannot hang or fail
because an external API is down.

## What is real vs. what you configure

| Area | Status |
|---|---|
| MIME / header parsing, SPF·DKIM·DMARC (read from `Authentication-Results` / `Received-SPF`) | Real |
| Lookalike / homoglyph / typosquat domains, display-name & executive impersonation, Reply-To mismatch | Real |
| Urgency / payment / credential / secrecy language, BEC indicators | Real (rule-based, explainable) |
| Link analysis (IP hosts, shorteners, punycode, link-text ≠ target, embedded redirects) | Real |
| Attachment hashing + dangerous-type detection | Real |
| SMTP trace + origin IP from `Received` headers | Real (probabilistic, labelled as such) |
| Threat-intel matching | Local list `data/threat_intel.json` (edit with your own IOCs) |
| Origin country | Needs a MaxMind DB: `pip install geoip2`, set `GEOIP_DB` (otherwise shown as "Unavailable") |
| Domain age (WHOIS/RDAP) | Not included — engine is offline by design; shown as "Not checked" |
| Cases, notes, evidence hashes + integrity re-check, audit log, campaigns, reports (HTML/JSON/print-to-PDF) | Real, stored in SQLite |

Scoring is a noisy-OR over named signals (`score = 1 − Π(1 − wᵢ)`), so every point of risk traces back to a reason
shown in the UI. It is a heuristic engine, not a trained ML model — the UI says "AI classification" in the product
sense; don't claim a model accuracy figure you haven't measured.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python wsgi.py                 # http://127.0.0.1:8000
make test                      # 19 tests
```

## Deploy

**Docker (anywhere):**
```bash
docker build -t sentineltrace .
docker run -d -p 8000:8000 -v st-data:/data -e API_KEY=$(openssl rand -hex 24) sentineltrace
```
**Render:** push the repo and use *New → Blueprint* (`render.yaml`). A 1 GB disk is mounted at `/data`.
**Railway / Fly / any PaaS:** use the Dockerfile, mount a volume at `/data`, expose `PORT`.

Health check: `GET /healthz` (200 = DB reachable).

### Production checklist
- Set **`API_KEY`** — otherwise anyone with the URL can use the API. The UI prompts for it automatically.
- Set `SEED_DEMO=0` once you stop demoing so sample emails don't mix with real data.
- Keep a **persistent volume** at `/data` (SQLite file). Back it up with `sqlite3 /data/sentineltrace.db ".backup out.db"`.
- Terminate **HTTPS** at your proxy/PaaS (HSTS is sent automatically on HTTPS). Keep `BEHIND_PROXY=1` behind one proxy.
- Set `RETENTION_DAYS` to match your data-retention policy (purged on startup).
- Rate limiting is per client IP **per worker**; add an edge limiter for stricter control.
- SQLite is right for a single node. For multiple instances, move `app/db.py` to Postgres.
- Only trust `Authentication-Results` added by *your own* gateway — a sender can forge that header.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze` | JSON `{"raw": "..."}` or multipart `file` → full analysis |
| POST | `/api/demo?kind=bec\|credential\|ceo\|invoice\|legit` | Analyse a built-in sample |
| GET | `/api/analyses[?q=&limit=]`, `/api/analyses/<id>` | List / fetch |
| PATCH | `/api/analyses/<id>` | `{"status": "Investigating"}` |
| GET | `/api/analyses/<id>/report[?format=json]`, `/eml` | Report, original evidence |
| GET | `/api/stats`, `/api/campaigns`, `/api/evidence`, `/api/audit` | Dashboard data |
| POST/GET/PATCH | `/api/analyses/<id>/case`, `/api/cases`, `/api/cases/<id>`, `/api/cases/<id>/notes` | Case management |
| GET | `/api/health`, `/api/config` | Public meta |

Errors are always JSON `{"error": "..."}` with the right status (400/401/404/413/429/500). Unexpected exceptions
are logged server-side and never leak a stack trace.

## Security notes
Strict CSP (`script-src 'self'`), `nosniff`, `X-Frame-Options: DENY`; every dynamic value in the UI and in reports is
HTML-escaped (tested with script/`onerror` payloads); upload size cap; constant-time API-key comparison; evidence
re-hashed on every view to detect tampering.
=======
# hackindia-ai-cybertech-hackathon-2026-logic-flux
Hackathon team repository for LOGIC FLUX - [hackindia-team:hackindia-ai-cybertech-hackathon-2026:logic-flux]
>>>>>>> d4e0b223f6357280579724823e15ab47b2c7ea3e
