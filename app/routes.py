"""REST API. Every handler validates input and returns JSON errors; nothing leaks stack traces."""
import hashlib
import hmac
import html
import json
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, current_app, jsonify, request

from . import db as dbm
from .analyzer import AnalysisError, FREEMAIL, analyze, base_domain
from .demo import KINDS, demo_email

bp = Blueprint("api", __name__, url_prefix="/api")

CASE_STATUSES = {"Open", "Under Investigation", "Resolved", "Closed"}
CASE_PRIORITIES = {"Low", "Medium", "High", "Critical"}
ANALYSIS_STATUSES = {"New", "Investigating", "Confirmed Threat", "False Positive", "Resolved"}
OPEN_CASE = ("Open", "Under Investigation")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# --------------------------------------------------------------------------- #
# Guards: auth + rate limit
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Sliding-window limiter (per process). Put a real limiter in front for multi-instance setups."""

    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int = 60) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self.hits) > 5000:  # bound memory
                for k in [k for k, v in self.hits.items() if not v or now - v[-1] > window][:2500]:
                    self.hits.pop(k, None)
            return True


PUBLIC_PATHS = {"/api/health", "/api/config"}


@bp.before_request
def guard():
    if request.method == "OPTIONS" or request.path in PUBLIC_PATHS:
        return None
    key = current_app.config["API_KEY"]
    if key:
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied.encode(), key.encode()):
            dbm.audit(dbm.get_db(), "Rejected request (bad API key)", request.path, "DENIED", request.remote_addr or "")
            raise ApiError(401, "Missing or invalid API key.")
    if request.method == "POST" and request.path in ("/api/analyze", "/api/demo"):
        if not current_app.limiter.allow(request.remote_addr or "?", current_app.config["RATE_LIMIT_PER_MIN"]):
            raise ApiError(429, "Rate limit exceeded. Try again in a minute.")
    return None


def _ip():
    return request.remote_addr or ""


def _json_body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _row_or_404(db, aid: str):
    if not re.fullmatch(r"ST-[A-F0-9]{10}", aid or ""):
        raise ApiError(404, "Analysis not found.")
    row = db.execute("SELECT * FROM analyses WHERE id=?", (aid,)).fetchone()
    if not row:
        raise ApiError(404, "Analysis not found.")
    return row


def _result_of(row) -> dict:
    res = json.loads(row["result"])
    res["status"] = row["status"]
    res["source"] = row["source"]
    return res


def _summary(row) -> dict:
    return {
        "id": row["id"], "created_at": row["created_at"], "sender": row["sender"], "subject": row["subject"],
        "threat_type": row["threat_type"], "level": row["level"], "risk": row["risk"],
        "origin_conf": row["origin_conf"], "status": row["status"], "source": row["source"],
    }


def _read_input() -> bytes:
    limit = current_app.config["MAX_UPLOAD_MB"] * 1024 * 1024
    f = request.files.get("file")
    if f is not None:
        data = f.read(limit + 1)
    elif request.is_json:
        raw = _json_body().get("raw")
        if not isinstance(raw, str):
            raise ApiError(400, "JSON body must contain a string field 'raw'.")
        data = raw.encode("utf-8", errors="replace")
    else:
        raw = request.form.get("raw", "")
        data = raw.encode("utf-8", errors="replace")
    if len(data) > limit:
        raise ApiError(413, f"Email is larger than {current_app.config['MAX_UPLOAD_MB']} MB.")
    if not data.strip():
        raise ApiError(400, "Empty input. Paste raw email source or upload an .eml file.")
    return data


# --------------------------------------------------------------------------- #
# Meta
# --------------------------------------------------------------------------- #
@bp.get("/health")
def health():
    try:
        dbm.get_db().execute("SELECT 1").fetchone()
        return jsonify(status="ok", version=current_app.config["VERSION"])
    except Exception:
        current_app.logger.exception("health check failed")
        return jsonify(status="degraded"), 503


@bp.get("/config")
def config():
    c = current_app.config
    db = dbm.get_db()
    seeded = db.execute("SELECT COUNT(*) FROM analyses WHERE source='seed'").fetchone()[0] > 0
    return jsonify(version=c["VERSION"], auth_required=bool(c["API_KEY"]), retention_days=c["RETENTION_DAYS"],
                   max_upload_mb=c["MAX_UPLOAD_MB"], demo_data=seeded, demo_kinds=list(KINDS))


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def _run_and_store(raw: bytes, source: str = "user"):
    try:
        result = analyze(raw, current_app.intel, current_app.config["GEOIP_DB"])
    except AnalysisError as exc:
        raise ApiError(422, str(exc))
    db = dbm.get_db()
    dbm.save_analysis(db, result, raw, source)
    dbm.audit(db, "Analyzed email", result["id"], "OK", _ip())
    return result


@bp.post("/analyze")
def analyze_route():
    return jsonify(_run_and_store(_read_input())), 201


@bp.post("/demo")
def demo_route():
    kind = request.args.get("kind") or _json_body().get("kind") or "bec"
    if kind not in KINDS:
        raise ApiError(400, f"Unknown demo kind. Choose one of: {', '.join(KINDS)}.")
    return jsonify(_run_and_store(demo_email(kind), "demo")), 201


@bp.get("/analyses")
def list_analyses():
    db = dbm.get_db()
    try:
        limit = max(1, min(int(request.args.get("limit", 25)), 200))
    except ValueError:
        limit = 25
    q = (request.args.get("q") or "").strip()[:100]
    if q:
        like = f"%{q.lower().replace('%', '').replace('_', '')}%"
        rows = db.execute(
            "SELECT * FROM analyses WHERE lower(sender) LIKE ? OR lower(subject) LIKE ? OR lower(id) LIKE ? "
            "OR lower(threat_type) LIKE ? ORDER BY created_at DESC LIMIT ?", (like, like, like, like, limit)).fetchall()
    else:
        rows = db.execute("SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return jsonify([_summary(r) for r in rows])


@bp.get("/analyses/<aid>")
def get_analysis(aid):
    db = dbm.get_db()
    row = _row_or_404(db, aid)
    dbm.audit(db, "Viewed analysis", aid, "OK", _ip())
    return jsonify(_result_of(row))


@bp.patch("/analyses/<aid>")
def patch_analysis(aid):
    db = dbm.get_db()
    row = _row_or_404(db, aid)
    status = _json_body().get("status")
    if status not in ANALYSIS_STATUSES:
        raise ApiError(400, f"status must be one of: {', '.join(sorted(ANALYSIS_STATUSES))}.")
    db.execute("UPDATE analyses SET status=? WHERE id=?", (status, row["id"]))
    db.commit()
    dbm.audit(db, f"Set status '{status}'", aid, "OK", _ip())
    return jsonify(_summary(db.execute("SELECT * FROM analyses WHERE id=?", (aid,)).fetchone()))


@bp.get("/analyses/<aid>/eml")
def download_eml(aid):
    db = dbm.get_db()
    row = _row_or_404(db, aid)
    dbm.audit(db, "Downloaded original email (evidence)", aid, "OK", _ip())
    return Response(row["raw"], mimetype="message/rfc822",
                    headers={"Content-Disposition": f'attachment; filename="{aid}.eml"'})


# --------------------------------------------------------------------------- #
# Stats / campaigns / evidence / audit
# --------------------------------------------------------------------------- #
@bp.get("/stats")
def stats():
    db = dbm.get_db()
    total = db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    threats = db.execute("SELECT COUNT(*) FROM analyses WHERE level != 'low'").fetchone()[0]
    high = db.execute("SELECT COUNT(*) FROM analyses WHERE level='high'").fetchone()[0]
    open_cases = db.execute("SELECT COUNT(*) FROM cases WHERE status IN ('Open','Under Investigation')").fetchone()[0]
    dist = {r["bucket"]: r["n"] for r in db.execute("SELECT bucket, COUNT(*) n FROM analyses GROUP BY bucket")}
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    this_week = db.execute("SELECT COUNT(*) FROM analyses WHERE created_at >= ?",
                           (week_ago.isoformat(timespec="seconds"),)).fetchone()[0]
    return jsonify({
        "emails_analyzed": total, "threats_detected": threats, "high_risk": high,
        "active_campaigns": len(_campaigns(db)), "open_cases": open_cases,
        "flag_rate": round(100 * threats / total, 1) if total else 0.0,
        "this_week": this_week,
        "distribution": {k: dist.get(k, 0) for k in ("legitimate", "suspicious", "phishing", "impersonation", "bec")},
    })


def _campaigns(db) -> list[dict]:
    rows = db.execute("SELECT id, created_at, result FROM analyses WHERE level != 'low' "
                      "ORDER BY created_at DESC LIMIT 500").fetchall()
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    items = []
    for r in rows:
        res = json.loads(r["result"])
        keys = set()
        sd = base_domain(res["identity"]["sender"].rsplit("@", 1)[-1]) if "@" in res["identity"]["sender"] else ""
        rd = base_domain(res["identity"]["reply_to"].rsplit("@", 1)[-1]) if "@" in res["identity"]["reply_to"] else ""
        if sd and sd not in FREEMAIL:
            keys.add("d:" + sd)
        if rd and rd not in FREEMAIL:
            keys.add("d:" + rd)
        for u in res["urls"]:
            if u["flags"] and u["host"]:
                keys.add("d:" + base_domain(u["host"]))
        node = "a:" + r["id"]
        find(node)
        for k in keys:
            union(node, k)
        items.append((r, res, node, keys))

    groups: dict[str, list] = {}
    for r, res, node, _ in items:
        groups.setdefault(find(node), []).append((r, res))
    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        domains, ips, urls = set(), set(), set()
        for _, res in members:
            domains.add(base_domain(res["identity"]["sender"].rsplit("@", 1)[-1]))
            if res["origin"]["ip"]:
                ips.add(res["origin"]["ip"])
            urls.update(u["url"] for u in res["urls"] if u["flags"])
        times = sorted(r["created_at"] for r, _ in members)
        top = max(res["risk"]["score"] for _, res in members)
        cid = "CMP-" + hashlib.sha1(min(r["id"] for r, _ in members).encode()).hexdigest()[:4].upper()
        out.append({
            "id": cid, "name": f"{members[0][1]['threat_type']} campaign", "emails": len(members),
            "domains": sorted(d for d in domains if d), "ips": sorted(ips), "urls": len(urls),
            "first_seen": times[0], "last_seen": times[-1], "risk": top,
            "level": "high" if top >= 70 else "medium", "analysis_ids": [r["id"] for r, _ in members],
        })
    return sorted(out, key=lambda c: (-c["risk"], -c["emails"]))


@bp.get("/campaigns")
def campaigns():
    return jsonify(_campaigns(dbm.get_db()))


@bp.get("/evidence")
def evidence():
    db = dbm.get_db()
    rows = db.execute("SELECT id, created_at, subject, sha256, raw, source FROM analyses ORDER BY created_at DESC LIMIT 100").fetchall()
    out = []
    for r in rows:
        actual = hashlib.sha256(r["raw"]).hexdigest()
        custody = db.execute("SELECT ts, action FROM audit WHERE resource=? ORDER BY id LIMIT 20", (r["id"],)).fetchall()
        out.append({"id": r["id"], "created_at": r["created_at"], "subject": r["subject"], "sha256": r["sha256"],
                    "size": len(r["raw"]), "verified": hmac.compare_digest(actual, r["sha256"]),
                    "custody": [{"ts": c["ts"], "action": c["action"]} for c in custody]})
    return jsonify(out)


@bp.get("/audit")
def audit_log():
    rows = dbm.get_db().execute("SELECT ts, actor, action, resource, status FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #
def _case_row(db, cid: str):
    m = re.fullmatch(r"CASE-(\d+)", str(cid))
    if m:
        num = int(m.group(1)) - 1000
    elif str(cid).isdigit():
        num = int(cid)
    else:
        raise ApiError(404, "Case not found.")
    row = db.execute("SELECT * FROM cases WHERE id=?", (num,)).fetchone()
    if not row:
        raise ApiError(404, "Case not found.")
    return row


def _case_json(db, row, detail=False) -> dict:
    out = {"id": dbm.case_code(row["id"]), "analysis_id": row["analysis_id"], "title": row["title"],
           "priority": row["priority"], "status": row["status"], "assignee": row["assignee"],
           "created_at": row["created_at"], "updated_at": row["updated_at"]}
    if detail:
        notes = db.execute("SELECT created_at, note FROM case_notes WHERE case_id=? ORDER BY id DESC", (row["id"],)).fetchall()
        out["notes"] = [dict(n) for n in notes]
        if row["analysis_id"]:
            a = db.execute("SELECT * FROM analyses WHERE id=?", (row["analysis_id"],)).fetchone()
            out["analysis"] = _summary(a) if a else None
    return out


@bp.get("/cases")
def list_cases():
    db = dbm.get_db()
    rows = db.execute("SELECT * FROM cases ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([_case_json(db, r) for r in rows])


@bp.get("/cases/<cid>")
def get_case(cid):
    db = dbm.get_db()
    return jsonify(_case_json(db, _case_row(db, cid), detail=True))


@bp.post("/analyses/<aid>/case")
def create_case(aid):
    db = dbm.get_db()
    a = _row_or_404(db, aid)
    existing = db.execute("SELECT * FROM cases WHERE analysis_id=? AND status IN ('Open','Under Investigation')", (aid,)).fetchone()
    if existing:
        return jsonify(_case_json(db, existing, detail=True))
    body = _json_body()
    title = str(body.get("title") or f"{a['threat_type']}: {a['subject'] or a['id']}")[:200]
    priority = body.get("priority") or {"high": "High", "medium": "Medium"}.get(a["level"], "Low")
    if priority not in CASE_PRIORITIES:
        raise ApiError(400, "Invalid priority.")
    ts = dbm.now_iso()
    cur = db.execute("INSERT INTO cases (analysis_id, title, priority, created_at, updated_at) VALUES (?,?,?,?,?)",
                     (aid, title, priority, ts, ts))
    db.execute("UPDATE analyses SET status='Investigating' WHERE id=? AND status='New'", (aid,))
    db.commit()
    dbm.audit(db, "Created case", dbm.case_code(cur.lastrowid), "OK", _ip())
    return jsonify(_case_json(db, db.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone(), True)), 201


@bp.patch("/cases/<cid>")
def patch_case(cid):
    db = dbm.get_db()
    row = _case_row(db, cid)
    body = _json_body()
    status, priority = body.get("status", row["status"]), body.get("priority", row["priority"])
    if status not in CASE_STATUSES or priority not in CASE_PRIORITIES:
        raise ApiError(400, "Invalid status or priority.")
    db.execute("UPDATE cases SET status=?, priority=?, updated_at=? WHERE id=?", (status, priority, dbm.now_iso(), row["id"]))
    db.commit()
    dbm.audit(db, f"Updated case ({status}/{priority})", dbm.case_code(row["id"]), "OK", _ip())
    return jsonify(_case_json(db, db.execute("SELECT * FROM cases WHERE id=?", (row["id"],)).fetchone(), True))


@bp.post("/cases/<cid>/notes")
def add_note(cid):
    db = dbm.get_db()
    row = _case_row(db, cid)
    note = str(_json_body().get("note") or "").strip()
    if not note:
        raise ApiError(400, "Note cannot be empty.")
    if len(note) > 2000:
        raise ApiError(400, "Note is limited to 2000 characters.")
    db.execute("INSERT INTO case_notes (case_id, created_at, note) VALUES (?,?,?)", (row["id"], dbm.now_iso(), note))
    db.execute("UPDATE cases SET updated_at=? WHERE id=?", (dbm.now_iso(), row["id"]))
    db.commit()
    dbm.audit(db, "Added case note", dbm.case_code(row["id"]), "OK", _ip())
    return jsonify(_case_json(db, row, detail=True)), 201


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def _e(v) -> str:
    return html.escape(str(v if v is not None else "—"))


def render_report_html(res: dict, case: dict | None = None) -> str:
    rows = lambda pairs: "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in pairs)
    reasons = "".join(f"<li><b>{_e(r['title'])}</b> <span class='sev {_e(r['severity'])}'>{_e(r['severity'])}</span><br>"
                      f"{_e(r['detail'])}<br><i>{_e(r['why'])}</i></li>" for r in res["reasons"]) or "<li>None</li>"
    steps = "".join(f"<li>{_e(s)}</li>" for s in res["recommended_action"]["steps"])
    trace = "".join(f"<tr><td>{_e(t['label'])}</td><td>{_e(t['host'])}</td><td>{_e(t['ip'])}</td><td>{_e(t['reputation'])}</td></tr>" for t in res["trace"])
    urls = "".join(f"<tr><td>{_e(u['url'])}</td><td>{_e(', '.join(u['flags']) or 'No flags')}</td></tr>" for u in res["urls"]) or "<tr><td colspan=2>None</td></tr>"
    atts = "".join(f"<tr><td>{_e(a['name'])}</td><td>{_e(a['size'])} B</td><td>{_e(a['sha256'])}</td><td>{_e(', '.join(a['flags']) or '—')}</td></tr>" for a in res["attachments"]) or "<tr><td colspan=4>None</td></tr>"
    tl = "".join(f"<tr><td>{_e(t['t'])}</td><td>{_e(t['event'])}</td></tr>" for t in res["timeline"])
    ident = rows([(k.replace("_", " ").title(), v) for k, v in res["identity"].items()])
    auth = rows([(k.upper(), v) for k, v in res["auth"].items()])
    case_html = f"<p><b>Case:</b> {_e(case['id'])} — {_e(case['title'])} ({_e(case['status'])})</p>" if case else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Forensic Report {_e(res['id'])}</title>
<style>body{{font:14px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1e293b;max-width:860px;margin:30px auto;padding:0 20px}}
h1{{font-size:22px;margin:0}}h2{{font-size:15px;border-bottom:1px solid #e2e5ea;padding-bottom:4px;margin-top:26px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid #eef1f5;vertical-align:top;word-break:break-word}}
th{{width:170px;color:#64748b;font-weight:600}}.score{{font-size:34px;font-weight:700;color:{'#C0362C' if res['risk']['level']=='high' else '#B4650B' if res['risk']['level']=='medium' else '#127A4E'}}}
.sev{{font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b}}li{{margin-bottom:8px}}.muted{{color:#64748b;font-size:12px}}
@media print{{body{{margin:0}}}}</style></head><body>
<h1>SentinelTrace — Forensic Investigation Report</h1>
<p class="muted">Analysis {_e(res['id'])} · generated {_e(res['created_at'])} UTC · engine v{_e(res['engine']['version'])}</p>{case_html}
<div class="score">{res['risk']['score']}% — {_e(res['risk']['label'])} RISK</div>
<p><b>Threat type:</b> {_e(res['threat_type'])} · <b>Classification:</b> {_e(res['classification'])}</p>
<p><b>Recommended action:</b> {_e(res['recommended_action']['headline'])}</p><ol>{steps}</ol>
<h2>Why this email was flagged</h2><ul>{reasons}</ul>
<h2>Email identity</h2><table>{ident}</table>
<h2>Authentication</h2><table>{auth}</table>
<h2>SMTP trace</h2><table><tr><th>Hop</th><th>Host</th><th>IP</th><th>Reputation</th></tr>{trace}</table>
<p class="muted">{_e(res['origin']['note'])} Origin confidence: {res['origin']['confidence']}%.</p>
<h2>URLs</h2><table>{urls}</table>
<h2>Attachments</h2><table><tr><th>Name</th><th>Size</th><th>SHA-256</th><th>Flags</th></tr>{atts}</table>
<h2>Evidence integrity</h2><table>{rows([('SHA-256 (original .eml)', res['evidence']['sha256']), ('Size (bytes)', res['evidence']['size'])])}</table>
<h2>Processing timeline (UTC)</h2><table>{tl}</table>
<p class="muted">Origin confidence reflects the reliability of technical evidence, not the identity of a person. Automated analysis — verify before taking disciplinary or legal action.</p>
</body></html>"""


@bp.get("/analyses/<aid>/report")
def report(aid):
    db = dbm.get_db()
    row = _row_or_404(db, aid)
    res = _result_of(row)
    crow = db.execute("SELECT * FROM cases WHERE analysis_id=? ORDER BY id DESC LIMIT 1", (aid,)).fetchone()
    case = _case_json(db, crow) if crow else None
    fmt = request.args.get("format", "html")
    dbm.audit(db, f"Generated {fmt} report", aid, "OK", _ip())
    if fmt == "json":
        return Response(json.dumps({"analysis": res, "case": case}, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{aid}-report.json"'})
    if fmt != "html":
        raise ApiError(400, "format must be 'html' or 'json'.")
    return Response(render_report_html(res, case), mimetype="text/html")
