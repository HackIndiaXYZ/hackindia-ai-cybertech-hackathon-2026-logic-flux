"""SentinelTrace application factory."""
import logging
import os
import time

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db as dbm
from .analyzer import Intel, analyze
from .config import Config
from .demo import SEED_PLAN, demo_email
from .routes import ApiError, RateLimiter, bp

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")


def _seed(app: Flask):
    """Analyse sample emails through the real engine so a fresh deployment is not an empty dashboard."""
    conn = dbm.connect(app.config["DATABASE_PATH"])
    try:
        if conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] > 0:
            return
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        for kind, minutes_ago in SEED_PLAN:
            raw = demo_email(kind)
            res = analyze(raw, app.intel, app.config["GEOIP_DB"])
            ts = (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")
            res["status"] = {"high": "Investigating", "medium": "New", "low": "Resolved"}[res["risk"]["level"]]
            dbm.save_analysis(conn, res, raw, "seed", ts)
        dbm.audit(conn, "Seeded demo data", "system", "OK", "", actor="system")
        app.logger.info("Seeded %d demo analyses", len(SEED_PLAN))
    finally:
        conn.close()


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    logging.basicConfig(level=app.config["LOG_LEVEL"], format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if app.config["BEHIND_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.limiter = RateLimiter()
    app.intel = Intel.load(app.config["THREAT_INTEL_FILE"])
    dbm.init_db(app.config["DATABASE_PATH"])
    app.teardown_appcontext(dbm.close_db)
    app.register_blueprint(bp)

    if app.config["RETENTION_DAYS"]:
        conn = dbm.connect(app.config["DATABASE_PATH"])
        try:
            n = dbm.purge_old(conn, app.config["RETENTION_DAYS"])
            if n:
                app.logger.info("Retention purge removed %d analyses", n)
        finally:
            conn.close()
    if app.config["SEED_DEMO"]:
        try:
            _seed(app)
        except Exception:
            app.logger.exception("Demo seeding failed (continuing without it)")

    # ---- errors: always JSON, never a stack trace ------------------------- #
    @app.errorhandler(ApiError)
    def api_error(e):
        return jsonify(error=e.message), e.status

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith("/api/"):
            msg = {413: f"Upload exceeds {app.config['MAX_UPLOAD_MB']} MB.", 404: "Not found.", 405: "Method not allowed."}.get(e.code, e.description)
            return jsonify(error=msg), e.code
        return e

    @app.errorhandler(Exception)
    def unexpected(e):
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        return jsonify(error="Internal server error. The incident has been logged."), 500

    @app.after_request
    def secure(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        resp = send_from_directory(app.static_folder, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/healthz")
    def healthz():
        try:
            dbm.get_db().execute("SELECT 1").fetchone()
            return jsonify(status="ok")
        except Exception:
            return jsonify(status="degraded"), 503

    return app
