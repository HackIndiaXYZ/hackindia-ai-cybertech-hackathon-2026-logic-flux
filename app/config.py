"""Environment-driven configuration. Every setting has a safe default."""
import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    VERSION = "1.0.0"
    DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join("data", "sentineltrace.db"))
    API_KEY = os.environ.get("API_KEY", "").strip()          # empty = open access
    MAX_UPLOAD_MB = max(1, _int("MAX_UPLOAD_MB", 10))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024 + 4096   # Flask hard limit
    RATE_LIMIT_PER_MIN = max(1, _int("RATE_LIMIT_PER_MIN", 30))
    SEED_DEMO = _bool("SEED_DEMO", True)                      # analyse sample emails on first run
    RETENTION_DAYS = max(0, _int("RETENTION_DAYS", 0))        # 0 = keep forever
    BEHIND_PROXY = _bool("BEHIND_PROXY", False)               # trust X-Forwarded-* (Render, Nginx...)
    THREAT_INTEL_FILE = os.environ.get("THREAT_INTEL_FILE", os.path.join("data", "threat_intel.json"))
    GEOIP_DB = os.environ.get("GEOIP_DB", "")                 # optional MaxMind .mmdb path
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
