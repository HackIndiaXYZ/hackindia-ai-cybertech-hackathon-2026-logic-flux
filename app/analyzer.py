"""SentinelTrace analysis engine.

Pure-Python, offline, deterministic. It parses a raw RFC-5322 message and
produces an explainable verdict. No network calls are made, so analysis can
never hang or fail because an external service is down.

Scoring uses a noisy-OR over independent signals: score = 1 - prod(1 - w_i).
That keeps the score bounded in 0..100, makes every point of risk traceable to
a named signal, and prevents a pile of weak signals from overwhelming a clean
message.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email import message_from_bytes, policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("sentineltrace.analyzer")

ENGINE_VERSION = "1.0.0"
MAX_BODY_CHARS = 200_000
MAX_URLS = 50
MAX_HEADERS = 80

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #
BRANDS = {
    "paypal": ["paypal.com", "paypalobjects.com", "paypal.me"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "office365.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazon.de"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
    "icici": ["icicibank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "paytm": ["paytm.com"],
    "github": ["github.com"],
    "zoom": ["zoom.us"],
    "adobe": ["adobe.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
}

FREEMAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "proton.me",
    "protonmail.com", "icloud.com", "yandex.com", "mail.com", "gmx.com", "rediffmail.com", "yahoo.in",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "country", "gq", "tk", "ml", "cf", "support", "rest", "icu"}
DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf", "jar", "msi", "ps1", "lnk", "iso", "img", "hta", "dll", "reg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlam", "dotm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab"}
HTML_EXT = {"html", "htm", "shtml", "xhtml"}

URGENCY_RE = re.compile(
    r"\b(urgent(?:ly)?|immediately|asap|right away|within \d+ ?(?:hours|hrs|days)|final notice|last warning|act now|"
    r"expires? (?:today|soon)|as soon as possible|time[- ]sensitive|immediate action|"
    r"account will be (?:suspended|closed|locked|terminated)|failure to (?:respond|comply|pay))\b"
)
FINANCIAL_RE = re.compile(
    r"\b(wire transfer|bank transfer|payment|invoice|remittance|iban|swift code|routing number|account number|"
    r"gift cards?|bitcoin|crypto(?:currency)?|outstanding balance|overdue|beneficiary|bank details|purchase order|payroll)\b"
)
CREDENTIAL_RE = re.compile(
    r"\b(password|verify your (?:account|identity)|confirm your (?:identity|account)|log ?in|sign ?in|credentials|"
    r"security alert|unusual (?:activity|sign-in)|account (?:has been )?(?:suspended|locked|limited)|"
    r"otp|one[- ]time (?:code|password)|update your (?:account|payment|billing)|password (?:expir\w+|reset))\b"
)
SECRECY_RE = re.compile(
    r"\b(confidential|keep this between|do not discuss|don't tell|strictly between us|"
    r"i(?:'m| am) in a meeting|can(?:'|no)t take calls|are you available)\b"
)
EXEC_RE = re.compile(
    r"\b(ceo|cfo|coo|cto|chief|president|managing director|director|chairman|vice president|vp|founder|owner|head of)\b"
)
LOGIN_URL_RE = re.compile(r"(login|signin|verify|secure|account|update|confirm|wallet|password)", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]\}]{1,2000}", re.I)
EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

_HOMOGLYPH = str.maketrans({"0": "o", "3": "e", "5": "s", "$": "s", "@": "a"})


# --------------------------------------------------------------------------- #
# Threat intel (local indicator list; no network)
# --------------------------------------------------------------------------- #
class Intel:
    def __init__(self, domains=(), ips=(), urls=()):
        self.domains = {d.lower() for d in domains}
        self.ips = set(ips)
        self.urls = {u.lower() for u in urls}

    @classmethod
    def load(cls, path: str) -> "Intel":
        try:
            if path and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                return cls(data.get("domains", []), data.get("ips", []), data.get("urls", []))
        except Exception:  # corrupt file must never stop the app
            log.exception("Could not load threat intel file %s", path)
        return cls()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def base_domain(d: str) -> str:
    d = (d or "").lower().strip(".")
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    if labels[-2] in {"co", "com", "org", "net", "gov", "ac", "edu", "nic"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _tokens(domain: str) -> list[str]:
    labels = domain.lower().split(".")
    body = labels[:-1] or labels
    return [t for lab in body for t in lab.split("-") if t]


def _variants(tok: str) -> set[str]:
    t = tok.translate(_HOMOGLYPH).replace("rn", "m").replace("vv", "w")
    return {t.replace("1", "l"), t.replace("1", "i")}


def _is_official(domain: str, officials: list[str]) -> bool:
    return any(domain == o or domain.endswith("." + o) for o in officials)


def brand_lookalike(domain: str) -> dict | None:
    """Detect typosquats / homoglyphs / brand keywords in an unofficial domain."""
    domain = (domain or "").lower()
    if not domain:
        return None
    tokens = _tokens(domain)
    hits = []
    for brand, officials in BRANDS.items():
        if _is_official(domain, officials):
            continue
        for tok in tokens:
            if tok == brand:
                hits.append({"kind": "brand_keyword", "brand": brand, "similarity": 100, "token": tok, "rank": 1})
                continue
            if brand in _variants(tok):
                sim = round(SequenceMatcher(None, tok, brand).ratio() * 100)
                hits.append({"kind": "homoglyph", "brand": brand, "similarity": sim, "token": tok, "rank": 3})
            elif len(brand) >= 5 and abs(len(tok) - len(brand)) <= 1 and SequenceMatcher(None, tok, brand).ratio() >= 0.85:
                sim = round(SequenceMatcher(None, tok, brand).ratio() * 100)
                hits.append({"kind": "typosquat", "brand": brand, "similarity": sim, "token": tok, "rank": 3})
            elif len(brand) >= 5 and brand in tok:
                hits.append({"kind": "brand_keyword", "brand": brand, "similarity": 100, "token": tok, "rank": 1})
    if not hits:
        return None
    hits.sort(key=lambda h: (-h["rank"], -h["similarity"]))
    return hits[0]


def org_lookalike(sender_domain: str, rcpt_domain: str) -> dict | None:
    """Sender domain imitates the *recipient's own* organisation domain."""
    sb, rb = base_domain(sender_domain), base_domain(rcpt_domain)
    if not sb or not rb or sb == rb or rb in FREEMAIL:
        return None
    rlabel = rb.split(".")[0]
    if len(rlabel) < 4:
        return None
    for tok in _tokens(sender_domain):
        if tok == rlabel or rlabel in _variants(tok):
            return {"target": rb, "token": tok}
    return None


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hdr(msg, name: str) -> str:
    try:
        v = msg.get(name, "")
        return str(v) if v is not None else ""
    except Exception:
        return ""


def _addr(value: str) -> tuple[str, str]:
    name, addr = parseaddr(value or "")
    addr = addr.strip().lower()
    return name.strip(), addr


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1] if "@" in addr else ""


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._skip = 0
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._anchor).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def _decode_part(part) -> str:
    try:
        return part.get_content()
    except Exception:
        try:
            payload = part.get_payload(decode=True) or b""
            return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            return ""


def extract_body(msg) -> tuple[str, list[tuple[str, str]]]:
    texts: list[str] = []
    links: list[tuple[str, str]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if (part.get_content_disposition() or "") == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            texts.append(_decode_part(part))
        elif ctype == "text/html":
            raw = _decode_part(part)[:MAX_BODY_CHARS]
            p = _HTMLText()
            try:
                p.feed(raw)
                p.close()
            except Exception:
                pass
            texts.append(" ".join(p.text))
            links.extend(p.links)
    return ("\n".join(t for t in texts if t))[:MAX_BODY_CHARS], links


def parse_auth(msg) -> dict:
    res = {"spf": None, "dkim": None, "dmarc": None}
    for h in msg.get_all("Authentication-Results", []) or []:
        for k in res:
            m = re.search(rf"\b{k}\s*=\s*([a-z]+)", str(h), re.I)
            if m and res[k] is None:
                res[k] = m.group(1).lower()
    if res["spf"] is None:
        rs = _hdr(msg, "Received-SPF")
        m = re.match(r"\s*([a-zA-Z]+)", rs)
        if m:
            res["spf"] = m.group(1).lower()
    return {k: (v or "missing") for k, v in res.items()}


def _valid_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def parse_received(msg) -> list[dict]:
    hops = []
    for h in reversed(msg.get_all("Received", []) or []):  # oldest hop first
        text = " ".join(str(h).split())
        host_m = re.match(r"from\s+(\S+)", text, re.I)
        ip = None
        for cand in IPV4_RE.findall(text.split(" by ")[0] if " by " in text else text):
            addr = _valid_ip(cand)
            if addr is not None:
                ip = addr
                if addr.is_global:
                    break
        hops.append({
            "host": (host_m.group(1) if host_m else "unknown")[:120],
            "ip": str(ip) if ip else None,
            "public": bool(ip and ip.is_global),
        })
    return hops


def geo_lookup(ip: str, mmdb: str) -> dict:
    """Optional MaxMind lookup. Silent no-op unless GEOIP_DB is configured and geoip2 is installed."""
    if not mmdb or not ip:
        return {}
    try:
        import geoip2.database  # type: ignore
        with geoip2.database.Reader(mmdb) as r:
            rec = r.city(ip)
            return {"country": rec.country.name, "city": rec.city.name}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
class _Signals:
    def __init__(self):
        self.items: list[dict] = []
        self.tags: set[str] = set()

    def add(self, sid, title, severity, weight, detail, why, cats=None, tags=()):
        self.items.append({
            "id": sid, "title": title, "severity": severity, "weight": weight,
            "detail": detail, "why": why, "cats": cats or {"suspicious": 1.0},
        })
        self.tags.update(tags)


def _matches(rx: re.Pattern, text: str) -> list[str]:
    seen, out = set(), []
    for m in rx.finditer(text):
        w = m.group(0)
        if w not in seen:
            seen.add(w)
            out.append(w)
        if len(out) >= 8:
            break
    return out


def _analyze_url(url: str, anchor: str, intel: Intel, rcpt_base: str) -> dict:
    flags: list[str] = []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return {"url": url[:300], "host": "", "flags": ["malformed"], "anchor": anchor[:120]}
    if _valid_ip(host):
        flags.append("IP address as host")
    if host in SHORTENERS:
        flags.append("URL shortener")
    if "xn--" in host:
        flags.append("Punycode (possible homograph)")
    if "@" in (p.netloc or ""):
        flags.append("Credentials/@ trick in URL")
    if host.count(".") >= 4:
        flags.append("Excessive subdomains")
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flags.append("High-abuse TLD")
    if p.scheme == "http" and LOGIN_URL_RE.search(url):
        flags.append("Login-style link without HTTPS")
    look = brand_lookalike(host) if host and not _valid_ip(host) else None
    if look and look["kind"] != "brand_keyword":
        flags.append(f"Lookalike of {look['brand']}")
    try:
        for vals in parse_qs(p.query).values():
            if any(v.lower().startswith(("http://", "https://")) for v in vals):
                flags.append("Embedded redirect to another URL")
                break
    except ValueError:
        pass
    am = URL_RE.search(anchor or "") or re.search(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", (anchor or "").lower())
    if am and host:
        shown = urlparse(am.group(0)).hostname if am.group(0).lower().startswith("http") else am.group(1)
        if shown and base_domain(shown.lower()) != base_domain(host):
            flags.append(f"Link text shows {shown.lower()} but goes to {host}")
    if host in intel.domains or url.lower() in intel.urls or base_domain(host) in intel.domains:
        flags.append("Listed in local threat intel")
    return {"url": url[:300], "host": host, "flags": flags, "anchor": (anchor or "")[:120]}


def _analyze_attachment(part) -> dict:
    name = part.get_filename() or "unnamed"
    try:
        data = part.get_payload(decode=True) or b""
    except Exception:
        data = b""
    parts = name.lower().rsplit(".", 2)
    ext = parts[-1] if len(parts) > 1 else ""
    flags = []
    if ext in DANGEROUS_EXT:
        flags.append("Executable / script file")
    if ext in MACRO_EXT:
        flags.append("Macro-enabled Office file")
    if ext in HTML_EXT:
        flags.append("HTML attachment (common credential-harvest vector)")
    if ext in ARCHIVE_EXT:
        flags.append("Archive (contents not inspected)")
    if len(parts) == 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and ext in DANGEROUS_EXT | HTML_EXT:
        flags.append("Double extension disguise")
    return {
        "name": name[:200], "type": part.get_content_type(), "size": len(data),
        "sha256": _sha256(data), "flags": flags,
    }


def _distribute(parts: dict[str, float], total: int) -> dict[str, int]:
    """Largest-remainder rounding so the shares always sum to exactly `total`."""
    s = sum(parts.values())
    if s <= 0 or total <= 0:
        return {k: 0 for k in parts}
    raw = {k: v / s * total for k, v in parts.items()}
    out = {k: int(v) for k, v in raw.items()}
    for k in sorted(raw, key=lambda k: raw[k] - out[k], reverse=True)[: total - sum(out.values())]:
        out[k] += 1
    return out


def _analyze(raw: bytes, intel: Intel, geoip_db: str, pol) -> dict:
    t0 = time.perf_counter()
    started = datetime.now(timezone.utc)
    timeline: list[dict] = []

    def mark(event: str):
        timeline.append({"t": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3], "event": event})

    mark("Email received")
    warnings: list[str] = []
    msg = message_from_bytes(raw, policy=pol)
    mark("MIME structure parsed")

    from_name, from_addr = _addr(_hdr(msg, "From"))
    _, reply_addr = _addr(_hdr(msg, "Reply-To"))
    _, rpath_addr = _addr(_hdr(msg, "Return-Path"))
    _, rcpt_addr = _addr(_hdr(msg, "To").split(",")[0] if _hdr(msg, "To") else "")
    subject = _hdr(msg, "Subject")[:300]
    message_id = _hdr(msg, "Message-ID").strip("<> ")[:200]
    sender_dom = _domain_of(from_addr)
    reply_dom = _domain_of(reply_addr)
    rpath_dom = _domain_of(rpath_addr)
    rcpt_dom = _domain_of(rcpt_addr)
    if not from_addr:
        warnings.append("No parsable From header — input may be a body-only paste, so header checks were skipped.")

    body, html_links = extract_body(msg)
    text = f"{subject}\n{body}".lower()
    sig = _Signals()

    # ---- Authentication ------------------------------------------------- #
    auth = parse_auth(msg)
    mark("SPF / DKIM / DMARC evaluated")
    if auth["spf"] == "fail":
        sig.add("spf_fail", "SPF check failed", "high", 0.25,
                "SPF result: fail. The sending server is not authorised for this domain.",
                "SPF lets a domain list which servers may send its mail. A failure means the sender may be forged.",
                {"phishing": 1, "impersonation": 0.5})
    elif auth["spf"] == "softfail":
        sig.add("spf_softfail", "SPF soft-fail", "medium", 0.12,
                "SPF result: softfail.", "The domain owner says this server is probably not authorised.")
    if auth["dkim"] in {"fail", "neutral", "permerror"}:
        sig.add("dkim_fail", "DKIM signature invalid", "high" if auth["dkim"] == "fail" else "medium",
                0.2 if auth["dkim"] == "fail" else 0.1,
                f"DKIM result: {auth['dkim']}.",
                "DKIM proves a message was not altered and was signed by the claimed domain.")
    if auth["dmarc"] == "fail":
        sig.add("dmarc_fail", "DMARC authentication failed", "high", 0.3,
                "DMARC result: fail. The message could not be verified as coming from the claimed domain.",
                "DMARC ties SPF/DKIM to the visible From domain; failing it is a strong spoofing indicator.",
                {"phishing": 1, "impersonation": 0.7})
    if all(v == "missing" for v in auth.values()):
        sig.add("no_auth", "No authentication results in headers", "low", 0.04,
                "No Authentication-Results or Received-SPF header was found.",
                "Without them SPF/DKIM/DMARC cannot be confirmed. Only trust results added by your own mail gateway.")

    # ---- Sender identity ------------------------------------------------ #
    look = brand_lookalike(sender_dom)
    lookalike_info = None
    if look and look["kind"] in {"homoglyph", "typosquat"}:
        lookalike_info = look
        sig.add("lookalike_domain", "Lookalike domain detected", "high", 0.55,
                f"Sender domain '{sender_dom}' imitates {look['brand']} ('{look['token']}' vs '{look['brand']}', {look['similarity']}% similar).",
                "Attackers register near-identical domains with swapped characters so the address looks genuine at a glance.",
                {"phishing": 1, "impersonation": 1}, ("brand",))
    elif look:
        lookalike_info = look
        sig.add("brand_keyword_domain", "Brand name inside an unofficial domain", "medium", 0.28,
                f"Sender domain '{sender_dom}' contains '{look['brand']}' but is not an official {look['brand']} domain.",
                "Putting a brand in a domain (e.g. brand-support.com) is a common way to look legitimate.",
                {"phishing": 1, "impersonation": 0.6}, ("brand",))

    org = org_lookalike(sender_dom, rcpt_dom) if sender_dom and rcpt_dom else None
    if org:
        sig.add("org_lookalike", "Sender imitates your own organisation's domain", "high", 0.45,
                f"Sender domain '{sender_dom}' resembles the recipient's domain '{org['target']}' but is a different domain.",
                "Executives and colleagues are impersonated using domains that look like your own.",
                {"impersonation": 1, "bec": 0.8}, ("exec",))

    dn_lower = from_name.lower()
    brand_in_name = next((b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", dn_lower)), None)
    if brand_in_name and sender_dom and not _is_official(sender_dom, BRANDS[brand_in_name]):
        sig.add("display_name_brand", "Display name claims a brand the domain does not own", "high", 0.35,
                f"Display name '{from_name}' mentions {brand_in_name}, but the address is @{sender_dom}.",
                "Mail clients often show only the display name, so it is an easy thing to fake.",
                {"phishing": 1, "impersonation": 1}, ("brand",))

    em = EMAIL_IN_TEXT_RE.search(from_name)
    if em and sender_dom and base_domain(em.group(1).lower()) != base_domain(sender_dom):
        sig.add("display_name_spoof", "Display name shows a different email address", "high", 0.3,
                f"Display name contains an address on {em.group(1).lower()} while the real sender is @{sender_dom}.",
                "Embedding a trusted address in the display name tricks quick readers.", {"phishing": 1, "impersonation": 1})

    if EXEC_RE.search(dn_lower) and sender_dom:
        freemail = base_domain(sender_dom) in FREEMAIL
        if freemail or org or (rcpt_dom and base_domain(sender_dom) != base_domain(rcpt_dom)):
            strong = freemail or bool(org)
            sig.add("exec_impersonation", "Possible executive impersonation", "high" if strong else "medium",
                    0.32 if strong else 0.14,
                    f"Display name '{from_name}' uses a leadership title but the sender is "
                    + ("on a free-mail domain." if freemail else f"external ({sender_dom})."),
                    "Executive impersonation is the classic opening of Business Email Compromise (BEC).",
                    {"impersonation": 1, "bec": 1}, ("exec",))

    if reply_dom and sender_dom and base_domain(reply_dom) != base_domain(sender_dom):
        sig.add("reply_to_mismatch", "Reply-To differs from sender", "high", 0.25,
                f"Replies go to @{reply_dom}, not @{sender_dom}.",
                "Redirecting replies to an unrelated domain is a common way to capture a victim's response or divert payments.",
                {"phishing": 0.6, "bec": 1}, ("redirect",))

    if rpath_dom and sender_dom and base_domain(rpath_dom) != base_domain(sender_dom):
        sig.add("return_path_mismatch", "Return-Path domain differs from sender", "low", 0.05,
                f"Return-Path is @{rpath_dom}; From is @{sender_dom}.",
                "Often benign (mailing services) but can indicate forwarding or spoofing.")

    # ---- Language -------------------------------------------------------- #
    urg, fin = _matches(URGENCY_RE, text), _matches(FINANCIAL_RE, text)
    cred, sec = _matches(CREDENTIAL_RE, text), _matches(SECRECY_RE, text)
    mark("Language & intent analysis completed")
    if urg:
        sig.add("urgency", "Urgent / pressuring language", "medium", min(0.3, 0.12 + 0.06 * (len(urg) - 1)),
                "Phrases found: " + ", ".join(f"'{w}'" for w in urg[:5]) + ".",
                "Pressure to act immediately is used to stop recipients from verifying the request.",
                {"phishing": 0.6, "bec": 0.6}, ("urgent",))
    if fin:
        sig.add("financial", "Financial / payment request language", "medium", min(0.25, 0.1 + 0.05 * (len(fin) - 1)),
                "Phrases found: " + ", ".join(f"'{w}'" for w in fin[:5]) + ".",
                "Payment, invoice and bank-detail wording is typical of fraud and BEC.",
                {"bec": 1, "phishing": 0.3}, ("financial",))
    if urg and fin:
        sig.add("payment_pressure", "Urgency combined with a payment request", "high", 0.22,
                "Both pressure language and payment/invoice wording appear in the same message.",
                "This pairing is the strongest textual fingerprint of invoice and wire-transfer fraud.",
                {"bec": 1}, ("bec",))
    if cred:
        sig.add("credential_request", "Credential or account-verification request", "high", min(0.3, 0.12 + 0.06 * (len(cred) - 1)),
                "Phrases found: " + ", ".join(f"'{w}'" for w in cred[:5]) + ".",
                "Legitimate services rarely ask you to confirm passwords or identity by email.",
                {"phishing": 1}, ("credential",))
    if sec:
        sig.add("secrecy", "Secrecy / availability pressure", "medium", 0.18,
                "Phrases found: " + ", ".join(f"'{w}'" for w in sec[:4]) + ".",
                "Attackers ask for secrecy or claim to be unreachable so victims will not check by phone.",
                {"bec": 1, "impersonation": 0.6}, ("exec",))

    # ---- URLs ------------------------------------------------------------ #
    seen_urls: dict[str, str] = {}
    for href, anchor in html_links:
        if href.lower().startswith(("http://", "https://")):
            seen_urls.setdefault(href, anchor)
    for u in URL_RE.findall(body):
        seen_urls.setdefault(u.rstrip(".,;"), "")
    urls = [_analyze_url(u, a, intel, base_domain(rcpt_dom)) for u, a in list(seen_urls.items())[:MAX_URLS]]
    mark("URLs inspected")
    bad_urls = [u for u in urls if u["flags"]]
    if bad_urls:
        mismatch = any(f.startswith("Link text shows") for u in bad_urls for f in u["flags"])
        w = min(0.5, 0.3 + 0.08 * (len(bad_urls) - 1)) + (0.1 if mismatch else 0)
        top = bad_urls[0]
        sig.add("suspicious_url", "Suspicious link(s)", "high", min(0.55, w),
                f"{len(bad_urls)} of {len(urls)} link(s) flagged. Example: {top['host'] or top['url'][:60]} — {top['flags'][0]}.",
                "Deceptive links are how phishing steals credentials or delivers malware.",
                {"phishing": 1}, ("url",))

    # ---- Attachments ----------------------------------------------------- #
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_filename() or part.get_content_disposition() == "attachment":
            attachments.append(_analyze_attachment(part))
            if len(attachments) >= 25:
                break
    mark("Attachments hashed & inspected")
    for a in attachments:
        if "Executable / script file" in a["flags"] or "Double extension disguise" in a["flags"]:
            sig.add("bad_attachment", "Dangerous attachment", "high", 0.55,
                    f"'{a['name']}' — {', '.join(a['flags'])}.", "Executables and scripts delivered by email are a primary malware route.",
                    {"phishing": 1}, ("malware",))
            break
    else:
        for a in attachments:
            if "Macro-enabled Office file" in a["flags"] or any(f.startswith("HTML attachment") for f in a["flags"]):
                sig.add("risky_attachment", "Risky attachment type", "medium", 0.3,
                        f"'{a['name']}' — {', '.join(a['flags'])}.",
                        "Macro documents and HTML files are frequently used to run code or harvest credentials.",
                        {"phishing": 1}, ("malware",) if "Macro-enabled Office file" in a["flags"] else ("htmlattach",))
                break

    # ---- Routing / origin / intel --------------------------------------- #
    hops = parse_received(msg)
    xorig = _valid_ip(_hdr(msg, "X-Originating-IP").strip("[] "))
    intel_hits = []
    if sender_dom and (sender_dom in intel.domains or base_domain(sender_dom) in intel.domains):
        intel_hits.append({"type": "Domain", "value": sender_dom, "matches": 1})
    for h in hops:
        if h["ip"] and h["ip"] in intel.ips:
            intel_hits.append({"type": "IP", "value": h["ip"], "matches": 1})
    for u in urls:
        if "Listed in local threat intel" in u["flags"]:
            intel_hits.append({"type": "URL", "value": u["url"][:120], "matches": 1})
    mark("Threat-intelligence lookup completed")
    if intel_hits:
        sig.add("intel_match", "Matches local threat-intelligence indicators", "high", 0.5,
                "; ".join(f"{h['type']} {h['value']}" for h in intel_hits[:4]) + ".",
                "These indicators were previously reported as malicious in your own feed.",
                {"phishing": 1}, ("intel",))

    # ---- Score ----------------------------------------------------------- #
    prod = 1.0
    for s in sig.items:
        prod *= 1 - s["weight"]
    score = int(round(100 * (1 - prod)))
    level = "high" if score >= 70 else "medium" if score >= 35 else "low"

    cat_raw = {"suspicious": 0.0, "phishing": 0.0, "impersonation": 0.0, "bec": 0.0}
    for s in sig.items:
        for c, f in s["cats"].items():
            cat_raw[c] += s["weight"] * f
    risk_parts = _distribute(cat_raw, score)
    distribution = {"legitimate": 100 - score, **risk_parts}

    tags = sig.tags
    if level == "low":
        threat_type, classification, bucket = "Legitimate / Low Risk", "No significant threat indicators", "legitimate"
    else:
        if "malware" in tags and "credential" not in tags and "bec" not in tags:
            threat_type = "Malware Delivery"
        elif "exec" in tags and ("financial" in tags or "bec" in tags):
            threat_type = "Executive Impersonation / BEC"
        elif ("financial" in tags or "bec" in tags) and ("brand" in tags or "redirect" in tags):
            threat_type = "BEC / Phishing"
        elif "credential" in tags:
            threat_type = "Credential Phishing"
        elif "exec" in tags:
            threat_type = "Executive Impersonation"
        elif level == "high" and ("brand" in tags or "url" in tags):
            threat_type = "Phishing"
        else:
            threat_type = "Suspicious"
        parts = []
        if "brand" in tags or "exec" in tags:
            parts.append("Impersonation")
        if "financial" in tags or "bec" in tags:
            parts.append("Financial Fraud")
        if "credential" in tags:
            parts.append("Credential Harvesting")
        if "malware" in tags:
            parts.append("Malware Delivery")
        if "url" in tags and not parts:
            parts.append("Malicious Link")
        classification = " + ".join(parts) or "Anomalous message"
        if level == "medium":
            bucket = "suspicious"
        else:
            top = max(("phishing", "impersonation", "bec"), key=lambda c: cat_raw[c])
            bucket = top

    bec_inds = [
        ("Payment diversion", "redirect" in tags and "financial" in tags),
        ("Fake invoice / payment request", bool(fin) and any(w in text for w in ("invoice", "payment"))),
        ("Executive impersonation", "exec" in tags),
        ("Urgent financial request", bool(urg) and bool(fin)),
        ("Credential request", "credential" in tags),
    ]
    present = sum(1 for _, p in bec_inds if p)
    bec_conf = int(round(100 * (1 - 0.6 ** present))) if present else 0

    # ---- Recommended action --------------------------------------------- #
    if level == "high":
        steps = ["Do not click any links or open attachments.", "Do not reply or send any payment/information.",
                 "Mark as Phishing and report to your IT / security team.", "Quarantine or delete the message."]
        if "bec" in tags or "financial" in tags:
            steps.insert(2, "Verify any payment or bank-detail request by phoning a known number — not one from the email.")
        if "credential" in tags:
            steps.append("If you already entered credentials, change the password and enable MFA immediately.")
        headline = "Do not click links. Mark as Phishing & report to IT."
    elif level == "medium":
        headline = "Treat with caution — verify the sender before acting."
        steps = ["Do not open attachments or sign in through links in this email.",
                 "Confirm the request through a separate, trusted channel.", "Escalate to IT if anything feels off."]
    else:
        headline = "No action required — message looks legitimate."
        steps = ["No significant risk indicators were found. Stay alert for unexpected requests."]

    # ---- Trace / origin -------------------------------------------------- #
    trace = [{"label": "Claimed sender", "host": sender_dom or "unknown", "ip": None, "reputation": "Header-claimed", "risk": False}]
    for i, h in enumerate(hops, 1):
        rep = "No data"
        risky = False
        if h["ip"] and h["ip"] in intel.ips:
            rep, risky = "Listed in local threat intel", True
        elif h["ip"] and not h["public"]:
            rep = "Private / internal"
        trace.append({"label": f"Relay {i}", "host": h["host"], "ip": h["ip"], "reputation": rep, "risk": risky})
    trace.append({"label": "Recipient mailbox", "host": rcpt_dom or "unknown", "ip": None, "reputation": "Destination", "risk": False})

    first_public = next((h["ip"] for h in hops if h["public"]), None) or (str(xorig) if xorig and xorig.is_global else None)
    n_public = sum(1 for h in hops if h["public"])
    if first_public:
        oconf = min(85, 25 + 20 * n_public) if n_public else 30
        geo = geo_lookup(first_public, geoip_db)
        origin = {
            "ip": first_public,
            "country": geo.get("country") or "Unavailable (GeoIP database not configured)",
            "isp": "Unavailable (no ASN data)",
            "confidence": oconf,
            "level": "high" if oconf >= 75 else "medium" if oconf >= 45 else "low",
            "note": "Earliest public IP found in Received headers. Origin is probabilistic and may be masked by VPNs, proxies or relays.",
        }
    else:
        origin = {"ip": None, "country": "Unknown", "isp": "Unknown", "confidence": 0, "level": "low",
                  "note": "No public IP address could be extracted from the headers."}

    domain_info = {
        "name": sender_dom or "unknown",
        "base": base_domain(sender_dom),
        "lookalike": bool(lookalike_info and lookalike_info["kind"] != "brand_keyword"),
        "target": (BRANDS[lookalike_info["brand"]][0] if lookalike_info else (org["target"] if org else None)),
        "similarity": lookalike_info["similarity"] if lookalike_info else None,
        "age": "Not checked (engine runs offline; plug in a WHOIS/RDAP source)",
        "intel_matches": sum(1 for h in intel_hits if h["type"] == "Domain"),
    }

    intel_rows = [
        {"type": "Sender domain", "value": sender_dom or "—", "matches": sum(1 for h in intel_hits if h["type"] == "Domain")},
        {"type": "Origin IP", "value": origin["ip"] or "—", "matches": sum(1 for h in intel_hits if h["type"] == "IP")},
        {"type": "URLs", "value": f"{len(urls)} observed", "matches": sum(1 for h in intel_hits if h["type"] == "URL")},
        {"type": "Attachments", "value": f"{len(attachments)} hashed", "matches": 0},
    ]

    headers = []
    for k, v in list(msg.raw_items())[:MAX_HEADERS]:
        headers.append([str(k), " ".join(str(v).split())[:500]])

    mark("AI classification completed")
    if level == "high":
        mark("High-risk alert generated")
    created = started.isoformat(timespec="seconds")

    reasons = sorted(sig.items, key=lambda s: -s["weight"])
    for r in reasons:
        r.pop("cats", None)

    return {
        "id": "ST-" + uuid.uuid4().hex[:10].upper(),
        "created_at": created,
        "status": "New",
        "risk": {"score": score, "level": level, "label": level.upper()},
        "threat_type": threat_type,
        "classification": classification,
        "bucket": bucket,
        "distribution": distribution,
        "reasons": reasons,
        "recommended_action": {"headline": headline, "steps": steps},
        "identity": {
            "sender": from_addr or "—", "display_name": from_name or "—", "reply_to": reply_addr or "—",
            "return_path": rpath_addr or "—", "recipient": rcpt_addr or "—", "subject": subject or "—",
            "message_id": message_id or "—", "date": _hdr(msg, "Date")[:80] or "—",
        },
        "auth": auth,
        "headers": headers,
        "trace": trace,
        "origin": origin,
        "domain": domain_info,
        "bec": {"confidence": bec_conf, "indicators": [{"name": n, "present": p} for n, p in bec_inds]},
        "urls": urls,
        "attachments": attachments,
        "intel": intel_rows,
        "timeline": timeline,
        "evidence": {"sha256": _sha256(raw), "size": len(raw)},
        "warnings": warnings,
        "engine": {"version": ENGINE_VERSION, "duration_ms": int((time.perf_counter() - t0) * 1000)},
    }


class AnalysisError(Exception):
    """Input could not be analysed even by the lenient fallback parser."""


def analyze(raw: bytes, intel: Intel | None = None, geoip_db: str = "") -> dict:
    """Analyse a raw message. Never raises on malformed input.

    The modern email parser is strict about some malformed address headers and can raise inside the standard
    library. If that happens we retry with the lenient legacy policy, which returns headers as raw strings.
    """
    intel = intel or Intel()
    try:
        return _analyze(raw, intel, geoip_db, policy.default)
    except Exception:
        log.warning("Strict parse failed; retrying with lenient parser", exc_info=True)
    try:
        res = _analyze(raw, intel, geoip_db, policy.compat32)
        res["warnings"].append("Headers were malformed; a lenient parser was used, so some checks may be incomplete.")
        return res
    except Exception as exc:
        log.exception("Analysis failed with both parsers")
        raise AnalysisError("This input could not be parsed as an email message.") from exc
