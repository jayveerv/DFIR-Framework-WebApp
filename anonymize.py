"""Pseudonymised copies of case outputs, for sharing a report outside the investigation team.

Personal and account identifiers (user names, IP addresses, host names, e-mail addresses, AWS access-key ids and
account ids) are replaced by stable tokens such as  user-3f9a1c  /  ip-77b2e0. The same value always gets the same
token inside one case (so the attack story still reads correctly) but tokens come from a keyed hash (HMAC-SHA256
with a per-case secret), so they cannot be linked across cases or reversed without that secret.

A pseudonymised copy is for reading, not for evidence: its hashes differ from the originals, and the original,
hash-verified case bundle stays the record. Data minimisation in the sense of ISO/IEC 27037 and privacy laws such
as the GDPR (Art. 4(5), 32) and India's DPDP Act 2023.
"""
import hashlib
import hmac
import ipaddress
import json
import re

GENERIC = {"", "-", "system", "local service", "network service", "anonymous logon", "n/a", "none", "unknown", "root",
           "administrator", "guest", "nt authority", "localhost", "window manager", "dwm-1", "dwm-2", "umfd-0", "umfd-1"}
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
AKID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
ACCT = re.compile(r"(?<![\d])\d{12}(?![\d])")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _tok(secret, kind, value):
    return f"{kind}-{hmac.new(secret, f'{kind}:{value}'.encode(), hashlib.sha256).hexdigest()[:6]}"


def _keep_ip(v):
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return True
    return ip.is_loopback or ip.is_unspecified or ip.is_multicast


def build_map(events, secret):
    """value -> token for every identifier found in the normalised events."""
    m = {}

    def add(kind, v):
        v = (v or "").strip()
        if len(v) < 3 or v.lower() in GENERIC or v in m:
            return
        if kind == "ip" and _keep_ip(v):
            return
        m[v] = _tok(secret, kind, v)
    for e in events:
        u = e.get("user") or ""
        add("user", u)
        if "\\" in u:                                   # DOMAIN\user: also the bare user
            add("user", u.split("\\", 1)[1])
        add("ip", e.get("src_ip"))
        add("host", e.get("host"))
        blob = json.dumps(e, ensure_ascii=False)
        for v in IPV4.findall(blob):
            add("ip", v)
        for v in AKID.findall(blob):
            add("key", v)
        for v in ACCT.findall(blob):
            add("acct", v)
        for v in EMAIL.findall(blob):
            add("mail", v)
    return m


def apply(text, mapping):
    if not mapping:
        return text
    keys = sorted(mapping, key=len, reverse=True)
    pat = re.compile("|".join(r"(?<![\w.@-])" + re.escape(k) + r"(?![\w@-]|\.\d)" for k in keys))
    return pat.sub(lambda mo: mapping[mo.group(0)], text)


BANNER = ('<div style="background:#0B1A33;color:#FCD34D;border-bottom:3px solid #F59E0B;padding:10px 36px;font:600 13px Segoe UI,Arial,sans-serif;letter-spacing:.3px">'
          'PSEUDONYMISED COPY &mdash; user names, IP addresses, host names, account and key identifiers are replaced by keyed tokens. '
          'For reading only: the original, hash-verified case bundle remains the evidence.</div>')


def report_html(html, mapping):
    # replace only in text between tags, never inside markup, CSS or attribute names
    parts = re.split(r"(<[^>]*>)", html)
    style = False
    for i, p in enumerate(parts):
        if p.startswith("<"):
            style = p.lower().startswith("<style") or (style and not p.lower().startswith("</style"))
            continue
        if not style:
            parts[i] = apply(p, mapping)
    out = "".join(parts)
    return re.sub(r"(<body[^>]*>)", r"\1" + BANNER, out, count=1)
