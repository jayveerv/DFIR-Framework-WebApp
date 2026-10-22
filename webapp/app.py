"""CP-DFIR Investigation Console - web application for the Cross-Platform DFIR Framework.

The framework (pipeline.py, collect.py, normalize.py, correlate.py, custody.py, report.py, hostcollect.py,
cloudstate.py) is used unchanged. This file only adds a web interface on top of it:

  * analyst accounts (login, first-run setup, admin can add analysts)
  * cases: create, configure, delete
  * evidence intake: upload files / zip, live triage of this computer, AWS CloudTrail + account state,
    Linux auth log over SSH, Windows Security log export, simulated scenarios
  * analysis: runs pipeline.run_case() in a background job and shows the results live
  * chain of custody: HMAC-signed ledger, anchor hash kept OUTSIDE the case folder, one-click verification
  * report / exports, per-case activity log, framework self-test, evaluation results

Run:   python webapp/app.py            (opens http://127.0.0.1:5000)
       python webapp/app.py --host 0.0.0.0 --port 8080 --no-browser
Environment: DFIR_PUBLIC_MODE=1 disables collectors that read the server itself (for an online demo).
"""
import argparse
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
import webbrowser
import zipfile
from datetime import datetime, timezone
from functools import wraps

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from flask import Flask, abort, jsonify, request, send_file, send_from_directory, session  # noqa: E402
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402
from werkzeug.utils import secure_filename  # noqa: E402

import anonymize  # noqa: E402
import config as fw_config  # noqa: E402
import pipeline  # noqa: E402
from correlate import FLAGS, POSTURE, RULE_FAMILIES  # noqa: E402
from custody import CustodyLedger, sha256_file  # noqa: E402
from make_dashboard import TACTICS, TECH  # noqa: E402
from report import CLOUD_STATE_TYPES  # noqa: E402

APP_NAME = "CP-DFIR Investigation Console"
VERSION = "1.0"
DATA = os.path.abspath(os.environ.get("DFIR_DATA_DIR") or os.path.join(ROOT, "webapp_data"))
CASES = os.path.join(DATA, "cases")
TMP = os.path.join(DATA, "tmp")
PUBLIC_MODE = os.environ.get("DFIR_PUBLIC_MODE", "") not in ("", "0", "false", "no")
LARGE_CASE_MB = float(os.environ.get("DFIR_LARGE_CASE_MB", "20"))  # above this size the console warns that analysis will take longer
# "Try demo" guest login (no password, cannot manage users or delete cases). On by default in public mode.
GUEST = os.environ.get("DFIR_GUEST", "1" if PUBLIC_MODE else "0") not in ("", "0", "false", "no")
MAX_UPLOAD = int(os.environ.get("DFIR_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
# Privacy: in public mode each visitor sees only their own cases (plus the shared, read-only demo case), and
# visitor cases are deleted automatically after DFIR_RETENTION_HOURS. 0 disables automatic deletion.
RETENTION_H = float(os.environ.get("DFIR_RETENTION_HOURS", "24" if PUBLIC_MODE else "0") or 0)
for d in (DATA, CASES, TMP):
    os.makedirs(d, exist_ok=True)

# Durable storage for hosts with a temporary disk: mirror the data folder into PostgreSQL (see persist.py).
MIRROR = None
STORAGE_ERROR = None
if (os.environ.get("DATABASE_URL") or "").strip():
    try:
        from persist import Mirror
        MIRROR = Mirror("".join(os.environ["DATABASE_URL"].split()), DATA)   # tolerate line breaks pasted into the variable
        MIRROR.restore()
        MIRROR.start()
    except Exception as e:                       # never refuse to start: fall back to the local disk and say so
        MIRROR, STORAGE_ERROR = None, f"database storage unavailable ({type(e).__name__}): cases are kept on the local disk only"
        print("  Storage  " + STORAGE_ERROR)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def _secret_file(name, nbytes=32):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(secrets.token_hex(nbytes))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    with open(p) as f:
        return f.read().strip()


# The HMAC key signs every custody-ledger entry written by the web app. It lives in webapp_data/, outside every
# case folder, so somebody who can rewrite a case folder cannot forge a valid chain without it.
CUSTODY_KEY = (os.environ.get("DFIR_CUSTODY_KEY") or _secret_file("custody.key")).encode()
CUSTODY_KEY_PATH = os.path.join(DATA, "custody.key")

app = Flask(__name__, static_folder=os.path.join(HERE, "static"), static_url_path="/static")
app.config.update(SECRET_KEY=os.environ.get("DFIR_SESSION_KEY") or _secret_file("session.key"), MAX_CONTENT_LENGTH=MAX_UPLOAD,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", JSON_SORT_KEYS=False)

LOCK = threading.RLock()

# ============================================================== users / auth
USERS = os.path.join(DATA, "users.json")
AUDIT = os.path.join(DATA, "audit.jsonl")
ANCHORS = os.path.join(DATA, "anchors.json")
_fails = {}


def users():
    return _read_json(USERS, {}) or {}


def save_users(u):
    with LOCK:
        _write_json(USERS, u)


def audit(action, case=None, **details):
    rec = {"time": _now(), "user": session.get("user") if _in_request() else None, "ip": request.remote_addr if _in_request() else None,
           "action": action, "case": case, "details": details}
    with LOCK:
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        if case:
            with open(os.path.join(CASES, case, "activity.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")


def _in_request():
    try:
        request.method  # noqa: B018
        return True
    except RuntimeError:
        return False


def owner_id():
    """Who owns a case created in this session: the username, or guest:<id> for an anonymous visitor."""
    u = session.get("user")
    return f"guest:{session.get('gid', 'anon')}" if u == "guest" else u


def can_read(m):
    u = current_user() or {}
    if u.get("role") == "admin" or m.get("shared"):
        return True
    own = m.get("owner")
    if own is None:                                 # cases from before ownership existed: visible to signed-in analysts
        return u.get("role") != "guest"
    if not PUBLIC_MODE and u.get("role") == "analyst":
        return True                                 # one team on a private install: analysts see each other's cases
    return own == owner_id()


def can_write(m):
    u = current_user() or {}
    if u.get("role") == "admin":
        return True
    if m.get("shared"):
        return False                                # the demo case is read-only for everybody but administrators
    return can_read(m)


def current_user():
    u = session.get("user")
    if u == "guest" and GUEST:
        return {"name": "Guest", "role": "guest"}
    return users().get(u) if u else None


def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not current_user():
            return jsonify(error="login required"), 401
        if request.method not in ("GET", "HEAD") and request.headers.get("X-Requested-With") != "cpdfir":
            return jsonify(error="missing request header"), 400        # simple CSRF guard for the JSON API
        return fn(*a, **k)
    return w


def admin_required(fn):
    @wraps(fn)
    @login_required
    def w(*a, **k):
        if current_user().get("role") != "admin":
            return jsonify(error="administrator only"), 403
        return fn(*a, **k)
    return w


def _pw_ok(p):
    return isinstance(p, str) and len(p) >= 8


@app.get("/api/session")
def api_session():
    u = current_user()
    return jsonify(setup_needed=not users(), user=({"username": session["user"], "name": u["name"], "role": u["role"]} if u else None),
                   app=APP_NAME, version=VERSION, public_mode=PUBLIC_MODE, platform=sys.platform, guest=GUEST,
                   retention_hours=RETENTION_H)


@app.post("/api/guest")
def api_guest():
    if not GUEST:
        return jsonify(error="guest access is off"), 403
    session.clear()
    session["user"] = "guest"
    session["gid"] = secrets.token_hex(6)      # every visitor is a separate guest: cases are not shared between visitors
    audit("guest_login")
    return jsonify(ok=True)


@app.post("/api/setup")
def api_setup():
    if users():
        return jsonify(error="already set up"), 400
    d = request.get_json(force=True) or {}
    un = (d.get("username") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", un):
        return jsonify(error="username: 3-32 characters a-z 0-9 _ . -"), 400
    if not _pw_ok(d.get("password")):
        return jsonify(error="password must be at least 8 characters"), 400
    save_users({un: {"name": (d.get("name") or un).strip()[:60], "role": "admin", "pw": generate_password_hash(d["password"]), "created": _now()}})
    session.clear()
    session["user"] = un
    audit("setup", account=un)
    return jsonify(ok=True)


@app.post("/api/login")
def api_login():
    ip = request.remote_addr or "?"
    f = [t for t in _fails.get(ip, []) if time.time() - t < 300]
    _fails[ip] = f
    if len(f) >= 8:
        return jsonify(error="too many failed logins, wait 5 minutes"), 429
    d = request.get_json(force=True) or {}
    un = (d.get("username") or "").strip().lower()
    u = users().get(un)
    if not u or not check_password_hash(u["pw"], d.get("password") or ""):
        f.append(time.time())
        audit("login_failed", username=un)
        return jsonify(error="wrong username or password"), 401
    session.clear()
    session["user"] = un
    audit("login")
    return jsonify(ok=True)


@app.post("/api/logout")
def api_logout():
    if session.get("user"):
        audit("logout")
    session.clear()
    return jsonify(ok=True)


@app.post("/api/password")
@login_required
def api_password():
    d = request.get_json(force=True) or {}
    u = users()
    if session["user"] not in u:
        return jsonify(error="the guest account has no password"), 400
    me = u[session["user"]]
    if not check_password_hash(me["pw"], d.get("old") or ""):
        return jsonify(error="current password is wrong"), 400
    if not _pw_ok(d.get("new")):
        return jsonify(error="new password must be at least 8 characters"), 400
    me["pw"] = generate_password_hash(d["new"])
    save_users(u)
    audit("password_changed")
    return jsonify(ok=True)


@app.get("/api/users")
@admin_required
def api_users():
    return jsonify([{"username": k, "name": v["name"], "role": v["role"], "created": v.get("created")} for k, v in users().items()])


@app.post("/api/users")
@admin_required
def api_user_add():
    d = request.get_json(force=True) or {}
    un = (d.get("username") or "").strip().lower()
    u = users()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", un):
        return jsonify(error="username: 3-32 characters a-z 0-9 _ . -"), 400
    if un in u:
        return jsonify(error="user exists"), 400
    if not _pw_ok(d.get("password")):
        return jsonify(error="password must be at least 8 characters"), 400
    role = "admin" if d.get("role") == "admin" else "analyst"
    u[un] = {"name": (d.get("name") or un).strip()[:60], "role": role, "pw": generate_password_hash(d["password"]), "created": _now()}
    save_users(u)
    audit("user_added", account=un, role=role)
    return jsonify(ok=True)


@app.delete("/api/users/<un>")
@admin_required
def api_user_del(un):
    u = users()
    if un == session["user"]:
        return jsonify(error="you cannot remove yourself"), 400
    if un in u:
        del u[un]
        save_users(u)
        audit("user_removed", account=un)
    return jsonify(ok=True)


# ============================================================== cases
KINDS = {
    "windows_xml": "Windows event log (XML)", "windows_evtx": "Windows event log (EVTX)", "linux_auth": "Linux auth log",
    "cloudtrail": "AWS CloudTrail", "cloud_state": "AWS account state", "host_artifact": "Live host artifact",
}
KIND_SOURCE = {"windows_xml": "windows", "windows_evtx": "windows", "linux_auth": "linux", "cloudtrail": "aws",
               "cloud_state": "cloud", "host_artifact": "host"}
HOST_FILES = {"system.json", "connections.json", "processes.json", "accounts.json", "persistence.json", "files.json"}
CLOUD_FILES = {"trails.json", "iam_account.json", "iam_users.json", "iam_roles.json", "s3_buckets.json", "security_groups.json", "identity.json"}
SYSLOG_RE = re.compile(rb"(sshd|sudo|useradd|pam_unix|su\[|su:|passwd\[|login\[|CRON\[)", re.I)
CFG_KEYS = ("linux_timezone_offset", "linux_log_year", "internal_ranges", "credential_inventory", "privileged_source_allowlist")


def case_dir(cid):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", cid or ""):
        abort(404)
    d = os.path.join(CASES, cid)
    if not os.path.isdir(d):
        abort(404)
    if _in_request() and session.get("user"):
        m = _read_json(os.path.join(d, "case.json")) or {}
        if not can_read(m):
            abort(404)                              # do not even reveal that the case exists
    return d


def meta_path(cid):
    return os.path.join(case_dir(cid), "case.json")


def load_meta(cid):
    m = _read_json(meta_path(cid))
    if not m:
        abort(404)
    return m


def save_meta(m):
    with LOCK:
        _write_json(os.path.join(CASES, m["id"], "case.json"), m)


def _rmtree(path):
    def onerr(fn, p, _exc):                     # evidence originals are read-only (Windows refuses to delete them)
        os.chmod(p, 0o644)
        fn(p)
    shutil.rmtree(path, onerror=onerr)


def _new_case_id():
    year = datetime.now().year
    n = 1 + max([int(x.split("-")[-1]) for x in os.listdir(CASES) if re.fullmatch(rf"CASE-{year}-\d{{4}}", x)] or [0])
    return f"CASE-{year}-{n:04d}"


def _anchors():
    return _read_json(ANCHORS, {}) or {}


def _set_anchor(cid, head, by):
    with LOCK:
        a = _anchors()
        a.setdefault(cid, []).append({"head": head, "time": _now(), "by": by})
        _write_json(ANCHORS, a)


def _anchor(cid):
    a = _anchors().get(cid) or []
    return a[-1]["head"] if a else None


def _public_case(m):
    lr = m.get("last_run") or {}
    return {"id": m["id"], "title": m["title"], "description": m.get("description", ""), "created": m["created"],
            "created_by": m.get("created_by"), "status": m.get("status", "new"), "evidence": len(m.get("evidence", [])),
            "sources": sorted({KIND_SOURCE.get(e["kind"], e["kind"]) for e in m.get("evidence", [])}),
            "analyzed": lr.get("time"), "incidents": lr.get("incidents"), "alerts": lr.get("alerts"), "events": lr.get("events"),
            "high": lr.get("high"), "custody_ok": (m.get("last_verify") or {}).get("ok", lr.get("custody_ok")),
            "job": _job_for(m["id"]), "shared": bool(m.get("shared")), "writable": can_write(m) if _in_request() else True,
            "expires": _expires(m)}


def _expires(m):
    if not RETENTION_H or m.get("shared") or not str(m.get("owner") or "").startswith("guest:"):
        return None
    t = datetime.fromisoformat(m["created"].replace("Z", "+00:00")).timestamp() + RETENTION_H * 3600
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.get("/api/cases")
@login_required
def api_cases():
    out = []
    for cid in sorted(os.listdir(CASES), reverse=True):
        m = _read_json(os.path.join(CASES, cid, "case.json"))
        if m and can_read(m):
            out.append(_public_case(m))
    return jsonify(out)


def _clean_cfg(d, base=None):
    cfg = dict(base or {})
    if "linux_timezone_offset" in d:
        v = str(d["linux_timezone_offset"]).strip() or "+00:00"
        if not re.fullmatch(r"[+-]\d{2}:\d{2}", v):
            raise ValueError("time zone offset must look like +05:30")
        cfg["linux_timezone_offset"] = v
    if "linux_log_year" in d:
        y = int(d["linux_log_year"])
        if not 1990 <= y <= 2100:
            raise ValueError("log year out of range")
        cfg["linux_log_year"] = y
    import ipaddress
    for k in ("internal_ranges", "privileged_source_allowlist"):
        if k in d:
            v = d[k]
            items = [x.strip() for x in (v if isinstance(v, list) else re.split(r"[\s,]+", v or "")) if x.strip()]
            for x in items:
                ipaddress.ip_network(x, strict=False)
            cfg[k] = items
    if "credential_inventory" in d:
        v = d["credential_inventory"]
        if isinstance(v, str):
            inv = {}
            for line in v.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "=" not in line:
                    raise ValueError("credential inventory lines must be  host:/path = AKIA...")
                a, b = line.rsplit("=", 1)
                inv[a.strip()] = b.strip()
            v = inv
        cfg["credential_inventory"] = dict(v or {})
    return cfg


@app.post("/api/cases")
@login_required
def api_case_new():
    d = request.get_json(force=True) or {}
    title = (d.get("title") or "").strip()[:120]
    if not title:
        return jsonify(error="give the case a title"), 400
    try:
        cfg = _clean_cfg(d, {k: fw_config.DEFAULT_CASE[k] for k in CFG_KEYS})
    except ValueError as e:
        return jsonify(error=str(e)), 400
    with LOCK:
        cid = _new_case_id()
        d0 = os.path.join(CASES, cid)
        os.makedirs(os.path.join(d0, "uploads"))
        m = {"id": cid, "title": title, "description": (d.get("description") or "").strip()[:2000], "created": _now(),
             "created_by": session["user"], "owner": owner_id(), "status": "new", "config": cfg, "evidence": []}
        save_meta(m)
    audit("case_created", cid, title=title)
    job = None
    if d.get("sample") in SAMPLES:
        j = _start_job(cid, "sample", _job_sample, scenario=d["sample"], analyze=True)
        job = j.id if j else None
    return jsonify(id=cid, job=job)


@app.get("/api/cases/<cid>")
@login_required
def api_case(cid):
    m = load_meta(cid)
    pc = _public_case(m)
    pc.update(config=m["config"], evidence_items=m.get("evidence", []), last_run=m.get("last_run"), last_verify=m.get("last_verify"),
              collections=m.get("collections", []),
              anchor=_anchor(cid), anchors=_anchors().get(cid, []), kinds=KINDS)
    return jsonify(pc)


@app.patch("/api/cases/<cid>")
@login_required
def api_case_edit(cid):
    m = load_meta(cid)
    d = request.get_json(force=True) or {}
    try:
        new_cfg = _clean_cfg(d, m["config"])
    except ValueError as e:
        return jsonify(error=str(e)), 400
    changed = [k for k in CFG_KEYS if new_cfg.get(k) != m["config"].get(k)]
    m["config"] = new_cfg
    for k in ("title", "description"):
        if k in d and str(d[k]).strip():
            m[k] = str(d[k]).strip()[:2000 if k == "description" else 120]
    if changed and m.get("status") == "analyzed":
        m["status"] = "stale"
    save_meta(m)
    audit("case_updated", cid, config_changed=changed)
    return jsonify(ok=True)


@app.delete("/api/cases/<cid>")
@admin_required
def api_case_del(cid):
    d = case_dir(cid)
    if (request.get_json(silent=True) or {}).get("confirm") != cid:
        return jsonify(error="type the case id to confirm"), 400
    if _job_for(cid):
        return jsonify(error="a job is running for this case"), 409
    audit("case_deleted", None, case_id=cid)
    _rmtree(d)
    return jsonify(ok=True)


@app.get("/api/cases/<cid>/activity")
@login_required
def api_activity(cid):
    p = os.path.join(case_dir(cid), "activity.jsonl")
    out = []
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            out = [json.loads(x) for x in f if x.strip()]
    return jsonify(out[::-1])


# ============================================================== evidence intake
def classify(name, path, hint=None):
    """Decide what kind of evidence a file is (or None). hint = folder name inside a zip ('host'/'cloud')."""
    low = name.lower()
    with open(path, "rb") as f:
        head = f.read(1 << 20)
    if low.endswith(".evtx") or head.startswith(b"ElfFile\x00"):
        return "windows_evtx"
    if low == "case_config.json":
        return "case_config"
    if low in ("ground_truth.json",):
        return None
    if low.endswith(".json"):
        if hint == "host" and (low in HOST_FILES or low == "manifest.json"):
            return "host_artifact"
        if hint == "cloud" and (low in CLOUD_FILES or low == "manifest.json"):
            return "cloud_state"
        if b'"eventName"' in head or b'"Records"' in head:
            return "cloudtrail"
        if low in HOST_FILES:
            return "host_artifact"
        if low in CLOUD_FILES:
            return "cloud_state"
        return None
    text_like = b"\x00" not in head[:4096]
    if (low.endswith(".xml") or head.lstrip()[:1] == b"<") and b"<Event" in head:
        return "windows_xml"
    if text_like and (low in ("auth.log", "secure") or low.startswith(("auth.log", "secure")) or low.endswith((".log", ".txt")) or "." not in low):
        if SYSLOG_RE.search(head):
            return "linux_auth"
    return None


def _add_item(m, src_path, name, kind, origin, by, move=False):
    """Store one evidence file under uploads/ (never modified afterwards) and register it in the case."""
    iid = uuid.uuid4().hex[:12]
    rel = os.path.join("uploads", iid + "_" + (secure_filename(name) or "file"))
    dst = os.path.join(CASES, m["id"], rel)
    (shutil.move if move else shutil.copy2)(src_path, dst)
    try:
        os.chmod(dst, 0o444)        # evidence originals are kept read-only
    except OSError:
        pass
    item = {"id": iid, "name": name, "kind": kind, "path": rel, "sha256": sha256_file(dst), "size": os.path.getsize(dst),
            "origin": origin, "added_by": by, "added": _now()}
    m["evidence"].append(item)
    return item


def _ingest_file(m, path, name, origin, by, hint=None, override=None, report=None):
    """Classify and register one file. case_config.json is merged into the case settings instead."""
    report = report if report is not None else []
    kind = override or classify(name, path, hint)
    if kind == "case_config":
        try:
            d = _read_json(path, {}) or {}
            m["config"] = _clean_cfg({k: d[k] for k in CFG_KEYS if k in d}, m["config"])
            report.append({"name": name, "ok": True, "kind": "case_config", "note": "merged into case settings"})
        except (ValueError, TypeError) as e:
            report.append({"name": name, "ok": False, "note": f"case_config.json rejected: {e}"})
        return None
    if kind not in KINDS:
        report.append({"name": name, "ok": False, "note": "not a supported evidence type (skipped)"})
        return None
    h = sha256_file(path)
    dup = next((e for e in m["evidence"] if e["sha256"] == h and e["name"] == name), None)
    if dup:
        report.append({"name": name, "ok": True, "kind": "duplicate", "sha256": h, "note": "identical file already in this case (not added twice)"})
        return dup
    it = _add_item(m, path, name, kind, origin, by)
    report.append({"name": name, "ok": True, "kind": kind, "sha256": it["sha256"], "size": it["size"]})
    return it


def _ingest_zip(m, zpath, zname, by, report):
    total = 0
    with zipfile.ZipFile(zpath) as z, tempfile.TemporaryDirectory(dir=TMP) as td:
        # A CP-DFIR collector package carries cpdfir_manifest.json with the SHA-256 taken at collection time:
        # every file is re-hashed here and compared, so a change between collection and upload is visible.
        manifest, expect, checked = None, {}, {"verified": 0, "mismatch": [], "missing": [], "extra": []}
        if "cpdfir_manifest.json" in z.namelist():
            try:
                manifest = json.loads(z.read("cpdfir_manifest.json").decode("utf-8-sig"))
                expect = {f["path"]: f.get("sha256") for f in manifest.get("files", []) if f.get("path") != "cpdfir_manifest.json"}
            except (ValueError, KeyError, TypeError):
                report.append({"name": "cpdfir_manifest.json", "ok": False, "note": "collector manifest unreadable - integrity since collection NOT verified"})
        for zi in z.infolist():
            if zi.is_dir():
                continue
            parts = [p for p in re.split(r"[\\/]+", zi.filename) if p not in ("", ".", "..")]
            if not parts or parts[-1].startswith((".", "__MACOSX")) or "__MACOSX" in parts:
                continue
            total += zi.file_size
            if total > MAX_UPLOAD * 4:
                report.append({"name": zname, "ok": False, "note": "zip too large when extracted, stopped"})
                break
            out = os.path.join(td, uuid.uuid4().hex)
            with z.open(zi) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
            rel = "/".join(parts)
            if rel == "cpdfir_manifest.json":
                continue
            if manifest is not None:
                h = sha256_file(out)
                if rel not in expect:
                    checked["extra"].append(rel)
                elif expect[rel] != h:
                    checked["mismatch"].append(rel)
                else:
                    checked["verified"] += 1
            hint = parts[-2].lower() if len(parts) > 1 else None
            _ingest_file(m, out, parts[-1], f"zip:{zname}", by, hint=hint, report=report)
        if manifest is not None:
            seen = {"/".join(p for p in re.split(r"[\\/]+", zi.filename) if p) for zi in z.infolist()}
            checked["missing"] = sorted(k for k in expect if k not in seen)
            ok = not (checked["mismatch"] or checked["missing"] or checked["extra"])
            col = {"package": zname, "package_sha256": sha256_file(zpath), "collector": manifest.get("collector_version"),
                   "host": manifest.get("hostname"), "platform": manifest.get("platform"), "run_as": manifest.get("run_as"),
                   "admin": manifest.get("is_admin"), "collected_utc": manifest.get("finished_utc"), "limited": manifest.get("limited") or {},
                   "verified": checked["verified"], "mismatch": checked["mismatch"], "missing": checked["missing"], "extra": checked["extra"],
                   "integrity_ok": ok, "checked_at": _now()}
            m.setdefault("collections", []).append(col)
            note = (f"collector package from {col['host']}: {checked['verified']} file(s) match the SHA-256 taken at collection"
                    if ok else f"INTEGRITY PROBLEM since collection - changed: {checked['mismatch']}, missing: {checked['missing']}, added: {checked['extra']}")
            report.append({"name": "cpdfir_manifest.json", "ok": ok, "kind": "collector_manifest", "note": note})


@app.post("/api/cases/<cid>/evidence")
@login_required
def api_upload(cid):
    case_dir(cid)
    files = request.files.getlist("files")
    override = request.form.get("kind") or None
    if override and override not in KINDS:
        override = None
    if not files:
        return jsonify(error="no files"), 400
    report = []
    with LOCK:
        m = load_meta(cid)
        for f in files:
            name = os.path.basename(f.filename or "upload")
            with tempfile.NamedTemporaryFile(dir=TMP, delete=False) as t:
                f.save(t)
                tp = t.name
            try:
                if name.lower().endswith(".zip") and zipfile.is_zipfile(tp):
                    report.append({"name": name, "ok": True, "kind": "zip", "sha256": sha256_file(tp), "note": "zip archive, contents below"})
                    _ingest_zip(m, tp, name, session["user"], report)
                else:
                    _ingest_file(m, tp, name, "upload", session["user"], override=override, report=report)
            finally:
                if os.path.exists(tp):
                    os.remove(tp)
        big = [r for r in report if r.get("ok") and r.get("size", 0) > LARGE_CASE_MB * 1048576]
        for r in big:
            r["note"] = ((r.get("note") or "") + f" large file ({r['size'] / 1048576:.0f} MB): analysis will take longer"
                         + (" on the hosted console; for big cases run CP-DFIR locally" if PUBLIC_MODE else "")).strip()
        if any(r["ok"] for r in report) and m.get("status") == "analyzed":
            m["status"] = "stale"
        save_meta(m)
    audit("evidence_uploaded", cid, files=[{k: r.get(k) for k in ("name", "kind", "sha256", "ok", "note")} for r in report])
    return jsonify(report=report)


@app.delete("/api/cases/<cid>/evidence/<iid>")
@login_required
def api_evidence_del(cid, iid):
    with LOCK:
        m = load_meta(cid)
        it = next((x for x in m["evidence"] if x["id"] == iid), None)
        if not it:
            abort(404)
        p = os.path.join(CASES, cid, it["path"])
        if os.path.exists(p):
            os.chmod(p, 0o644)
            os.remove(p)
        m["evidence"].remove(it)
        if m.get("status") == "analyzed":
            m["status"] = "stale"
        save_meta(m)
    audit("evidence_removed", cid, name=it["name"], sha256=it["sha256"])
    return jsonify(ok=True)


@app.get("/api/cases/<cid>/evidence/<iid>/download")
@login_required
def api_evidence_get(cid, iid):
    m = load_meta(cid)
    it = next((x for x in m["evidence"] if x["id"] == iid), None)
    if not it:
        abort(404)
    return send_file(os.path.join(CASES, cid, it["path"]), as_attachment=True, download_name=it["name"])


def assemble(m, input_dir):
    """Build the framework's input folder from the stored evidence originals.
    One file of a kind is copied byte-for-byte; several files of the same kind are combined (text logs appended,
    CloudTrail records merged). The originals stay untouched in uploads/."""
    if os.path.isdir(input_dir):
        shutil.rmtree(input_dir)
    os.makedirs(input_dir)
    notes = []
    by = {}
    for it in m["evidence"]:
        by.setdefault(it["kind"], []).append(it)
    P = lambda it: os.path.join(CASES, m["id"], it["path"])  # noqa: E731
    for kind, fname in (("windows_xml", "windows_security.xml"), ("linux_auth", "auth.log")):
        items = by.get(kind, [])
        if len(items) == 1:
            shutil.copyfile(P(items[0]), os.path.join(input_dir, fname))
        elif items:
            with open(os.path.join(input_dir, fname), "wb") as out:
                for it in items:
                    with open(P(it), "rb") as f:
                        data = f.read()
                    out.write(data if data.endswith(b"\n") else data + b"\n")
            notes.append(f"{len(items)} {KINDS[kind]} files combined into {fname}")
    items = by.get("cloudtrail", [])
    if len(items) == 1:
        shutil.copyfile(P(items[0]), os.path.join(input_dir, "cloudtrail.json"))
    elif items:
        from normalize import _lenient_records
        recs = []
        for it in items:
            with open(P(it), encoding="utf-8-sig", errors="replace") as f:
                text = f.read()
            try:
                doc = json.loads(text)
                recs += doc.get("Records", [doc]) if isinstance(doc, dict) else doc
            except ValueError:
                recs += [r for r in _lenient_records(text) if isinstance(r, dict)]
        with open(os.path.join(input_dir, "cloudtrail.json"), "w", encoding="utf-8") as f:
            json.dump({"Records": recs}, f)
        notes.append(f"{len(items)} CloudTrail files merged ({len(recs)} records)")
    used = set()
    for it in by.get("windows_evtx", []):
        n = secure_filename(it["name"]) or "log.evtx"
        if not n.lower().endswith(".evtx"):
            n += ".evtx"
        base, k = n, 2
        while n.lower() in used:
            n = f"{base[:-5]}_{k}.evtx"
            k += 1
        used.add(n.lower())
        shutil.copyfile(P(it), os.path.join(input_dir, n))
    for kind, sub in (("host_artifact", "host"), ("cloud_state", "cloud")):
        items = by.get(kind, [])
        if items:
            os.makedirs(os.path.join(input_dir, sub), exist_ok=True)
            seen = {}
            for it in items:
                nm = os.path.basename(it["name"])
                if nm in seen:
                    notes.append(f"{sub}/{nm}: a later collection replaced an earlier one")
                seen[nm] = it
            for nm, it in seen.items():
                shutil.copyfile(P(it), os.path.join(input_dir, sub, nm))
    return notes


# ============================================================== background jobs
JOBS = {}


class Job:
    def __init__(self, cid, kind, user):
        self.id, self.case, self.kind, self.user = uuid.uuid4().hex[:10], cid, kind, user
        self.status, self.lines, self.started, self.ended, self.error, self.result = "running", [], _now(), None, None, None
        self.stage, self.pct, self.t0 = "starting", 0, time.time()

    def log(self, *a):
        msg = " ".join(str(x) for x in a)
        for line in msg.splitlines() or [""]:
            self.lines.append({"t": time.strftime("%H:%M:%S"), "m": line})
        del self.lines[:-600]

    def view(self, since=0):
        return {"id": self.id, "case": self.case, "kind": self.kind, "status": self.status, "started": self.started, "ended": self.ended,
                "error": self.error, "result": self.result, "lines": self.lines[since:], "n": len(self.lines),
                "stage": self.stage, "pct": self.pct, "elapsed": round(time.time() - self.t0, 1)}


def _job_for(cid):
    for j in JOBS.values():
        if j.case == cid and j.status == "running":
            return {"id": j.id, "kind": j.kind}
    return None


def _start_job(cid, kind, fn, **kw):
    if cid and _job_for(cid):
        return None
    j = Job(cid, kind, session.get("user"))
    user = users().get(session.get("user"), {})
    JOBS[j.id] = j

    def run():
        try:
            j.result = fn(j, cid, user, **kw)
            j.status = "done"
        except Exception as e:
            j.error = str(e) or type(e).__name__
            j.log("ERROR: " + j.error)
            j.log(traceback.format_exc().strip().splitlines()[-1])
            j.status = "failed"
        j.ended = _now()
        _audit_job(j, user)
        if MIRROR:
            MIRROR.request_sync()

    threading.Thread(target=run, daemon=True).start()
    return j


def _audit_job(j, user):
    rec = {"time": _now(), "user": j.user, "ip": None, "action": f"job_{j.kind}_{j.status}", "case": j.case,
           "details": {"job": j.id, "error": j.error, "result": j.result if isinstance(j.result, dict) else None}}
    with LOCK:
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        if j.case and os.path.isdir(os.path.join(CASES, j.case)):
            with open(os.path.join(CASES, j.case, "activity.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")


@app.get("/api/jobs/<jid>")
@login_required
def api_job(jid):
    j = JOBS.get(jid)
    if not j:
        abort(404)
    return jsonify(j.view(int(request.args.get("since", 0))))


def _job_analyze(j, cid, user, **_):
    with LOCK:
        m = load_meta(cid)
    if not m["evidence"]:
        raise RuntimeError("this case has no evidence yet: upload files or run a collector first")
    d = os.path.join(CASES, cid)
    inp, out = os.path.join(d, "input"), os.path.join(d, "case")
    j.log(f"Case {cid}: {len(m['evidence'])} evidence item(s)")
    j.log("[0/5] Assembling the evidence set from the stored originals ...")
    for n in assemble(m, inp):
        j.log("      " + n)
    cfg = dict(fw_config.DEFAULT_CASE, **m["config"])
    cfg["case_id"], cfg["investigator"] = cid, user.get("name") or ("Guest analyst" if j.user == "guest" else j.user)
    cfg["title"] = m.get("title", "")
    size = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(inp) for f in fs)
    j.log(f"      {size / 1048576:.1f} MB of evidence")
    if size > LARGE_CASE_MB * 1048576:
        j.log(f"NOTE: large case ({size / 1048576:.0f} MB). " + ("The hosted console has limited processor time, so this can take several "
              "minutes; for big cases run CP-DFIR on your own machine." if PUBLIC_MODE else "Parsing binary EVTX is the slowest step."))
    weights = {1: 5, 2: 60, 3: 20, 4: 10, 5: 5}
    def progress(no, name, state, info):
        done = sum(v for k, v in weights.items() if k < no)
        if state == "start":
            j.stage, j.pct = f"{no}/5 {name}", done
            j.log(f"[{no}/5] {name} ...")
        elif state == "file":
            i, tot = (int(x) for x in info.split()[0].split("/"))
            j.pct = done + int(weights[no] * i / max(tot, 1))
            j.log(f"      {info}")
        else:
            j.pct = done + weights[no]
            j.log(f"      done: {info}")
    ctx = pipeline.run_case(inp, out, cfg, key=CUSTODY_KEY, progress=progress)
    j.stage, j.pct = "5/5 Reporting", 100
    j.log("[5/5] Reporting      self-contained HTML report written")
    corr = ctx["corr"]
    t = ctx["timings"]
    j.log("")
    for s, st in ctx["stats"].items():
        j.log(f"  {s:<8} records {st.get('records_seen', 0):>7}  normalized {st.get('normalized', 0):>7}  errors {st.get('errors', 0)}")
    for msg in ctx["acquire_msgs"]:
        j.log("  " + msg)
    j.log(f"  events {len(ctx['events'])}, flagged {corr['alert_events']}, incidents {len(corr['incidents'])}")
    for inc in corr["incidents"]:
        j.log(f"    {inc['id']} [{inc['severity']}] {', '.join(inc['platforms'])}  {inc['event_count']} events")
    j.log(f"  chain of custody: {'VERIFIED' if ctx['custody_ok'] else 'FAILED'} (HMAC-signed)")
    j.log(f"  anchor hash {ctx['final_head_hash'][:16]}... stored outside the case folder")
    j.log("  stage times: " + ", ".join(f"{k} {v:.3f}s" for k, v in t.items()))
    _set_anchor(cid, ctx["final_head_hash"], j.user)
    high = sum(1 for i in corr["incidents"] if i["severity"] == "High")
    run = {"time": _now(), "by": j.user, "events": len(ctx["events"]), "alerts": corr["alert_events"], "incidents": len(corr["incidents"]),
           "high": high, "cross": sum(1 for i in corr["incidents"] if i.get("cross_platform")), "unlinked": len(corr["unlinked_alerts"]),
           "custody_ok": ctx["custody_ok"], "head": ctx["final_head_hash"], "timings": t, "stats": ctx["stats"],
           "acquired": ctx["acquired"], "messages": ctx["acquire_msgs"],
           "evidence_ids": [e["id"] for e in m["evidence"]]}
    with LOCK:
        m = load_meta(cid)
        m["last_run"], m["status"] = run, "analyzed"
        m.pop("last_verify", None)
        save_meta(m)
    _EV_CACHE.pop(cid, None)
    return {k: run[k] for k in ("events", "alerts", "incidents", "high", "custody_ok")}


def _import_dir(cid, src, origin, user, j):
    """Register every collected file from a collector output folder as evidence."""
    report = []
    with LOCK:
        m = load_meta(cid)
        for dp, _, fs in os.walk(src):
            for fn in sorted(fs):
                hint = os.path.basename(dp).lower() if dp != src else None
                _ingest_file(m, os.path.join(dp, fn), fn, origin, user, hint=hint, report=report)
        if m.get("status") == "analyzed":
            m["status"] = "stale"
        save_meta(m)
    ok = [r for r in report if r["ok"]]
    for r in report:
        j.log(("  + " if r["ok"] else "  - ") + r["name"] + (f"  [{KINDS.get(r.get('kind'), r.get('kind'))}]  sha256 {r['sha256'][:16]}..." if r.get("sha256") else f"  {r.get('note', '')}"))
    j.log(f"{len(ok)} evidence file(s) added to the case")
    return len(ok)


def _then_analyze(j, cid, user, analyze, n):
    if analyze and n:
        j.log("")
        j.log("Running the analysis ...")
        return _job_analyze(j, cid, user)
    return {"added": n}


def _job_sample(j, cid, user, scenario="S1", analyze=True, **_):
    import generate_data
    desc = SAMPLES.get(scenario)
    if not desc:
        raise RuntimeError("unknown scenario")
    with tempfile.TemporaryDirectory(dir=TMP) as td:
        j.log(f"Generating simulated evidence for scenario {scenario}: {desc}")
        generate_data.build(scenario.replace("_cloud", ""), td)
        if scenario.endswith("_cloud"):
            generate_data.cloud_state(td, True)
        n = _import_dir(cid, td, f"simulated:{scenario}", j.user, j)
    return _then_analyze(j, cid, user, analyze, n)


def _job_triage(j, cid, user, days=7, logs=True, analyze=True, **_):
    import socket
    import hostcollect
    with tempfile.TemporaryDirectory(dir=TMP) as td:
        j.log(f"Live triage of this computer ({socket.gethostname()}, {sys.platform}), read-only, order of volatility")
        man = hostcollect.collect_host(td, include_logs=logs, days=days, log=j.log)
        for v in (man.get("limited") or {}).values():
            j.log("  LIMIT: " + str(v))
        for e in (man.get("errors") or [])[:8]:
            j.log("  error: " + str(e))
        n = _import_dir(cid, td, f"triage:{socket.gethostname()}", j.user, j)
    with LOCK:
        m = load_meta(cid)
        m["config"]["linux_timezone_offset"] = hostcollect._local_offset()
        m["config"]["linux_log_year"] = datetime.now().year
        save_meta(m)
    j.log(f"Case time zone set to this computer's offset {hostcollect._local_offset()} for its local logs")
    return _then_analyze(j, cid, user, analyze, n)


def _job_aws(j, cid, user, access_key=None, secret_key=None, session_token=None, profile=None, region=None, days=7,
             state=True, all_regions=False, analyze=True, **_):
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 is not installed:  pip install boto3")
    import collect
    import cloudstate
    if access_key:
        sess = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token or None,
                             region_name=region or None)
    else:
        sess = boto3.Session(profile_name=profile or None, region_name=region or None)
    region = region or sess.region_name or "us-east-1"
    with tempfile.TemporaryDirectory(dir=TMP) as td:
        try:
            ident = sess.client("sts", region_name=region).get_caller_identity()
            j.log(f"AWS identity: {ident.get('Arn')} (account {ident.get('Account')})")
        except Exception as e:
            raise RuntimeError(f"AWS credentials not accepted: {e}")
        j.log(f"CloudTrail LookupEvents, last {days} day(s), region {region} (read-only, paced to the API limit) ...")
        try:
            _, n, calls = collect.collect_live_aws(td, days=days, region=region, client=sess.client("cloudtrail", region_name=region))
            j.log(f"  {n} CloudTrail events in {calls} API calls")
        except Exception as e:
            j.log(f"  CloudTrail failed: {e}")
        if state:
            j.log("Account state (IAM, access keys, MFA, S3, security groups, trails) ...")
            try:
                man = cloudstate.collect_cloud_state(td, region=region, session=sess, log=j.log, all_regions=all_regions)
                j.log(f"  {len(man['artifacts'])} files, {len(man['api_operations'])} read-only API operations, {len(man['errors'])} denied/failed calls")
            except Exception as e:
                j.log(f"  account state failed: {e}")
        n = _import_dir(cid, td, f"aws:{ident.get('Account')}:{region}", j.user, j)
    j.log("Credentials were used for this collection only and were not stored.")
    return _then_analyze(j, cid, user, analyze, n)


def _job_ssh(j, cid, user, host=None, username="ubuntu", port=22, path="/var/log/auth.log", sudo=True, key_text=None, analyze=True, **_):
    import collect
    if shutil.which("ssh") is None:
        raise RuntimeError("no ssh client found on this computer")
    with tempfile.TemporaryDirectory(dir=TMP) as td:
        kp = None
        if key_text:
            kp = os.path.join(td, "id_key")
            with open(kp, "w", newline="\n") as f:
                f.write(key_text.replace("\r\n", "\n").strip() + "\n")
            os.chmod(kp, 0o600)
        out = os.path.join(td, "out")
        j.log(f"ssh {username}@{host}:{port}  {'sudo ' if sudo else ''}cat {path}")
        collect.collect_linux_ssh(host, username, out, key=kp, path=path, use_sudo=sudo, port=int(port))
        n = _import_dir(cid, out, f"ssh:{username}@{host}", j.user, j)
    j.log("The private key was deleted after use.")
    return _then_analyze(j, cid, user, analyze, n)


def _job_winlog(j, cid, user, count=5000, analyze=True, **_):
    import collect
    with tempfile.TemporaryDirectory(dir=TMP) as td:
        j.log(f"wevtutil export of the Windows Security log (last {count} events, needs Administrator) ...")
        collect.collect_live_windows(td, int(count), "xml")
        n = _import_dir(cid, td, "windows-live", j.user, j)
    return _then_analyze(j, cid, user, analyze, n)


SAMPLES = {
    "S1": "Windows RDP brute force + Linux SSH compromise + AWS key abuse by one attacker IP",
    "S2": "Linux compromise and AWS abuse from a different IP, linked only through the stolen credential",
    "S3": "Two separate incidents on two hosts and one AWS account",
    "S4": "Benign activity only (false-positive check)",
    "S5": "Hard cases: shared session and an insider without brute force",
    "S1_cloud": "Scenario S1 plus an exposed AWS account state (posture findings)",
}


@app.get("/api/samples")
@login_required
def api_samples():
    return jsonify(SAMPLES)


def _public_host_check(host):
    """Hosted console: SSH only to public Internet addresses (no internal, loopback or cloud-metadata targets)."""
    import ipaddress
    import socket
    host = (host or "").strip()
    if not host:
        return "give the SSH host"
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, 22)}
    except OSError:
        return "the SSH host name could not be resolved"
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not ip.is_global:
            return f"{host} resolves to a private/internal address ({a}); the hosted console only connects to public hosts"
    return None


@app.post("/api/cases/<cid>/jobs/<kind>")
@login_required
def api_job_start(cid, kind):
    case_dir(cid)
    d = request.get_json(silent=True) or {}
    fns = {"analyze": _job_analyze, "sample": _job_sample, "triage": _job_triage, "aws": _job_aws, "ssh": _job_ssh, "winlog": _job_winlog}
    if kind not in fns:
        abort(404)
    if PUBLIC_MODE and kind in ("triage", "winlog"):
        return jsonify(error="not available on the hosted console: it would collect the server, not your computer - "
                             "use the downloadable collector (Evidence page) and upload its zip"), 403
    if PUBLIC_MODE and kind == "ssh":
        err = _public_host_check(d.get("host"))
        if err:
            return jsonify(error=err), 400
    if kind == "winlog" and sys.platform != "win32":
        return jsonify(error="Windows Security log export only works when the console runs on Windows"), 400
    if kind == "ssh" and not (d.get("host") or "").strip():
        return jsonify(error="give the SSH host"), 400
    kw = {k: v for k, v in d.items() if k in ("scenario", "analyze", "days", "logs", "access_key", "secret_key", "session_token", "profile",
                                               "region", "state", "all_regions", "host", "username", "port", "path", "sudo", "key_text", "count")}
    j = _start_job(cid, kind, fns[kind], **kw)
    if not j:
        return jsonify(error="another job is already running for this case"), 409
    safe = {k: v for k, v in kw.items() if k not in ("secret_key", "session_token", "key_text")}
    if "access_key" in safe and safe["access_key"]:
        safe["access_key"] = safe["access_key"][:4] + "..." + safe["access_key"][-4:]
    audit(f"job_{kind}_started", cid, job=j.id, options=safe)
    return jsonify(job=j.id)


# ============================================================== results
_EV_CACHE = {}


def _events(cid):
    p = os.path.join(CASES, cid, "case", "normalized_events.json")
    if not os.path.exists(p):
        return []
    mt = os.path.getmtime(p)
    c = _EV_CACHE.get(cid)
    if not c or c[0] != mt:
        with open(p, encoding="utf-8") as f:
            evs = json.load(f)
        c = (mt, evs, {e["event_id"]: e for e in evs})
        _EV_CACHE[cid] = c
    return c


def _row(e):
    return {"id": e["event_id"], "t": e["time_utc"], "e": e["epoch"], "s": e["source"], "h": e.get("host") or "", "ty": e["event_type"],
            "u": e.get("user") or "", "ip": e.get("src_ip") or "", "tg": str(e.get("target") or e.get("detail") or "")[:140],
            "f": e.get("flags") or [], "sv": e.get("severity") or "info", "i": e.get("incident") or "",
            "src": f"{e.get('source_file')}:{e.get('line_ref')}"}


def _tech(tid):
    return {"id": tid, "tactic": TECH.get(tid, ("Other", tid))[0], "name": TECH.get(tid, ("", tid))[1]}


@app.get("/api/cases/<cid>/results")
@login_required
def api_results(cid):
    m = load_meta(cid)
    d = os.path.join(CASES, cid, "case")
    inc = _read_json(os.path.join(d, "incidents.json"))
    if not inc or not m.get("last_run"):
        return jsonify(ready=False)
    c = _events(cid)
    evs, by = (c[1], c[2]) if c else ([], {})
    incidents = []
    for i in inc["incidents"]:
        ids = [x for x in i["event_ids"] if x in by]
        incidents.append({
            "id": i["id"], "severity": i["severity"], "start": i["start"], "end": i["end"], "platforms": i["platforms"],
            "cross": i.get("cross_platform"), "count": i["event_count"], "alerts": i["alert_count"],
            "techniques": [_tech(t) for t in i["techniques"]], "entities": i["entities"], "links": i["links"],
            "stages": [{k: s.get(k) for k in ("flag", "technique", "name", "severity", "count", "first", "last", "sources", "hosts", "posture")} for s in i["stages"]],
            "events": [_row(by[x]) for x in ids[:2500]], "events_total": len(ids)})
    unlinked = [_row(by[x]) for x in inc["unlinked_alerts"][:1000] if x in by]
    fired = []
    for rule, n in sorted(inc["rules_fired"].items(), key=lambda x: -x[1]):
        tid, name, sev = FLAGS.get(rule, ("?", rule, "info"))
        fired.append({"rule": rule, "count": n, "name": name, "severity": sev, "posture": rule in POSTURE, **{"tech": _tech(tid)}})
    fam_of = {}
    for fam, rules in RULE_FAMILIES.items():
        for r in rules:
            fam_of.setdefault(r, []).append(fam)
    techs = {}
    for rule, (tid, name, sev) in FLAGS.items():
        t = techs.setdefault(tid, dict(_tech(tid), rules=[], hits=0))
        n = inc["rules_fired"].get(rule, 0)
        t["rules"].append({"rule": rule, "desc": name, "sev": sev, "hits": n, "fam": fam_of.get(rule, [])})
        t["hits"] += n
    posture = [dict(_row(e), why=[FLAGS[f][1] for f in e.get("flags", []) if f in POSTURE]) for e in evs
               if any(f in POSTURE for f in (e.get("flags") or []))]
    cloud_inv = [_row(e) for e in evs if e["event_type"] in CLOUD_STATE_TYPES][:500]
    sev_counts, plat_flag, ips = {}, {}, {}
    for e in evs:
        if e.get("flags"):
            sev_counts[e.get("severity") or "info"] = sev_counts.get(e.get("severity") or "info", 0) + 1
            plat_flag[e["source"]] = plat_flag.get(e["source"], 0) + 1
            ip = e.get("src_ip")
            if ip and not fw_config.is_internal(ip, m["config"]):
                ips[ip] = ips.get(ip, 0) + 1
    hourly = {}
    for e in evs:
        if e.get("flags"):
            k = e["time_utc"][:13]
            hourly[k] = hourly.get(k, 0) + 1
    ledger = []
    lp = os.path.join(d, "custody_ledger.jsonl")
    if os.path.exists(lp):
        with open(lp, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    x = json.loads(line)
                    ledger.append({"seq": x.get("seq"), "stage": x.get("stage"), "action": x.get("action"), "target": x.get("target"),
                                   "time": x.get("time_utc"), "actor": x.get("actor"), "sha": x.get("sha256") or "", "prev": x.get("prev_hash"),
                                   "hash": x.get("entry_hash"), "hmac": bool(x.get("hmac")), "details": x.get("details")})
    return jsonify(ready=True, run=m["last_run"], incidents=incidents, unlinked=unlinked, fired=fired, techs=list(techs.values()),
                   tactics=TACTICS, posture=posture, cloud_inventory=cloud_inv, sev=sev_counts, plat_flag=plat_flag,
                   top_ips=sorted(ips.items(), key=lambda x: -x[1])[:10], hourly=sorted(hourly.items()), ledger=ledger,
                   anchor=_anchor(cid), stale=m.get("status") == "stale", total_rules=len(FLAGS))


@app.get("/api/cases/<cid>/events")
@login_required
def api_events(cid):
    case_dir(cid)
    c = _events(cid)
    evs = c[1] if c else []
    q = (request.args.get("q") or "").lower().strip()
    src = request.args.get("source") or ""
    flagged = request.args.get("flagged") == "1"
    inc = request.args.get("incident") or ""
    page, size = max(0, int(request.args.get("page", 0))), min(500, max(10, int(request.args.get("size", 100))))
    out = []
    for e in evs:
        if src and e["source"] != src:
            continue
        if flagged and not e.get("flags"):
            continue
        if inc and e.get("incident") != inc:
            continue
        if q:
            hay = " ".join(str(e.get(k) or "") for k in ("event_id", "time_utc", "host", "event_type", "user", "src_ip", "target", "detail",
                                                          "key_id", "raw")) + " " + " ".join(e.get("flags") or [])
            if q not in hay.lower():
                continue
        out.append(e)
    return jsonify(total=len(out), page=page, size=size, rows=[_row(e) for e in out[page * size:(page + 1) * size]],
                   sources=sorted({e["source"] for e in evs}))


@app.get("/api/cases/<cid>/events/<eid>")
@login_required
def api_event(cid, eid):
    case_dir(cid)
    c = _events(cid)
    e = c[2].get(eid) if c else None
    if not e:
        abort(404)
    e = dict(e)
    try:
        e["excerpt"] = _excerpt(os.path.join(CASES, cid, "case", "evidence"), e)
    except Exception:
        e["excerpt"] = None
    return jsonify(e)


def _excerpt(ev_dir, e):
    """The original record behind a normalised event, read from the acquired evidence copy."""
    sf, n = e.get("source_file"), e.get("line_ref")
    if not sf or not n:
        return None
    p = os.path.join(ev_dir, sf)
    if not os.path.abspath(p).startswith(os.path.abspath(ev_dir)) or not os.path.exists(p):
        return None
    n = int(n)
    if e["source"] == "linux":
        with open(p, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if i == n:
                    return f"{sf} line {n}:\n{line.rstrip()}"
    elif e["source"] == "windows":
        from normalize import _windows_chunks
        for i, ch in enumerate(_windows_chunks(p), 1):
            if i == n:
                import xml.dom.minidom
                try:
                    ch = xml.dom.minidom.parseString(ch).toprettyxml(indent="  ").split("\n", 1)[1]
                except Exception:
                    pass
                return f"{sf} record {n}:\n{ch[:6000]}"
    elif e["source"] == "aws" and not sf.startswith(("cloud/", "host/")):
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
        try:
            doc = json.loads(text)
            recs = doc.get("Records", [doc]) if isinstance(doc, dict) else doc
        except ValueError:
            from normalize import _lenient_records
            recs = _lenient_records(text)
        if 0 < n <= len(recs):
            return f"{sf} record {n}:\n" + json.dumps(recs[n - 1], indent=1)[:6000]
    elif sf.startswith(("cloud/", "host/")):
        d = _read_json(p, {})
        items = d.get("items") if isinstance(d, dict) else None
        if isinstance(items, list) and 0 < n <= len(items):
            return f"{sf} item {n}:\n" + json.dumps(items[n - 1], indent=1)[:6000]
        return f"{sf}:\n" + json.dumps(d, indent=1)[:3000]
    return None


@app.post("/api/cases/<cid>/verify")
@login_required
def api_verify(cid):
    d = case_dir(cid)
    lp = os.path.join(d, "case", "custody_ledger.jsonl")
    if not os.path.exists(lp):
        return jsonify(error="analyse the case first"), 400
    anchor = _anchor(cid)
    ok, checks = CustodyLedger(lp).verify(anchor, CUSTODY_KEY)
    res = {"ok": ok, "time": _now(), "by": session["user"], "anchor": anchor, "hmac": True, "checks": checks,
           "entries": sum(1 for c in checks if c["type"] == "ledger"), "files": sum(1 for c in checks if c["type"] == "file"),
           "failed": [c for c in checks if not c["ok"]]}
    with LOCK:
        m = load_meta(cid)
        m["last_verify"] = {k: res[k] for k in ("ok", "time", "by", "entries", "files")}
        save_meta(m)
    audit("custody_verified", cid, ok=ok, failed=[c["item"] for c in res["failed"]])
    return jsonify(res)


@app.post("/api/cases/<cid>/tamper")
@login_required
def api_tamper(cid):
    """Tamper-detection check: really change a file inside the analysed case (and restore it) to show verification
    catching it. The change is made to the working copy in case/evidence or the ledger, never to the originals."""
    d = case_dir(cid)
    act = (request.get_json(force=True) or {}).get("action")
    ev = os.path.join(d, "case", "evidence")
    lp = os.path.join(d, "case", "custody_ledger.jsonl")
    bk = os.path.join(DATA, "tamper_backup", cid)
    if not os.path.exists(lp):
        return jsonify(error="analyse the case first"), 400
    if act in ("evidence", "ledger"):
        if os.path.isdir(bk):
            return jsonify(error="a tamper check is already active: restore first"), 400
        os.makedirs(bk)
        if act == "evidence":
            files = [os.path.join(dp, f) for dp, _, fs in os.walk(ev) for f in fs]
            if not files:
                shutil.rmtree(bk)
                return jsonify(error="no evidence files"), 400
            target = sorted(files, key=lambda p: (not p.endswith("auth.log"), p))[0]
            rel = os.path.relpath(target, os.path.join(d, "case"))
            shutil.copy2(target, os.path.join(bk, "file"))
            with open(target, "ab") as f:
                f.write(b"\n# one line appended by the CP-DFIR tamper check\n")
            what = f"appended one line to {rel}"
        else:
            rel = "custody_ledger.jsonl"
            shutil.copy2(lp, os.path.join(bk, "file"))
            with open(lp, encoding="utf-8") as f:
                lines = f.readlines()
            e = json.loads(lines[0])
            e["actor"] = "someone else"
            lines[0] = json.dumps(e) + "\n"
            with open(lp, "w", encoding="utf-8") as f:
                f.writelines(lines)
            what = "changed the actor of ledger entry 1"
        _write_json(os.path.join(bk, "info.json"), {"rel": rel, "what": what})
        audit("tamper_demo", cid, change=what)
        return jsonify(ok=True, what=what)
    if act == "restore":
        info = _read_json(os.path.join(bk, "info.json"))
        if not info:
            return jsonify(error="nothing to restore"), 400
        shutil.copy2(os.path.join(bk, "file"), os.path.join(d, "case", info["rel"]))
        shutil.rmtree(bk)
        audit("tamper_demo_restored", cid, file=info["rel"])
        return jsonify(ok=True, what=f"restored {info['rel']}")
    if act == "status":
        info = _read_json(os.path.join(bk, "info.json"))
        return jsonify(active=bool(info), what=(info or {}).get("what"))
    abort(400)


@app.get("/api/cases/<cid>/file/<what>")
@login_required
def api_case_file(cid, what):
    d = os.path.join(case_dir(cid), "case")
    files = {"report": "report.html", "timeline": "timeline.csv", "events": "normalized_events.json", "incidents": "incidents.json",
             "ledger": "custody_ledger.jsonl"}
    if what not in files or not os.path.exists(os.path.join(d, files[what])):
        abort(404)
    dl = request.args.get("download") == "1"
    if request.args.get("anon") == "1":
        if what == "ledger":
            return jsonify(error="the custody ledger is not pseudonymised: it is the integrity record of the original evidence"), 400
        mp = _anon_map(cid)
        with open(os.path.join(d, files[what]), encoding="utf-8") as f:
            txt = f.read()
        out = anonymize.report_html(txt, mp) if what == "report" else anonymize.apply(txt, mp)
        audit("export", cid, file=files[what], pseudonymised=True, identifiers=len(mp))
        name = f"{cid}_PSEUDONYMISED_{files[what]}"
        mt = {"report": "text/html", "timeline": "text/csv"}.get(what, "application/json")
        return send_file(io.BytesIO(out.encode("utf-8")), as_attachment=dl, download_name=name, mimetype=mt)
    if what != "report" or dl:
        audit("export", cid, file=files[what])
    return send_file(os.path.join(d, files[what]), as_attachment=dl, download_name=f"{cid}_{files[what]}")


def _anon_map(cid):
    """Per-case secret (kept in case.json) so tokens are stable inside the case and unlinkable across cases."""
    with LOCK:
        m = load_meta(cid)
        if not m.get("anon_secret"):
            m["anon_secret"] = secrets.token_hex(16)
            save_meta(m)
    return anonymize.build_map(_events(cid)[1] if _events(cid) else [], bytes.fromhex(m["anon_secret"]))


@app.get("/api/cases/<cid>/bundle")
@login_required
def api_bundle(cid):
    """Zip of the analysed case (evidence copies, ledger, outputs, report) plus the anchor hash, for hand-over."""
    d = os.path.join(case_dir(cid), "case")
    if not os.path.isdir(d):
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for dp, _, fs in os.walk(d):
            for f in fs:
                p = os.path.join(dp, f)
                z.write(p, os.path.join(cid, os.path.relpath(p, d)))
        z.writestr(f"{cid}/ANCHOR_HASH.txt", f"Ledger anchor hash (kept outside the case folder by the console):\n{_anchor(cid)}\n"
                   "Verify with:  python main.py verify --case <folder> --anchor <hash> --custody-key-file <custody.key>\n")
    buf.seek(0)
    audit("export", cid, file="case bundle")
    return send_file(buf, as_attachment=True, download_name=f"{cid}_case_bundle.zip", mimetype="application/zip")


# ============================================================== system
@app.post("/api/system/selftest")
@login_required
def api_selftest():
    def fn(j, cid, user, **_):
        j.log("python main.py selftest")
        p = subprocess.Popen([sys.executable, os.path.join(ROOT, "main.py"), "selftest"], cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        for line in p.stdout:
            j.log(line.rstrip())
        p.wait()
        if p.returncode:
            raise RuntimeError("some tests failed")
        return {"ok": True}
    j = _start_job(None, "selftest", fn)
    return jsonify(job=j.id)


@app.get("/api/system/info")
@login_required
def api_info():
    import platform
    mods = {}
    for mname in ("networkx", "Evtx", "boto3", "psutil", "flask"):
        try:
            mod = __import__(mname)
            mods[mname] = getattr(mod, "__version__", "installed")
        except ImportError:
            mods[mname] = None
    st = {"backend": "local disk (data folder)", "last_error": STORAGE_ERROR}
    if MIRROR:
        try:
            st = MIRROR.status()
        except Exception as e:
            st = {"backend": "PostgreSQL", "last_error": str(e)}
    hide = PUBLIC_MODE and (current_user() or {}).get("role") != "admin"      # do not show server paths to visitors
    return jsonify(python=sys.version.split()[0], system=platform.platform(), host="hosted" if hide else platform.node(), modules=mods,
                   data_dir="(hosted)" if hide else DATA, storage=st, retention_hours=RETENTION_H,
                   custody_key=("environment variable" if hide else CUSTODY_KEY_PATH) if not os.environ.get("DFIR_CUSTODY_KEY") else "DFIR_CUSTODY_KEY environment variable",
                   rules=len(FLAGS), techniques=len({v[0] for v in FLAGS.values()}), families={k: len(v) for k, v in RULE_FAMILIES.items()},
                   public_mode=PUBLIC_MODE, cases=len(os.listdir(CASES)), research=[n for n in ("evaluation.json", "real_data_results.json",
                   "real_data_report.html") if os.path.exists(os.path.join(ROOT, "results", n))])


@app.get("/api/audit")
@admin_required
def api_audit():
    out = []
    if os.path.exists(AUDIT):
        with open(AUDIT, encoding="utf-8") as f:
            out = [json.loads(x) for x in f if x.strip()]
    return jsonify(out[::-1][:500])


_RESEARCH = {"key": None, "data": None}


def _research_data():
    """Evaluation results (results/evaluation.json, results/real_data_results.json) for the console's evaluation pages."""
    import make_dashboard
    paths = [os.path.join(ROOT, "results", n) for n in ("evaluation.json", "real_data_results.json")]
    key = tuple(os.path.getmtime(p) if os.path.exists(p) else 0 for p in paths)
    if _RESEARCH["key"] == key:
        return _RESEARCH["data"]
    if not os.path.exists(paths[0]):
        return None
    D = make_dashboard.collect_data(ROOT)
    D.pop("explorer", None)
    for c in D.get("cases", {}).values():
        for i in c.get("incidents", []):
            i.pop("events", None)
    ev = _read_json(paths[0], {})
    rows = []
    for s_, pol in [(x, False) for x in ev.get("scenarios", [])] + [(x, True) for x in ev.get("policy", [])]:
        x = s_["score"]
        rows.append({"name": s_["name"], "desc": s_.get("description") or "Same logs with the admin-source policy (admin logons expected only from 10.0.5.10)",
                     "policy": pol, "records": x["records_in_sources"], "completeness": x["completeness"], "found": x["incidents_found"],
                     "exp": x["incidents_expected"], "false_inc": x["false_incidents"], "split": x["split_incidents"], "merged": x["merged_incidents"],
                     "p": x["precision"], "r": x["recall"], "f1": x["f1"], "fa": x["false_alerts"], "tp": x["tp"], "fp": x["fp"], "fn": x["fn"],
                     "cross": x["cross_platform_incidents"]})
    D["scen_detail"] = rows
    rd = _read_json(paths[1], None)
    if rd and D.get("real"):
        w = rd["windows"]
        D["real"]["win"]["top_ignored"] = w.get("top_ignored", [])[:10]
        D["real"]["win"]["supported_events"] = w.get("supported_events")
        D["real"]["generated"] = (rd.get("generated") or "")[:16].replace("T", " ")
        for l in D["real"]["linux"]:
            src = rd["linux"].get(l["file"], {})
            l.update(accepted=src.get("accepted"), bf_success=src.get("bf_success"), distinct=src.get("distinct_failing_ips"),
                     ind_fail=src.get("independent_failed_password"), ignored=src.get("ignored"), top_ignored=(src.get("top_ignored") or [])[:5])
        D["real"]["aws"] = [{"file": a["file"], "why": a["why"], "hit": a["hit"], "records": a.get("records"), "flags": sorted(a.get("flags") or []),
                             "expected": a.get("expected", [])} for a in rd["aws"]]
        ho = rd.get("heldout")
        if ho:
            D["real"]["heldout"] = {k: ho.get(k) for k in ("dataset", "rules_fingerprint", "samples", "records", "errors", "in_scope", "in_alerted",
                                                            "in_exact", "in_parent", "in_alerted_pct", "in_exact_pct", "in_parent_pct", "out_scope",
                                                            "out_alerted", "unlabelled", "unlabelled_alerted", "per_corpus", "per_technique", "background")}
    _RESEARCH.update(key=key, data=D)
    return D


@app.get("/api/research")
@login_required
def api_research():
    D = _research_data()
    if not D:
        return jsonify(ready=False)
    return jsonify(ready=True, **D)


COLLECTORS = os.path.join(ROOT, "collectors")


@app.get("/api/collectors/<name>")
def api_collector(name):
    """The read-only evidence collectors (public: they contain no case data)."""
    if name not in ("cpdfir-collect-windows.ps1", "cpdfir-collect-linux.py"):
        abort(404)
    return send_from_directory(COLLECTORS, name, as_attachment=True, mimetype="text/plain")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.before_request
def _write_guard():
    """Every state-changing call on a case needs write access (the shared demo case is read-only)."""
    va = request.view_args or {}
    if request.method in ("POST", "PATCH", "DELETE", "PUT") and va.get("cid") and session.get("user"):
        p = os.path.join(CASES, va["cid"], "case.json")
        m = _read_json(p) if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", va["cid"]) and os.path.exists(p) else None
        if m is not None and not can_write(m):
            if not can_read(m):
                abort(404)
            read_only_call = request.endpoint == "api_verify" or (
                request.endpoint == "api_tamper" and (request.get_json(silent=True) or {}).get("action") == "status")
            if not read_only_call:                               # anybody who can see a case may verify its custody
                return jsonify(error="this case is read-only for your account (shared demo case) - create your own case to work on it"), 403


def _retention_sweep():
    """Delete visitor (guest) cases older than the retention period. Runs every 10 minutes in the background."""
    while RETENTION_H:
        try:
            now = time.time()
            for cid in os.listdir(CASES):
                m = _read_json(os.path.join(CASES, cid, "case.json"))
                if not m or m.get("shared") or not str(m.get("owner") or "").startswith("guest:") or _job_for(cid):
                    continue
                t = datetime.fromisoformat(m["created"].replace("Z", "+00:00")).timestamp()
                if now - t > RETENTION_H * 3600:
                    with LOCK:
                        _rmtree(os.path.join(CASES, cid))
                    audit("case_expired", None, case_id=cid, retention_hours=RETENTION_H)
                    if MIRROR:
                        MIRROR.request_sync()
        except Exception:
            pass
        time.sleep(600)


if RETENTION_H:
    threading.Thread(target=_retention_sweep, daemon=True).start()


@app.after_request
def headers(r):
    if MIRROR and request.method in ("POST", "PATCH", "DELETE", "PUT") and r.status_code < 400:
        MIRROR.request_sync()
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"
    if r.mimetype == "text/html" and request.path == "/":
        r.headers["X-Frame-Options"] = "DENY"
    return r


@app.errorhandler(413)
def too_big(_):
    return jsonify(error=f"upload larger than {MAX_UPLOAD // (1024 * 1024)} MB"), 413


def _bootstrap_admin():
    """Online deploy: create the first admin from DFIR_ADMIN_USER / DFIR_ADMIN_PASSWORD so a stranger cannot claim the setup page."""
    un = (os.environ.get("DFIR_ADMIN_USER") or "").strip().lower()
    pw = os.environ.get("DFIR_ADMIN_PASSWORD") or ""
    if un and pw and not users() and re.fullmatch(r"[a-z0-9_.-]{3,32}", un) and _pw_ok(pw):
        save_users({un: {"name": os.environ.get("DFIR_ADMIN_NAME", un)[:60], "role": "admin",
                         "pw": generate_password_hash(pw), "created": _now()}})


_bootstrap_admin()


def _seed_demo():
    """Public deploy: start with one analysed demo case so the console is never empty (the free host wipes data on restart)."""
    if os.environ.get("DFIR_SEED_DEMO", "1" if PUBLIC_MODE else "0") in ("", "0", "false", "no"):
        return
    with LOCK:
        if [x for x in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, x))]:
            return
        cid = _new_case_id()
        os.makedirs(os.path.join(CASES, cid, "uploads"))
        save_meta({"id": cid, "title": "Demo — cross-platform attack (Windows + Linux + AWS)", "created": _now(), "created_by": "system",
                   "owner": "system", "shared": True,
                   "description": "Simulated attack: RDP brute force on Windows, SSH compromise on Linux, stolen AWS key abused in the cloud, "
                                  "plus an exposed AWS account state.", "status": "new",
                   "config": {k: fw_config.DEFAULT_CASE[k] for k in CFG_KEYS}, "evidence": []})
    audit("case_created", cid, title="Demo — cross-platform attack (Windows + Linux + AWS)", by="system")
    j = Job(cid, "sample", "system")
    JOBS[j.id] = j

    def run():
        try:
            j.result = _job_sample(j, cid, {"name": "Demo Analyst"}, scenario="S1_cloud", analyze=True)
            j.status = "done"
        except Exception as e:
            j.status, j.error = "failed", str(e)
        j.ended = _now()
        _audit_job(j, {"name": "Demo Analyst"})
        if MIRROR:
            MIRROR.request_sync()
    threading.Thread(target=run, daemon=True).start()


_seed_demo()


def main():
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)))
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '::') else a.host}:{a.port}/"
    print(f"\n  {APP_NAME} v{VERSION}\n  Open  {url}\n  Data  {DATA}\n  Stop  Ctrl+C\n")
    if not a.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        from waitress import serve
        serve(app, host=a.host, port=a.port, threads=8)
    except ImportError:
        app.run(host=a.host, port=a.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
