#!/usr/bin/env python3
"""CP-DFIR evidence collector for Linux (read-only, Python 3 standard library only - nothing to install).

Collects, in order of volatility (RFC 3227): host identity, network sockets (/proc/net), processes (/proc, with
executable SHA-256), local accounts, sudoers, persistence (cron, systemd units, rc.local, ld.so.preload,
authorized_keys), executables/scripts written recently in /tmp, /var/tmp, /dev/shm and Downloads, and the
authentication log (auth.log / secure, or the journal). Nothing on the system is changed. Every output file is
hashed (SHA-256) into cpdfir_manifest.json and everything is packed into one zip.

Upload the zip on the Evidence page of a case in the CP-DFIR console; the console re-hashes every file and
compares it with the manifest, so any change between collection and upload is reported.

Usage:   sudo python3 cpdfir-collect-linux.py [--days 7] [--out DIR]
"""
import argparse
import glob
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone

VERSION = "py-1.1"


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def sha256(path, cap=200 * 1024 * 1024):
    try:
        if os.path.getsize(path) > cap:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        return h.hexdigest()
    except OSError:
        return None


def read(path, cap=2_000_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(cap)
    except OSError:
        return None


def magic(path):
    try:
        with open(path, "rb") as f:
            b = f.read(4)
    except OSError:
        return None
    if b == b"\x7fELF":
        return "ELF"
    if b[:2] == b"MZ":
        return "PE"
    if b[:2] == b"#!":
        return "script"
    return None


class Collector:
    def __init__(self, days):
        self.days = days
        self.work = tempfile.mkdtemp(prefix="cpdfir_")
        self.host = os.path.join(self.work, "host")
        os.makedirs(self.host)
        self.errors, self.limited = [], {}
        self.admin = os.geteuid() == 0
        if not self.admin:
            self.limited["not_admin"] = "Not run as root: other users' processes, socket owners and protected logs may be missing."

    def save(self, name, obj):
        with open(os.path.join(self.host, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)
        print(f"  {name}")

    def homes(self):
        hs = set()
        for p in pwd.getpwall():
            if p.pw_dir not in ("/", "/nonexistent") and not p.pw_shell.endswith(("nologin", "false")) and os.path.isdir(p.pw_dir):
                hs.add(p.pw_dir)
        return sorted(hs)

    # ------------------------------------------------------------------ artifacts
    def system(self):
        boot = None
        for l in (read("/proc/stat") or "").splitlines():
            if l.startswith("btime "):
                boot = int(l.split()[1])
        off = -time.timezone if not time.localtime().tm_isdst else -time.altzone
        logged = []
        try:
            out = subprocess.run(["who"], capture_output=True, text=True, timeout=20).stdout
            for l in out.splitlines():
                parts = l.split()
                if parts:
                    m = re.search(r"\(([^)]+)\)", l)
                    logged.append(dict(name=parts[0], terminal=parts[1] if len(parts) > 1 else None, host=m.group(1) if m else None, started=None))
        except Exception as e:
            self.errors.append(f"who: {e}")
        self.save("system.json", dict(collected_at=iso(time.time()), hostname=socket.gethostname(), fqdn=socket.getfqdn(), os="Linux",
                                      release=platform.release(), version=platform.version()[:200], machine=platform.machine(),
                                      boot_time=iso(boot), uptime_s=int(time.time() - boot) if boot else None,
                                      timezone_offset=f"{'+' if off >= 0 else '-'}{abs(off) // 3600:02d}:{abs(off) % 3600 // 60:02d}",
                                      is_admin=self.admin, collector_version=VERSION, run_as=pwd.getpwuid(os.geteuid()).pw_name,
                                      logged_in=logged))

    def _inode_pids(self):
        m = {}
        for fd in glob.glob("/proc/[0-9]*/fd/*"):
            try:
                t = os.readlink(fd)
            except OSError:
                continue
            if t.startswith("socket:["):
                m[t[8:-1]] = int(fd.split("/")[2])
        return m

    @staticmethod
    def _addr(hexaddr, v6):
        ip, port = hexaddr.split(":")
        b = bytes.fromhex(ip)
        if v6:
            b = b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))
            return socket.inet_ntop(socket.AF_INET6, b), int(port, 16)
        return socket.inet_ntop(socket.AF_INET, b[::-1]), int(port, 16)

    def connections(self):
        states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
                  "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
        owners = self._inode_pids()
        rows = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for l in (read(f"/proc/net/{proto}") or "").splitlines()[1:]:
                f = l.split()
                if len(f) < 10:
                    continue
                try:
                    lip, lp = self._addr(f[1], proto.endswith("6"))
                    rip, rp = self._addr(f[2], proto.endswith("6"))
                except (ValueError, OSError):
                    continue
                st = states.get(f[3], f[3]) if proto.startswith("tcp") else "NONE"
                rows.append(dict(proto=proto, local_ip=lip, local_port=lp, remote_ip=None if rp == 0 else rip, remote_port=rp or None,
                                 status=st, pid=owners.get(f[9])))
        if any(r["pid"] is None for r in rows) and not self.admin:
            self.limited["connections"] = "Some sockets have no owning process (needs root)."
        return rows

    def processes(self):
        out, cache = [], {}
        for d in glob.glob("/proc/[0-9]*"):
            pid = int(d.rsplit("/", 1)[1])
            st = read(f"{d}/stat") or ""
            m = re.match(r"\d+ \((.*)\) (\S) (\d+) (?:\S+ ){18}(\d+)", st)
            if not m:
                continue
            name, state, ppid, start_ticks = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            cmd = [c for c in (read(f"{d}/cmdline") or "").split("\x00") if c]
            try:
                exe = os.readlink(f"{d}/exe")
            except OSError:
                exe = None
            deleted = bool(exe and exe.endswith(" (deleted)"))
            if deleted:
                exe = exe[:-10]
            uid = None
            for l in (read(f"{d}/status") or "").splitlines():
                if l.startswith("Uid:"):
                    uid = int(l.split()[1])
            try:
                user = pwd.getpwuid(uid).pw_name if uid is not None else None
            except KeyError:
                user = str(uid)
            try:
                cwd = os.readlink(f"{d}/cwd")
            except OSError:
                cwd = None
            boot = next((int(l.split()[1]) for l in (read("/proc/stat") or "").splitlines() if l.startswith("btime ")), 0)
            created = boot + start_ticks / os.sysconf("SC_CLK_TCK") if boot else None
            h = None
            if exe and not deleted:
                if exe not in cache and len(cache) < 400:
                    cache[exe] = sha256(exe)
                h = cache.get(exe)
            out.append(dict(pid=pid, ppid=ppid, name=name, exe=exe, cmdline=cmd, username=user, create_time_utc=iso(created),
                            status=state, cwd=cwd, exe_deleted=deleted, exe_sha256=h))
        return out

    def accounts(self):
        items = [dict(name=p.pw_name, uid=p.pw_uid, gid=p.pw_gid, home=p.pw_dir, shell=p.pw_shell, kind="local_user") for p in pwd.getpwall()]
        groups = {}
        for l in (read("/etc/group") or "").splitlines():
            f = l.split(":")
            if len(f) >= 4 and f[0] in ("sudo", "wheel", "admin", "adm", "root"):
                groups[f[0]] = [x for x in f[3].split(",") if x]
        sud = []
        for f in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
            t = read(f)
            if t:
                sud += [f"{os.path.basename(f)}: {l.strip()}" for l in t.splitlines() if l.strip() and not l.strip().startswith("#")][:50]
        self.save("accounts.json", dict(collected_at=iso(time.time()), items=items, groups=groups, sudoers=sud))

    def persistence(self):
        items = []

        def add(kind, name, value, mtime=None, **k):
            items.append(dict(kind=kind, name=name, value=value, mtime=iso(mtime), **k))
        for f in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")) + sorted(glob.glob("/var/spool/cron/crontabs/*") + glob.glob("/var/spool/cron/*")):
            if os.path.isfile(f):
                for l in (read(f) or "").splitlines():
                    if l.strip() and not l.strip().startswith("#") and not re.match(r"^\s*\w+=", l):
                        add("cron", f, l.strip(), os.path.getmtime(f))
        for d in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
            for f in sorted(glob.glob(d + "/*")):
                if os.path.isfile(f):
                    add("cron_script", f, os.path.basename(f), os.path.getmtime(f), sha256=sha256(f))
        units = glob.glob("/etc/systemd/system/*.service") + glob.glob("/etc/systemd/system/*/*.service")
        for h in self.homes():
            units += glob.glob(h + "/.config/systemd/user/*.service")
        for f in sorted(set(units)):
            if os.path.isfile(f):
                for l in (read(f) or "").splitlines():
                    if re.match(r"^\s*Exec(Start|StartPre|StartPost)\s*=", l):
                        add("systemd", f, l.split("=", 1)[1].strip(), os.path.getmtime(f))
        t = read("/etc/rc.local")
        if t:
            for l in t.splitlines():
                if l.strip() and not l.strip().startswith("#") and l.strip() != "exit 0":
                    add("rc_local", "/etc/rc.local", l.strip(), os.path.getmtime("/etc/rc.local"))
        t = read("/etc/ld.so.preload")
        if t and t.strip():
            add("ld_preload", "/etc/ld.so.preload", t.strip()[:300], os.path.getmtime("/etc/ld.so.preload"))
        for h in self.homes() + ["/root"]:
            f = h + "/.ssh/authorized_keys"
            if os.path.isfile(f):
                for l in (read(f) or "").splitlines():
                    p = l.split()
                    kt = next((x for x in p if x.startswith(("ssh-", "ecdsa-", "sk-"))), None)
                    if kt:
                        i = p.index(kt)
                        blob = p[i + 1] if len(p) > i + 1 else ""
                        add("authorized_keys", f, f"{kt} {hashlib.sha256(blob.encode()).hexdigest()[:32]} {' '.join(p[i + 2:])}".strip(),
                            os.path.getmtime(f), options=" ".join(p[:i]))
        self.save("persistence.json", dict(collected_at=iso(time.time()), items=items))

    def files(self):
        cut = time.time() - self.days * 86400
        found, scanned = [], 0
        own = os.path.realpath(self.work)
        for base in ["/tmp", "/var/tmp", "/dev/shm"] + [h + "/Downloads" for h in self.homes()]:
            for root, dirs, fs in os.walk(base):
                if root.count(os.sep) - base.count(os.sep) >= 3:
                    dirs[:] = []
                if os.path.realpath(root).startswith(own):
                    continue
                for n in fs:
                    scanned += 1
                    p = os.path.join(root, n)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if max(st.st_mtime, st.st_ctime) < cut:
                        continue
                    mg = magic(p)
                    found.append(dict(path=p, size=st.st_size, mtime=iso(st.st_mtime), changed=iso(st.st_ctime), magic=mg,
                                      sha256=sha256(p, 50 * 1024 * 1024) if mg else None, timestomped=bool(st.st_ctime - st.st_mtime > 3600)))
                if scanned > 20000:
                    self.limited["files"] = "File scan stopped after 20000 entries."
                    break
        found.sort(key=lambda r: r["changed"] or "", reverse=True)
        found.sort(key=lambda r: r["magic"] is None)
        self.save("files.json", dict(collected_at=iso(time.time()), window_days=self.days, scanned=scanned, total_recent=len(found), items=found[:1000]))

    def logs(self):
        for src in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.exists(src):
                if not os.access(src, os.R_OK):
                    self.limited["auth_log"] = f"{src} is not readable (run with sudo)."
                    return
                with open(os.path.join(self.work, "auth.log"), "wb") as o:
                    for rot in sorted(glob.glob(src + ".[0-9]"), reverse=True):     # older uncompressed rotation first
                        with open(rot, "rb") as i:
                            shutil.copyfileobj(i, o)
                    with open(src, "rb") as i:
                        shutil.copyfileobj(i, o)
                print("  auth.log")
                return
        try:
            out = subprocess.run(["journalctl", "--no-pager", "-o", "short-iso", "--since", f"-{self.days}d",
                                  "_COMM=sshd", "+", "_COMM=sudo", "+", "_COMM=useradd"], capture_output=True, text=True, timeout=180).stdout
        except Exception as e:
            out = ""
            self.errors.append(f"journalctl: {e}")
        if re.search(r"^\d{4}-\d\d-\d\dT", out, re.M):
            with open(os.path.join(self.work, "auth.log"), "w", encoding="utf-8") as f:
                f.write(out)
            print("  auth.log (from the journal)")
        else:
            self.limited["auth_log"] = "No readable /var/log/auth.log or /var/log/secure and no journal output."

    # ------------------------------------------------------------------ run
    def run(self, out_dir):
        t0 = time.time()
        host = socket.gethostname()
        print(f"CP-DFIR collector {VERSION} - collecting from {host} (root={self.admin}, last {self.days} days)")
        self.system()
        conns = self.connections()
        procs = self.processes()
        self.save("connections.json", dict(collected_at=iso(time.time()), items=conns))
        self.save("processes.json", dict(collected_at=iso(time.time()), items=procs))
        self.accounts()
        self.persistence()
        self.files()
        self.logs()
        with open(os.path.join(self.host, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(dict(collector_version=VERSION, host=dict(hostname=host, os="Linux", is_admin=self.admin),
                           errors=self.errors, limited=self.limited), f, indent=1)
        files = []
        for root, _, fs in os.walk(self.work):
            for n in sorted(fs):
                p = os.path.join(root, n)
                files.append(dict(path=os.path.relpath(p, self.work).replace(os.sep, "/"), sha256=sha256(p), size=os.path.getsize(p)))
        man = dict(tool="CP-DFIR collector", collector_version=VERSION, platform="Linux", hostname=host,
                   run_as=pwd.getpwuid(os.geteuid()).pw_name, is_admin=self.admin, started_utc=iso(t0), finished_utc=iso(time.time()),
                   window_days=self.days, files=files, errors=self.errors, limited=self.limited)
        with open(os.path.join(self.work, "cpdfir_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(man, f, indent=1)
        os.makedirs(out_dir, exist_ok=True)
        zp = os.path.join(out_dir, f"CPDFIR_{host}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip")
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, fs in os.walk(self.work):
                for n in fs:
                    p = os.path.join(root, n)
                    z.write(p, os.path.relpath(p, self.work))
        shutil.rmtree(self.work, ignore_errors=True)
        print(f"\nDone in {time.time() - t0:.0f} s\nEvidence package : {zp}\nSHA-256          : {sha256(zp)}")
        print("Note this hash in your case notes, then upload the zip on the case's Evidence page.")
        for v in self.limited.values():
            print("WARNING:", v)
        return zp


def main():
    if not sys.platform.startswith("linux"):
        sys.exit("This collector is for Linux. On Windows use cpdfir-collect-windows.ps1.")
    ap = argparse.ArgumentParser(description="CP-DFIR evidence collector for Linux (read-only)")
    ap.add_argument("--days", type=int, default=7, help="look-back window for recent files and the journal (default 7)")
    ap.add_argument("--out", default=os.getcwd(), help="folder for the evidence zip (default: current folder)")
    a = ap.parse_args()
    Collector(a.days).run(a.out)


if __name__ == "__main__":
    main()
