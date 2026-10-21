"""Optional durable storage for hosted deployments whose disk is wiped on restart (e.g. a free Render instance).

When DATABASE_URL (PostgreSQL) is set, the console's data folder - cases, evidence originals, custody ledgers,
users, audit log and anchors - is mirrored file by file into one table and restored on start. Without
DATABASE_URL nothing changes: the data folder on disk is the only store (the normal local installation).

Design
  * whole files, keyed by their path inside the data folder; content stored as bytea with its SHA-256
  * restore on start before the console touches the folder; files whose content does not match the stored
    SHA-256 are not restored and are reported (integrity of the mirror itself)
  * sync after every state-changing request and after every background job, debounced, in a background thread:
    only files whose size or mtime changed are uploaded; files deleted on disk are deleted from the table
  * secrets are NOT mirrored: the custody HMAC key and the session key must come from environment variables
    (DFIR_CUSTODY_KEY, DFIR_SESSION_KEY) on such a host, so the database alone can never forge a ledger
"""
import hashlib
import os
import threading
import time

SKIP_DIRS = {"tmp"}
SKIP_FILES = {"custody.key", "session.key"}


class Mirror:
    def __init__(self, url, root, log=print):
        import psycopg                                   # only needed when DATABASE_URL is set
        self.psycopg = psycopg
        self.url, self.root, self.log = url, root, log
        self.state = {}                                  # rel path -> (size, mtime_ns)
        self.lock = threading.Lock()
        self.dirty = threading.Event()
        self.last_error = None
        self.last_sync = None
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS cpdfir_files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size BIGINT NOT NULL, "
                      "data BYTEA NOT NULL, updated TIMESTAMPTZ NOT NULL DEFAULT now())")

    def _conn(self):
        return self.psycopg.connect(self.url, autocommit=True, connect_timeout=15)

    def _walk(self):
        out = {}
        for dp, dns, fns in os.walk(self.root):
            rel_dir = os.path.relpath(dp, self.root)
            if rel_dir.split(os.sep)[0] in SKIP_DIRS:
                dns[:] = []
                continue
            for n in fns:
                if n in SKIP_FILES:
                    continue
                p = os.path.join(dp, n)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                out[os.path.relpath(p, self.root).replace(os.sep, "/")] = (st.st_size, st.st_mtime_ns)
        return out

    def restore(self):
        n, bad = 0, []
        with self._conn() as c:
            for path, sha, data in c.execute("SELECT path, sha256, data FROM cpdfir_files"):
                data = bytes(data)
                if hashlib.sha256(data).hexdigest() != sha or ".." in path.split("/"):
                    bad.append(path)
                    continue
                p = os.path.join(self.root, *path.split("/"))
                os.makedirs(os.path.dirname(p), exist_ok=True)
                if os.path.exists(p):
                    os.chmod(p, 0o644)
                with open(p, "wb") as f:
                    f.write(data)
                if "/uploads/" in path:
                    os.chmod(p, 0o444)                   # evidence originals stay read-only
                n += 1
        self.state = self._walk()
        self.log(f"  Storage  restored {n} file(s) from the database" + (f"; {len(bad)} failed their SHA-256 check: {bad[:5]}" if bad else ""))
        return n, bad

    def sync(self):
        with self.lock:
            now = self._walk()
            changed = [k for k, v in now.items() if self.state.get(k) != v]
            gone = [k for k in self.state if k not in now]
            if not changed and not gone:
                return 0
            with self._conn() as c:
                for k in changed:
                    try:
                        with open(os.path.join(self.root, *k.split("/")), "rb") as f:
                            data = f.read()
                    except OSError:
                        continue
                    c.execute("INSERT INTO cpdfir_files(path, sha256, size, data, updated) VALUES (%s, %s, %s, %s, now()) "
                              "ON CONFLICT (path) DO UPDATE SET sha256 = EXCLUDED.sha256, size = EXCLUDED.size, data = EXCLUDED.data, updated = now()",
                              (k, hashlib.sha256(data).hexdigest(), len(data), data))
                if gone:
                    c.execute("DELETE FROM cpdfir_files WHERE path = ANY(%s)", (gone,))
            self.state = now
            self.last_sync = time.time()
            return len(changed) + len(gone)

    def request_sync(self):
        self.dirty.set()

    def start(self, debounce=2.0):
        def loop():
            while True:
                self.dirty.wait()
                time.sleep(debounce)
                self.dirty.clear()
                try:
                    self.sync()
                    self.last_error = None
                except Exception as e:                   # keep serving; retry on the next change
                    self.last_error = f"{type(e).__name__}: {e}"
                    self.log("  Storage  sync failed: " + self.last_error)
                    time.sleep(10)
                    self.dirty.set()
        threading.Thread(target=loop, daemon=True).start()

    def status(self):
        with self._conn() as c:
            files, size = c.execute("SELECT count(*), coalesce(sum(size), 0) FROM cpdfir_files").fetchone()
        return dict(backend="PostgreSQL", files=files, bytes=int(size), last_sync=self.last_sync, last_error=self.last_error)
