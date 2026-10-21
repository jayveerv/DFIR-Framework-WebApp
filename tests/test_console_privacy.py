"""Hosted-console features: per-visitor case isolation, read-only shared case, collector-package integrity check,
pseudonymised export, the stdlib Linux collector and the held-out labelling rules."""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "webapp"))

import anonymize  # noqa: E402
import heldout  # noqa: E402

H = {"X-Requested-With": "cpdfir"}


def _app(tmp):
    """Import the console in public mode with its own data folder (fresh module each time)."""
    os.environ.update(DFIR_PUBLIC_MODE="1", DFIR_DATA_DIR=tmp, DFIR_SEED_DEMO="0", DFIR_RETENTION_HOURS="0")
    os.environ.pop("DATABASE_URL", None)
    for m in ("app",):
        sys.modules.pop(m, None)
    import importlib.util
    spec = importlib.util.spec_from_file_location("app", os.path.join(ROOT, "webapp", "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod


def _package(files):
    """A collector-style zip: files + cpdfir_manifest.json with their SHA-256."""
    import hashlib
    buf = io.BytesIO()
    man = {"tool": "CP-DFIR collector", "collector_version": "test", "platform": "Linux", "hostname": "lab01", "run_as": "root",
           "is_admin": True, "finished_utc": "2026-10-01T10:00:00Z",
           "files": [{"path": k, "sha256": hashlib.sha256(v).hexdigest(), "size": len(v)} for k, v in files.items()]}
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
        z.writestr("cpdfir_manifest.json", json.dumps(man))
    return buf.getvalue()


AUTH = (b"Oct  1 10:00:01 lab01 sshd[100]: Failed password for root from 198.51.100.7 port 4000 ssh2\n"
        b"Oct  1 10:00:02 lab01 sshd[100]: Failed password for root from 198.51.100.7 port 4001 ssh2\n")


class HostedConsole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.mod = _app(cls.tmp)
        cls.app = cls.mod.app

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        for k in ("DFIR_PUBLIC_MODE", "DFIR_DATA_DIR", "DFIR_SEED_DEMO", "DFIR_RETENTION_HOURS"):
            os.environ.pop(k, None)

    def guest(self):
        c = self.app.test_client()
        self.assertEqual(c.post("/api/guest", json={}, headers=H).status_code, 200)
        return c

    def new_case(self, c, title="t"):
        r = c.post("/api/cases", json={"title": title}, headers=H)
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["id"]

    def test_visitors_do_not_see_each_others_cases(self):
        a, b = self.guest(), self.guest()
        cid = self.new_case(a, "private")
        self.assertIn(cid, [x["id"] for x in a.get("/api/cases").get_json()])
        self.assertNotIn(cid, [x["id"] for x in b.get("/api/cases").get_json()])
        self.assertEqual(b.get(f"/api/cases/{cid}").status_code, 404)
        self.assertEqual(b.post(f"/api/cases/{cid}/jobs/analyze", json={}, headers=H).status_code, 404)

    def test_shared_case_is_read_only_but_verifiable(self):
        m = self.mod
        cid = "CASE-SHARED-01"
        os.makedirs(os.path.join(m.CASES, cid, "uploads"))
        m.save_meta({"id": cid, "title": "demo", "created": m._now(), "created_by": "system", "owner": "system", "shared": True,
                     "status": "new", "config": {k: m.fw_config.DEFAULT_CASE[k] for k in m.CFG_KEYS}, "evidence": []})
        g = self.guest()
        self.assertIn(cid, [x["id"] for x in g.get("/api/cases").get_json()])
        r = g.post(f"/api/cases/{cid}/evidence", data={"files": (io.BytesIO(AUTH), "auth.log")}, headers=H, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(g.post(f"/api/cases/{cid}/verify", json={}, headers=H).status_code, 403)

    def test_collector_package_integrity(self):
        g = self.guest()
        cid = self.new_case(g)
        ok = _package({"auth.log": AUTH})
        r = g.post(f"/api/cases/{cid}/evidence", data={"files": (io.BytesIO(ok), "pkg.zip")}, headers=H, content_type="multipart/form-data")
        man = [x for x in r.get_json()["report"] if x["name"] == "cpdfir_manifest.json"][0]
        self.assertTrue(man["ok"], man)
        # the same package with one byte changed after collection
        buf = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(ok)) as zin, zipfile.ZipFile(buf, "w") as zout:
            for i in zin.infolist():
                d = zin.read(i.filename)
                zout.writestr(i, d.replace(b"198.51.100.7", b"198.51.100.8") if i.filename == "auth.log" else d)
        cid2 = self.new_case(g)
        r = g.post(f"/api/cases/{cid2}/evidence", data={"files": (io.BytesIO(buf.getvalue()), "pkg.zip")}, headers=H, content_type="multipart/form-data")
        man = [x for x in r.get_json()["report"] if x["name"] == "cpdfir_manifest.json"][0]
        self.assertFalse(man["ok"])
        self.assertIn("auth.log", man["note"])
        col = g.get(f"/api/cases/{cid2}").get_json()["collections"][0]
        self.assertEqual(col["mismatch"], ["auth.log"])

    def test_duplicate_upload_is_not_added_twice(self):
        g = self.guest()
        cid = self.new_case(g)
        for _ in range(2):
            g.post(f"/api/cases/{cid}/evidence", data={"files": (io.BytesIO(AUTH), "auth.log")}, headers=H, content_type="multipart/form-data")
        self.assertEqual(len(g.get(f"/api/cases/{cid}").get_json()["evidence_items"]), 1)

    def test_ssh_to_private_address_refused_when_hosted(self):
        g = self.guest()
        cid = self.new_case(g)
        r = g.post(f"/api/cases/{cid}/jobs/ssh", json={"host": "10.1.2.3"}, headers=H)
        self.assertEqual(r.status_code, 400)
        self.assertIn("private", r.get_json()["error"])
        r = g.post(f"/api/cases/{cid}/jobs/triage", json={}, headers=H)
        self.assertEqual(r.status_code, 403)

    def test_collector_download(self):
        c = self.app.test_client()
        self.assertEqual(c.get("/api/collectors/cpdfir-collect-linux.py").status_code, 200)
        self.assertEqual(c.get("/api/collectors/../app.py").status_code, 404)


class Pseudonymisation(unittest.TestCase):
    EV = [{"user": "CORP\\alice", "src_ip": "198.51.100.7", "host": "WS-FIN-01", "detail": "key AKIAQ3EXAMPLEAPP0001 in 123456789012"},
          {"user": "root", "src_ip": "127.0.0.1", "host": "web01", "detail": "mail bob@example.org"}]

    def test_stable_unlinkable_tokens(self):
        m1 = anonymize.build_map(self.EV, b"secret-1")
        m2 = anonymize.build_map(self.EV, b"secret-2")
        self.assertTrue(m1["alice"].startswith("user-"))
        self.assertTrue(m1["198.51.100.7"].startswith("ip-"))
        self.assertTrue(m1["AKIAQ3EXAMPLEAPP0001"].startswith("key-"))
        self.assertTrue(m1["123456789012"].startswith("acct-"))
        self.assertTrue(m1["bob@example.org"].startswith("mail-"))
        self.assertNotIn("root", m1)                 # generic accounts stay readable
        self.assertNotIn("127.0.0.1", m1)            # loopback is not personal data
        self.assertNotEqual(m1["alice"], m2["alice"])  # per-case secret: not linkable across cases
        self.assertEqual(m1, anonymize.build_map(self.EV, b"secret-1"))

    def test_report_markup_is_untouched(self):
        m = anonymize.build_map(self.EV, b"k")
        html = "<html><head><style>.web01{color:red}</style></head><body><p class='web01'>alice from 198.51.100.7 on web01</p></body></html>"
        out = anonymize.report_html(html, m)
        self.assertIn(".web01{color:red}", out)
        self.assertIn("class='web01'", out)
        self.assertNotIn("alice", out.split("<p")[1])
        self.assertNotIn("198.51.100.7", out)
        self.assertIn("PSEUDONYMISED COPY", out)


class HeldOutLabels(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(heldout.label_of("EVTX-to-MITRE-Attack/TA0008-Lateral Movement/T1021.002-SMB Windows Admin Shares/x.evtx"),
                         ("EVTX-to-MITRE-Attack", "T1021.002"))
        self.assertEqual(heldout.label_of("YamatoSecurity/LateralMovement/T1210_Zerologon_Sysmon.evtx"), ("YamatoSecurity", "T1210"))
        self.assertEqual(heldout.label_of("DeepBlueCLI/many-events-security.evtx"), ("DeepBlueCLI", "background"))
        self.assertEqual(heldout.label_of("YamatoSecurity/Sysmon/Sysmon-27-BlockExeWrite_AbusingCertutil.evtx")[1], None)

    def test_sibling_subtechnique_is_not_in_scope(self):
        cov = heldout.covered_techniques()
        self.assertIn("T1003.001", cov)
        self.assertNotIn("T1003.006", cov)
        rows = heldout.rescope([{"label": "T1003.006", "scope": "?"}, {"label": "T1003.001", "scope": "?"}])
        self.assertEqual([r["scope"] for r in rows], ["out", "in"])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux collector")
class LinuxCollector(unittest.TestCase):
    def test_package_is_complete_and_hashed(self):
        import hashlib
        import importlib.util
        spec = importlib.util.spec_from_file_location("col", os.path.join(ROOT, "collectors", "cpdfir-collect-linux.py"))
        col = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(col)
        out = tempfile.mkdtemp()
        try:
            c = col.Collector(1)
            c.log = lambda *a: None
            zp = c.run(out)
            with zipfile.ZipFile(zp) as z:
                man = json.loads(z.read("cpdfir_manifest.json"))
                names = set(z.namelist())
                for f in man["files"]:
                    if f["path"] != "cpdfir_manifest.json":
                        self.assertEqual(hashlib.sha256(z.read(f["path"])).hexdigest(), f["sha256"])
            for n in ("host/system.json", "host/processes.json", "host/connections.json", "host/accounts.json", "host/persistence.json", "host/files.json"):
                self.assertIn(n, names)
            procs = json.loads(zipfile.ZipFile(zp).read("host/processes.json"))["items"]
            self.assertTrue(any(p["pid"] == os.getpid() for p in procs))
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
