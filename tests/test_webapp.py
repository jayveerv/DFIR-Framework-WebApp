"""Web application (webapp/app.py): login, case, upload, analysis, custody verification and tamper detection."""
import importlib
import io
import os
import shutil
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

AUTH_LOG = b"""Oct 18 10:00:01 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51234 ssh2
Oct 18 10:00:03 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51235 ssh2
Oct 18 10:00:05 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51236 ssh2
Oct 18 10:00:07 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51237 ssh2
Oct 18 10:00:09 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51238 ssh2
Oct 18 10:00:20 web01 sshd[1201]: Accepted password for admin from 45.33.12.9 port 51240 ssh2
Oct 18 10:01:00 web01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/sbin/useradd backdoor
"""


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class WebAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["DFIR_DATA_DIR"] = cls.tmp
        sys.path.insert(0, os.path.join(ROOT, "webapp"))
        import app as A
        cls.A = importlib.reload(A)
        cls.c = cls.A.app.test_client()
        cls.H = {"X-Requested-With": "cpdfir"}

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("DFIR_DATA_DIR", None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _wait(self, cid):
        for _ in range(300):
            if not self.c.get(f"/api/cases/{cid}").json["job"]:
                return
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_end_to_end(self):
        c, H = self.c, self.H
        self.assertEqual(c.get("/api/cases").status_code, 401)
        self.assertTrue(c.post("/api/setup", json={"username": "analyst", "password": "password123", "name": "Test"}).json["ok"])
        self.assertEqual(c.post("/api/cases", json={"title": "x"}).status_code, 400)          # CSRF header missing
        cid = c.post("/api/cases", json={"title": "web01"}, headers=H).json["id"]
        r = c.post(f"/api/cases/{cid}/evidence", data={"files": [(io.BytesIO(AUTH_LOG), "auth.log"), (io.BytesIO(b"\x00\x01"), "x.bin")]},
                   headers=H, content_type="multipart/form-data").json["report"]
        self.assertEqual([x["ok"] for x in r], [True, False])
        self.assertEqual(r[0]["kind"], "linux_auth")
        c.post(f"/api/cases/{cid}/jobs/analyze", json={}, headers=H)
        self._wait(cid)
        res = c.get(f"/api/cases/{cid}/results").json
        self.assertTrue(res["ready"])
        self.assertEqual(len(res["incidents"]), 1)
        self.assertIn("brute_force", [f["rule"] for f in res["fired"]])
        self.assertTrue(c.post(f"/api/cases/{cid}/verify", headers=H).json["ok"])
        self.assertTrue(c.post(f"/api/cases/{cid}/tamper", json={"action": "evidence"}, headers=H).json["ok"])
        v = c.post(f"/api/cases/{cid}/verify", headers=H).json
        self.assertFalse(v["ok"])
        self.assertTrue(any("auth.log" in x["item"] for x in v["failed"]))
        c.post(f"/api/cases/{cid}/tamper", json={"action": "restore"}, headers=H)
        self.assertTrue(c.post(f"/api/cases/{cid}/verify", headers=H).json["ok"])
        ev = c.get(f"/api/cases/{cid}/events?flagged=1&q=backdoor").json
        self.assertEqual(ev["total"], 1)
        one = c.get(f"/api/cases/{cid}/events/{ev['rows'][0]['id']}").json
        self.assertIn("useradd backdoor", one["excerpt"])
        self.assertEqual(c.get(f"/api/cases/{cid}/file/report").status_code, 200)

    def test_classify(self):
        d = tempfile.mkdtemp()
        try:
            def f(name, data, hint=None):
                p = os.path.join(d, name)
                with open(p, "wb") as fh:
                    fh.write(data)
                return self.A.classify(name, p, hint)
            self.assertEqual(f("Security.evtx", b"ElfFile\x00" + b"\x00" * 100), "windows_evtx")
            self.assertEqual(f("export.xml", b"<Event xmlns='x'><System/></Event>"), "windows_xml")
            self.assertEqual(f("secure", AUTH_LOG), "linux_auth")
            self.assertEqual(f("trail.json", b'{"Records":[{"eventName":"ConsoleLogin"}]}'), "cloudtrail")
            self.assertEqual(f("processes.json", b"{}"), "host_artifact")
            self.assertEqual(f("manifest.json", b"{}", "cloud"), "cloud_state")
            self.assertIsNone(f("notes.txt", b"hello world"))
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
