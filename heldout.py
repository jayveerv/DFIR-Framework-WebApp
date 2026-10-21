"""Held-out validation on real Windows attack logs that were NOT used while the detection rules were written.

Why: the EVTX-ATTACK-SAMPLES results (realdata.py) are development-set results - the rules were refined after looking
at those samples, so they are optimistic. This module measures the frozen rule set on three other public corpora:

  EVTX-to-MITRE-Attack (M. Decrevoisier)   one folder per ATT&CK technique -> the folder gives the label
  DeepBlueCLI sample logs (SANS)            attack captures + three large "many-events" logs used as background
  Yamato Security samples                   technique id in the file name where present

All three are taken from the Hayabusa sample collection at a fixed commit (HO_COMMIT), so the run is reproducible.
Files byte-identical to a development sample are excluded. The rule-set fingerprint (SHA-256 of the detection and
parsing code) is stored with the results: the numbers belong to exactly that rule set, which was not changed after
this evaluation was run.

Measured
  * parsing: records, parse errors, supported events (python-evtx 0.8 cannot decode a few files: NullTypeNode bug)
  * in-scope samples (a CP-DFIR rule exists for the labelled technique, its parent, or an equivalent technique):
      detection rate  - the sample raised at least one alert
      technique match - an alert mapped to the labelled technique (exact) or its parent technique
  * out-of-scope samples: share that still raised an alert (incidental detections, not counted as success)
  * background logs: alerts per 1,000 events and which rules fired (upper bound on false alarms; the logs are not
    labelled benign, so this is not a false-positive *rate*)
"""
import collections
import hashlib
import os
import re
import time
import urllib.parse

import config
import correlate
import normalize

HO_REPO = "Yamato-Security/hayabusa-sample-evtx"
HO_COMMIT = "0845333ecb4afcf64c55c6e10946383f168f308c"
HO_BASE = f"https://raw.githubusercontent.com/{HO_REPO}/{HO_COMMIT}/"
HERE = os.path.dirname(os.path.abspath(__file__))

# byte-identical to a development (EVTX-ATTACK-SAMPLES) file -> excluded from the held-out set
EXCLUDED = {"EVTX-to-MITRE-Attack/TA0004-Privilege Escalation/T1134.005-Access Token Manipulation SID-History Injection/ID 4765 - SID history added.evtx":
            "byte-identical to a development sample"}

# DeepBlueCLI file names do not carry technique ids: labels below are my reading of the file names (documented).
DEEPBLUE = {
    "Powershell-Invoke-Obfuscation-encoding-menu.evtx": "T1027", "Powershell-Invoke-Obfuscation-many.evtx": "T1027",
    "Powershell-Invoke-Obfuscation-string-menu.evtx": "T1027", "disablestop-eventlog.evtx": "T1562.002",
    "eventlog-dac.evtx": "T1562.002", "metasploit-psexec-native-target-security.evtx": "T1569.002",
    "metasploit-psexec-native-target-system.evtx": "T1569.002", "metasploit-psexec-powershell-target-security.evtx": "T1569.002",
    "metasploit-psexec-powershell-target-system.evtx": "T1569.002", "metasploit-psexec-pwshpayload.evtx": "T1569.002",
    "metasploit-sysmon.evtx": None, "mimikatz-privesc-hashdump.evtx": "T1003", "mimikatz-privilegedebug-tokenelevate-hashdump.evtx": "T1003",
    "new-user-security.evtx": "T1136.001", "password-spray.evtx": "T1110.003", "powersploit-security.evtx": "T1059.001",
    "powersploit-system.evtx": "T1059.001", "psattack-security.evtx": "T1059.001", "sliver-security.evtx": None,
    "sliver-sysmon.evtx": None, "smb-password-guessing-security.evtx": "T1110.001", "wmi-event-filter-persistance.evtx": "T1546.003",
    "many-events-application.evtx": "background", "many-events-security.evtx": "background", "many-events-system.evtx": "background",
}
# techniques that describe the same activity as the label (PsExec = service execution over admin shares)
EQUIV = {"T1569.002": {"T1569.002", "T1543.003", "T1021.002"}, "T1027": {"T1027", "T1059.001"}}


def rules_fingerprint():
    h = hashlib.sha256()
    for f in ("correlate.py", "normalize.py", "config.py"):
        with open(os.path.join(HERE, f), "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()


def label_of(rel):
    corpus = rel.split("/", 1)[0]
    name = rel.rsplit("/", 1)[-1]
    if corpus == "EVTX-to-MITRE-Attack":
        m = re.search(r"/(T\d{4}(?:\.\d{3})?)", rel)
        return corpus, (m.group(1) if m else None)
    if corpus == "DeepBlueCLI":
        return corpus, DEEPBLUE.get(name)
    m = re.match(r"(T\d{4}(?:\.\d{3})?)_", name)
    return corpus, (m.group(1) if m else None)


def parent(t):
    return t.split(".")[0] if t else t


def covered_techniques():
    return {v[0] for v in correlate.FLAGS.values()}


def fetch(root, log=print):
    rd = os.path.join(root, "real_data")
    names = [l.strip() for l in open(os.path.join(rd, "heldout_files.txt"), encoding="utf-8") if l.strip()]
    todo = [n for n in names if not os.path.exists(os.path.join(rd, "heldout", n))]
    if todo:
        from realdata import _get
        log(f"Downloading {len(todo)} held-out EVTX samples (first time only) ...")
        for i, n in enumerate(todo, 1):
            _get(HO_BASE + urllib.parse.quote(n), os.path.join(rd, "heldout", n))
            if i % 50 == 0:
                log(f"  {i}/{len(todo)}")
    return [n for n in names if not os.path.exists(os.path.join(rd, "heldout", n))]


def run(root, log=print):
    rd = os.path.join(root, "real_data")
    cfg = config.load_case_config(None)
    names = [l.strip() for l in open(os.path.join(rd, "heldout_files.txt"), encoding="utf-8") if l.strip()]
    cov = covered_techniques()
    rows, t0 = [], time.time()
    for i, n in enumerate(names, 1):
        if n in EXCLUDED:
            continue
        p = os.path.join(rd, "heldout", n)
        if not os.path.exists(p):
            continue
        ev, st = normalize.parse_windows(p)
        for k, e in enumerate(ev, 1):
            e["event_id"] = f"E{k}"
        if ev:
            correlate.correlate(ev, cfg)
        flags = collections.Counter(f for e in ev for f in e["flags"])
        techs = sorted({correlate.FLAGS[f][0] for f in flags if f in correlate.FLAGS})
        corpus, lab = label_of(n)
        if lab == "background":
            scope = "background"
        elif not lab:
            scope = "unlabelled"
        else:
            # in scope = a rule exists for exactly this technique, for its parent technique (a parent-level rule covers
            # every sub-technique), or for an equivalent technique. A rule for a *sibling* sub-technique does not count.
            scope = "in" if (lab in cov or parent(lab) in cov or (EQUIV.get(lab, set()) & cov)) else "out"
        ok_set = EQUIV.get(lab, {lab}) if lab else set()
        exact = bool(lab and set(techs) & ok_set)
        par = bool(lab and ({parent(t) for t in techs} & {parent(x) for x in ok_set}))
        rows.append(dict(file=n, corpus=corpus, label=lab, scope=scope, records=st["records_seen"], supported=st["normalized"],
                         errors=st["errors"], flags=dict(flags), techniques=techs, alerted=bool(flags), exact=exact, parent_match=par))
        if i % 80 == 0:
            log(f"  held-out: {i}/{len(names)}")
    return summarise(rows, time.time() - t0)


def rescope(rows):
    """Re-apply the scope rule to stored rows (no re-detection)."""
    cov = covered_techniques()
    for r in rows:
        lab = r["label"]
        if lab and lab != "background":
            r["scope"] = "in" if (lab in cov or parent(lab) in cov or (EQUIV.get(lab, set()) & cov)) else "out"
    return rows


def summarise(rows, secs):
    def pct(a, b):
        return round(100 * a / b, 1) if b else None
    ins = [r for r in rows if r["scope"] == "in"]
    out = [r for r in rows if r["scope"] == "out"]
    unl = [r for r in rows if r["scope"] == "unlabelled"]
    bg = [r for r in rows if r["scope"] == "background"]
    per_corpus = collections.OrderedDict()
    for r in rows:
        c = per_corpus.setdefault(r["corpus"], dict(samples=0, records=0, errors=0, in_scope=0, in_alerted=0, in_exact=0, in_parent=0))
        c["samples"] += 1
        c["records"] += r["records"]
        c["errors"] += r["errors"]
        if r["scope"] == "in":
            c["in_scope"] += 1
            c["in_alerted"] += r["alerted"]
            c["in_exact"] += r["exact"]
            c["in_parent"] += r["parent_match"]
    per_tech = collections.OrderedDict()
    for r in sorted(ins, key=lambda r: r["label"]):
        t = per_tech.setdefault(r["label"], dict(samples=0, alerted=0, exact=0))
        t["samples"] += 1
        t["alerted"] += r["alerted"]
        t["exact"] += r["exact"]
    bg_rows = [dict(file=r["file"], records=r["records"], supported=r["supported"], alerts=sum(r["flags"].values()), flags=r["flags"],
                    per_1000=round(1000 * sum(r["flags"].values()) / r["supported"], 2) if r["supported"] else None) for r in bg]
    missed = [dict(file=r["file"], label=r["label"], supported=r["supported"], techniques=r["techniques"])
              for r in ins if not r["parent_match"]]
    return dict(
        dataset=f"{HO_REPO}@{HO_COMMIT[:12]}", rules_fingerprint=rules_fingerprint()[:16], seconds=round(secs, 1),
        excluded=EXCLUDED, samples=len(rows), records=sum(r["records"] for r in rows), errors=sum(r["errors"] for r in rows),
        with_supported=sum(r["supported"] > 0 for r in rows),
        in_scope=len(ins), in_alerted=sum(r["alerted"] for r in ins), in_exact=sum(r["exact"] for r in ins),
        in_parent=sum(r["parent_match"] for r in ins),
        in_alerted_pct=pct(sum(r["alerted"] for r in ins), len(ins)), in_exact_pct=pct(sum(r["exact"] for r in ins), len(ins)),
        in_parent_pct=pct(sum(r["parent_match"] for r in ins), len(ins)),
        out_scope=len(out), out_alerted=sum(r["alerted"] for r in out), unlabelled=len(unl), unlabelled_alerted=sum(r["alerted"] for r in unl),
        per_corpus=per_corpus, per_technique=per_tech, background=bg_rows, missed=missed,
        out_scope_techniques=dict(collections.Counter(r["label"] for r in out).most_common()),
        rows=rows)


if __name__ == "__main__":
    import json
    import sys
    root = HERE
    fetch(root)
    res = run(root)
    print(json.dumps({k: v for k, v in res.items() if k not in ("rows",)}, indent=1)[:6000])
    if len(sys.argv) > 1:
        json.dump(res, open(sys.argv[1], "w"), indent=1)
