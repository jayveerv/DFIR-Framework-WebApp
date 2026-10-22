"""Reporting layer: self-contained HTML report (no internet, no JavaScript needed)."""
from datetime import datetime, timezone
from html import escape as h

BROWN, ORANGE, TINT = "#0E4A6E", "#0EA5E9", "#EEF5FB"
SEV_COL = {"high": "#E11D48", "medium": "#D97706", "info": "#94A3B8"}
PLAT_NAME = {"windows": "Windows", "linux": "Linux", "aws": "AWS", "host": "Live host", "cloud": "AWS account state"}
CLOUD_STATE_TYPES = ("trail_state", "account_state", "iam_user_state", "access_key_state", "bucket_state", "sg_state")

VERSION = "1.3"

# One stylesheet for every CP-DFIR report (case report, evaluation, real-data validation). Same palette as the
# investigation console: dark by default, light on request, and always light when printed (A4, page numbers).
CSS = f"""
:root{{--bg:#070B14;--panel:#0F1830;--panel2:#13203D;--line:#1D2B4A;--tx:#E6EDF7;--mu:#8EA0BF;--th:#13203D;--thtx:#E6EDF7;--tint:#0B1222;
--h2:#E6EDF7;--h3:#22D3EE;--acc:#22D3EE;--code:#13203D;--ok:#34D399;--bad:#F43F5E;--warn:#F59E0B;color-scheme:dark}}
:root[data-theme=light]{{--bg:#F3F6FA;--panel:#FFFFFF;--panel2:#F4F7FC;--line:#DCE4EF;--tx:#0F172A;--mu:#475569;--th:#0B1A33;--thtx:#E6EDF7;--tint:#EEF5FB;
--h2:#0B1A33;--h3:#0E4A6E;--acc:#0EA5E9;--code:#E8EEF6;--ok:#059669;--bad:#E11D48;--warn:#D97706;color-scheme:light}}
*{{box-sizing:border-box}}
body{{font-family:"Segoe UI",Inter,system-ui,Calibri,Arial,sans-serif;margin:0;color:var(--tx);background:var(--bg);font-size:14px;line-height:1.5}}
.mark{{background:#0B1A33;color:#FCD34D;font:600 11px "Segoe UI",Arial,sans-serif;letter-spacing:2.2px;text-transform:uppercase;padding:6px 36px;border-bottom:1px solid #1D2B4A}}
header{{background:linear-gradient(110deg,#070B14 0%,#0B1A33 55%,#12284A 100%);color:#E6EDF7;padding:22px 36px;border-bottom:3px solid #22D3EE}}
header h1{{margin:0;font-size:24px;letter-spacing:.2px}} header h1 small{{display:block;font-size:11px;letter-spacing:2px;color:#22D3EE;font-weight:600;margin-bottom:6px;text-transform:uppercase}}
header p{{margin:6px 0 0;color:#8EA0BF;font-size:12.5px}}
main{{padding:10px 36px 48px;max-width:1280px;margin:auto}}
h2{{color:var(--h2);border-left:4px solid var(--acc);padding:2px 0 2px 12px;margin-top:36px;font-size:20px;break-after:avoid}}
h3{{color:var(--h3);margin:22px 0 6px;break-after:avoid}}
p,li{{max-width:1100px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:20px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:10px;padding:12px 18px;min-width:160px;box-shadow:0 2px 10px rgba(15,23,42,.06)}}
.card b{{display:block;font-size:27px;color:var(--h2)}} .card b span{{font-size:22px}} .card span{{font-size:12px;color:var(--mu)}}
.card b span.ok{{color:var(--ok)}} .card b span.bad{{color:var(--bad)}}
.box{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:12px 0}}
.summary{{border-left:4px solid var(--acc)}} .summary p{{margin:6px 0}}
table{{border-collapse:separate;border-spacing:0;width:100%;font-size:12.5px;margin:8px 0;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}}
th{{background:var(--th);color:var(--thtx);text-align:left;padding:7px 9px;font-weight:600}}
td{{border-top:1px solid var(--line);padding:6px 9px;vertical-align:top}} tr:nth-child(even) td{{background:var(--tint)}}
td.n,th.n{{text-align:right;font-variant-numeric:tabular-nums}}
table.kv td:first-child{{width:230px;color:var(--mu);font-weight:600}}
.ok{{color:var(--ok);font-weight:bold}} .bad{{color:var(--bad);font-weight:bold}} .warn{{color:var(--warn);font-weight:bold}}
.tag{{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;color:#fff;margin:1px;font-weight:600}}
.note{{font-size:12.5px;color:var(--mu)}} code{{background:var(--code);padding:1px 4px;font-size:11.5px;border-radius:3px}}
.mono{{font-family:Consolas,"Cascadia Code",monospace;font-size:11.5px;word-break:break-all}}
details{{margin:10px 0}} summary{{cursor:pointer;color:var(--h3);font-weight:bold}}
.fig{{overflow-x:auto;background:#fff;border-radius:8px;margin:6px 0}}
svg text{{font-family:"Segoe UI",Calibri,Arial,sans-serif}}
.tools{{position:fixed;top:12px;right:16px;display:none;gap:8px;z-index:9}}
.tools button{{cursor:pointer;background:#0F1830;color:#E6EDF7;border:1px solid #28406B;border-radius:8px;padding:6px 11px;font:13px "Segoe UI",Arial,sans-serif}}
.tools button:hover{{border-color:#22D3EE}}
footer{{max-width:1280px;margin:0 auto;padding:16px 36px 30px;color:var(--mu);font-size:11.5px;border-top:1px solid var(--line)}}
@media (max-width:700px){{main,header,footer,.mark{{padding-left:16px;padding-right:16px}} table{{display:block;overflow-x:auto}}}}
@page{{size:A4;margin:14mm 11mm 16mm;@bottom-right{{content:"Page " counter(page) " of " counter(pages);font:9px Arial;color:#64748B}}}}
@media print{{
:root,:root[data-theme=light],:root[data-theme=dark]{{--bg:#fff;--panel:#fff;--panel2:#fff;--line:#CBD5E1;--tx:#0F172A;--mu:#475569;--th:#0B1A33;--thtx:#fff;--tint:#F1F5F9;
--h2:#0B1A33;--h3:#0E4A6E;--acc:#0EA5E9;--code:#EEF2F7;--ok:#047857;--bad:#BE123C;--warn:#B45309;color-scheme:light}}
body{{font-size:11.5px;-webkit-print-color-adjust:exact;print-color-adjust:exact}} .tools{{display:none!important}}
main{{max-width:none;padding:0 6mm}} header{{padding:14px 6mm}} .mark{{padding:5px 6mm}} footer{{padding:10px 6mm}}
.card{{box-shadow:none}} tr,.card,.box,svg{{break-inside:avoid}} table{{font-size:10.5px}} th{{padding:5px 7px}} td{{padding:4px 7px}}
}}
"""

# Theme toggle (follows the console's choice, stored under the same key) and print button. Pure progressive
# enhancement: without JavaScript the report still renders completely.
TOOLS_JS = """<script>(function(){var r=document.documentElement,k='cpdfir-theme';
try{var t=localStorage.getItem(k);if(t==='light')r.setAttribute('data-theme','light');}catch(e){}
document.addEventListener('DOMContentLoaded',function(){var b=document.querySelector('.tools');if(!b)return;b.style.display='flex';
document.getElementById('tt').onclick=function(){var l=r.getAttribute('data-theme')!=='light';if(l)r.setAttribute('data-theme','light');else r.removeAttribute('data-theme');
try{localStorage.setItem(k,l?'light':'dark');}catch(e){}};document.getElementById('tp').onclick=function(){window.print();};});
window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.dataset.o=d.open?1:0;d.open=true;});});
window.addEventListener('afterprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=d.dataset.o==='1';});});})();</script>"""


def page_open(title, kicker, heading, sub, marking="CP-DFIR"):
    """Common head + header of every CP-DFIR report page."""
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{h(title)}</title><style>{CSS}</style>{TOOLS_JS}</head><body>"
            f"<div class='tools'><button id='tt' title='Light / dark'>&#9680; Theme</button><button id='tp' title='Print or save as PDF'>&#8681; Print / PDF</button></div>"
            f"<div class='mark'>{h(marking)}</div><header><h1><small>{h(kicker)}</small>{h(heading)}</h1><p>{sub}</p></header><main>")


def page_close(note=""):
    return (f"</main><footer>CP-DFIR v{VERSION} · Cross-Platform Digital Forensics and Incident Response Framework{(' · ' + note) if note else ''}</footer></body></html>")



def _sev(s):
    return f'<span class="tag" style="background:{SEV_COL.get(s.lower(), "#999")}">{h(s.upper())}</span>'


def _table(head, rows, cls=""):
    out = [f'<table class="{cls}"><tr>' + "".join(f"<th>{h(c)}</th>" for c in head) + "</tr>"]
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    out.append("</table>")
    return "".join(out)


SHORT = {"credential file read in session": "credential read", "same API call": "same API call",
         "credential inventory (file holds key)": "file holds key", "key created by key": "key created",
         "same event": "same event"}


def graph_svg(inc):
    cols = {"ip": [], "cred": [], "key": []}
    for n in inc["entities"]:
        cols[n["kind"]].append(n)
    xs = {"ip": 20, "cred": 420, "key": 820}
    w, hh = 250, 34
    pos = {}
    rows = max(len(v) for v in cols.values()) if any(cols.values()) else 1
    height = 50 + rows * 62
    parts = [f'<svg width="1200" height="{height}" viewBox="0 0 1200 {height}" xmlns="http://www.w3.org/2000/svg" style="background:#fff;border:1px solid #DCE4EF;border-radius:8px;max-width:100%;height:auto">']
    titles = {"ip": "Attacker IP", "cred": "Credential file", "key": "Cloud access key"}
    for k, x in xs.items():
        if cols[k]:
            parts.append(f'<text x="{x}" y="18" font-size="12" font-weight="bold" fill="{BROWN}">{titles[k]}</text>')
    for k, lst in cols.items():
        for i, n in enumerate(lst):
            y = 30 + i * 62
            pos[n["id"]] = (xs[k], y)
    for l in inc["links"]:
        if l["a"] in pos and l["b"] in pos:
            (x1, y1), (x2, y2) = pos[l["a"]], pos[l["b"]]
            a_right = x1 + w if x1 < x2 else x1
            b_left = x2 if x1 < x2 else x2 + w
            if x1 == x2:
                a_right, b_left = x1 + w, x2 + w
                parts.append(f'<path d="M{a_right} {y1 + hh / 2} h22 V{y2 + hh / 2} h-22" fill="none" stroke="#6B7280" stroke-width="1.6"/>')
                parts.append(f'<text x="{a_right + 28}" y="{(y1 + y2) / 2 + hh / 2 + 4}" font-size="10" fill="#374151">{h(SHORT.get(l["reason"], l["reason"]))}</text>')
                continue
            parts.append(f'<line x1="{a_right}" y1="{y1 + hh / 2}" x2="{b_left}" y2="{y2 + hh / 2}" stroke="#6B7280" stroke-width="1.6"/>')
            mx, my = (a_right + b_left) / 2, (y1 + y2) / 2 + hh / 2
            parts.append(f'<text x="{mx}" y="{my - 3}" font-size="10" text-anchor="middle" fill="#374151" '
                         f'style="paint-order:stroke;stroke:#fff;stroke-width:3px">{h(SHORT.get(l["reason"], l["reason"]))}</text>')
    for n in inc["entities"]:
        x, y = pos[n["id"]]
        label = n["id"].split(":", 1)[1]
        label = label if len(label) < 40 else "..." + label[-37:]
        plat = "/".join(PLAT_NAME[p] for p in n["platforms"])
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{hh}" rx="4" fill="{TINT}" stroke="{BROWN}"/>')
        parts.append(f'<text x="{x + 8}" y="{y + 15}" font-size="11.5" font-weight="bold" fill="#1F2937">{h(label)}</text>')
        parts.append(f'<text x="{x + 8}" y="{y + 28}" font-size="10" fill="#4B5563">{h(plat)} · {n["events"]} event{"s" if n["events"] != 1 else ""}</text>')
    parts.append("</svg>")
    return "".join(parts)


def timeline_svg(inc, by_id):
    evs = [by_id[i] for i in inc["event_ids"]]
    t0, t1 = evs[0]["epoch"], evs[-1]["epoch"]
    span = max(t1 - t0, 1)
    lanes = ["windows", "linux", "aws", "host"]
    lanes = [l for l in lanes if l in inc["platforms"]]
    W, left, top, lh = 1060, 90, 30, 46
    height = top + lh * len(lanes) + 40
    parts = [f'<svg width="{W}" height="{height}" viewBox="0 0 {W} {height}" xmlns="http://www.w3.org/2000/svg" style="background:#fff;border:1px solid #DCE4EF;border-radius:8px;max-width:100%;height:auto">']
    for i, l in enumerate(lanes):
        y = top + i * lh + lh / 2
        parts.append(f'<text x="10" y="{y + 4}" font-size="12" font-weight="bold" fill="{BROWN}">{PLAT_NAME[l]}</text>')
        parts.append(f'<line x1="{left}" y1="{y}" x2="{W - 20}" y2="{y}" stroke="#E2E8F0"/>')
    for e in evs:
        i = lanes.index(e["source"])
        x = left + (e["epoch"] - t0) / span * (W - left - 30)
        y = top + i * lh + lh / 2
        parts.append(f'<circle cx="{x:.1f}" cy="{y}" r="{5 if e["severity"] != "info" else 3.5}" fill="{SEV_COL[e["severity"]]}"><title>{h(e["time_utc"] + " " + e["event_type"] + " " + str(e["flags"]))}</title></circle>')
    base = top + lh * len(lanes) + 6
    for k in range(6):
        t = t0 + span * k / 5
        x = left + (t - t0) / span * (W - left - 30)
        lab = datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")
        parts.append(f'<text x="{x:.0f}" y="{base + 14}" font-size="10" text-anchor="middle" fill="#4B5563">{lab}Z</text>')
    parts.append(f'<circle cx="{W - 260}" cy="{height - 8}" r="4" fill="{SEV_COL["high"]}"/><text x="{W - 252}" y="{height - 4}" font-size="10">high</text>')
    parts.append(f'<circle cx="{W - 210}" cy="{height - 8}" r="4" fill="{SEV_COL["medium"]}"/><text x="{W - 202}" y="{height - 4}" font-size="10">medium</text>')
    parts.append(f'<circle cx="{W - 140}" cy="{height - 8}" r="3" fill="{SEV_COL["info"]}"/><text x="{W - 132}" y="{height - 4}" font-size="10">related (not alerted)</text>')
    parts.append("</svg>")
    return "".join(parts)


def _event_row(e):
    flags = " ".join(f'<span class="tag" style="background:{SEV_COL["high" if e["severity"] == "high" else "medium"]}">{h(f)}</span>' for f in e["flags"])
    return [h(e["time_utc"].replace("T", " ")), PLAT_NAME[e["source"]], h(e["host"] or ""), h(e["event_type"]),
            h(e["user"] or ""), h(e["src_ip"] or ""), h((e["target"] or e["detail"] or "")[:70]), flags]


def _flag_catalog():
    import correlate
    return correlate.FLAGS


ACCOUNT_FLAGS = {"brute_force_success", "privileged_session", "privileged_logon_unexpected_source", "sudo_untrusted",
                 "external_api_use", "account_created"}
PERSIST_FLAGS = {"account_created", "privilege_group_add", "access_key_created", "registry_persistence", "scheduled_task_created",
                 "service_installed"}


def executive_summary(events, corr, custody_ok, by_id):
    """Plain-language summary for a non-technical reader, generated only from the findings (no free text)."""
    incs = corr["incidents"]
    plat = ", ".join(PLAT_NAME.get(x, x) for x in sorted({e["source"] for e in events})) or "no"
    if not incs:
        body = (f"<p>CP-DFIR analysed <b>{len(events):,}</b> events from {plat} evidence. <b>No incident was found</b>: "
                f"{corr['alert_events']} event(s) matched a detection rule, but none could be tied to an untrusted entity "
                "(external address, stolen credential or cloud key). Review any alerts in section 3 before closing the case.</p>"
                f"<p>Evidence integrity: {'<span class=ok>verified</span>.' if custody_ok else '<span class=bad>FAILED</span> &mdash; see section 4.'}</p>")
        return f'<div class="box summary">{body}</div>'
    rank = {"high": 2, "medium": 1}
    top = max(incs, key=lambda i: (rank.get(i["severity"].lower(), 0), i["alert_count"]))
    ents = [n for i in incs for n in i["entities"]]
    ips = sorted({n["id"].split(":", 1)[1] for n in ents if n["kind"] == "ip"})
    keys = sorted({n["id"].split(":", 1)[1] for n in ents if n["kind"] == "key"})
    creds = sorted({n["id"].split(":", 2)[2] + " on " + n["id"].split(":", 2)[1] for n in ents if n["kind"] == "cred" and n["id"].count(":") >= 2})
    inc_ev = [by_id[eid] for i in incs for eid in i["event_ids"] if eid in by_id]
    hosts = sorted({e["host"] for e in inc_ev if e.get("host") and e["source"] in ("windows", "linux", "host") and e["flags"]})
    flags = {f for e in inc_ev for f in e["flags"]}
    users = sorted({e["user"] for e in inc_ev if e.get("user") and set(e["flags"]) & ACCOUNT_FLAGS})
    xp = sum(1 for i in incs if i["cross_platform"])
    stages = h(", ".join(s["name"] for s in top["stages"][:6])) + (" &hellip;" if len(top["stages"]) > 6 else "")
    body = (f"<p>CP-DFIR analysed <b>{len(events):,}</b> events from {plat} evidence and found <b>{len(incs)} incident(s)</b>"
            f"{f', {xp} of them spanning more than one platform' if xp else ''}. The most serious, <b>{h(top['id'])}</b> "
            f"{_sev(top['severity'])}, ran from {h(top['start'].replace('T', ' '))} to {h(top['end'].replace('T', ' '))} UTC on "
            f"{h(' + '.join(PLAT_NAME[p] for p in top['platforms']))} and involves {len(top['techniques'])} MITRE ATT&amp;CK technique(s): "
            f"{stages}.</p>")
    body += ("<p>Evidence integrity: " + ("<span class='ok'>verified</span> &mdash; every evidence file and ledger entry matched its recorded hash."
                                          if custody_ok else "<span class='bad'>FAILED</span> &mdash; read section 4 before relying on these findings.")
             + (" <b>Event logs were cleared during the attack</b>, so the timeline may be incomplete." if "log_cleared" in flags else "") + "</p>")
    steps = []
    if ips:
        steps.append(f"Block and investigate the external source address(es) <span class='mono'>{h(', '.join(ips[:8]))}</span>.")
    if users:
        steps.append(f"Reset the credentials of, and review all activity by, the account(s) <b>{h(', '.join(users[:8]))}</b>.")
    if keys:
        steps.append(f"Deactivate and rotate the AWS access key(s) <span class='mono'>{h(', '.join(keys[:6]))}</span> and review every call made with them.")
    if creds:
        steps.append(f"Remove the stored cloud credentials ({h('; '.join(creds[:4]))}) and rotate them.")
    if hosts:
        steps.append(f"Isolate and image the affected host(s) <b>{h(', '.join(hosts[:8]))}</b> before any clean-up.")
    if flags & PERSIST_FLAGS:
        steps.append("Remove the persistence the attacker created (new accounts, group memberships, access keys, services, tasks or Run keys listed in section 3).")
    if steps:
        body += "<p><b>Suggested next steps</b> (for the investigator to confirm):</p><ol>" + "".join(f"<li>{x}</li>" for x in steps) + "</ol>"
    return f'<div class="box summary">{body}</div>'


def build_report(ctx):
    events, corr, cfg = ctx["events"], ctx["corr"], ctx["cfg"]
    by_id = {e["event_id"]: e for e in events}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    incs = corr["incidents"]
    cid = cfg["case_id"]
    o = [page_open(f"Forensic report {cid}", "CP-DFIR · Forensic investigation report", f"Investigation Report — {cid}",
                   f"{h(cfg.get('title') or 'Cross-platform investigation')} · Investigator: {h(cfg.get('investigator', ''))} · Generated: {now}",
                   marking=f"Confidential · forensic investigation report · {cid} · handle according to your evidence-handling policy")]
    ok = ctx["custody_ok"]
    o.append('<div class="cards">')
    for val, lab in [(f"{len(events):,}", "events normalised"), (len(ctx["stats"]), "evidence sources"),
                     (f"{corr['alert_events']:,}", "events flagged"), (len(incs), "incidents found"),
                     ('<span class="ok">VERIFIED</span>' if ok else '<span class="bad">FAILED</span>', "chain of custody")]:
        o.append(f'<div class="card"><b>{val}</b><span>{lab}</span></div>')
    o.append("</div>")

    o.append("<h2>1. Executive summary</h2>")
    o.append(executive_summary(events, corr, ok, by_id))

    o.append("<h2>2. Case details and scope</h2>")
    times = sorted(e["time_utc"] for e in events if e.get("time_utc"))
    rows = [
        ("Case", h(cid)), ("Title", h(cfg.get("title") or "")), ("Investigator", h(cfg.get("investigator", "-"))),
        ("Report generated", now),
        ("Tool", f"CP-DFIR v{VERSION} &middot; {len(_flag_catalog())} detection rules mapped to MITRE ATT&amp;CK"),
        ("Evidence sources", h(", ".join(f"{PLAT_NAME.get(k, k)} ({v['normalized']:,} events)" for k, v in ctx["stats"].items()) or "-")),
        ("Evidence files acquired", f"{len(ctx['acquired'])} file(s), each hashed with SHA-256 before and after copying"),
        ("Time span of the evidence", f"{h(times[0].replace('T', ' '))} &rarr; {h(times[-1].replace('T', ' '))} (UTC)" if times else "-"),
        ("Time zone", "All times are UTC. Linux syslog times were converted with the case offset "
                      + h(str(cfg.get("linux_timezone_offset", "+00:00")))),
        ("Integrity", ('<span class="ok">Chain of custody verified</span>' if ok else '<span class="bad">Chain of custody FAILED</span>')
         + " &mdash; HMAC-signed, hash-chained ledger; this report is itself recorded in the ledger after it is written"),
    ]
    o.append('<table class="kv">' + "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows if v) + "</table>")

    o.append("<h2>3. Findings</h2>")
    if not incs:
        o.append("<p>No incident was found: no flagged event could be tied to an untrusted entity.</p>")
    for inc in incs:
        plats = " + ".join(PLAT_NAME[p] for p in inc["platforms"])
        o.append(f"<h3>3.{incs.index(inc) + 1} {inc['id']} {_sev(inc['severity'])} &nbsp; {h(inc['start'].replace('T', ' '))} → {h(inc['end'].replace('T', ' '))}</h3>")
        o.append(f'<p class="note">Platforms: <b>{plats}</b> ({"cross-platform" if inc["cross_platform"] else "single platform"}) · '
                 f'{inc["event_count"]} events · {inc["alert_count"]} flagged · ATT&amp;CK: {h(", ".join(inc["techniques"]))}</p>')
        o.append("<p style='margin:18px 0 6px'><b>Attack stages (in order of first occurrence)</b></p>")
        o.append(_table(["First seen (UTC)", "Technique", "Stage", "Events", "Where"],
                        [[h(r["first"].replace("T", " ")), h(r["technique"]), h(r["name"]) + " " + _sev(r["severity"]), r["count"],
                          h(", ".join(f"{PLAT_NAME[s]}" for s in r["sources"]) + " / " + ", ".join(r["hosts"]))] for r in inc["stages"]]))
        o.append("<p style='margin:18px 0 6px'><b>How the evidence was linked</b></p>")
        o.append("<div class='fig'>" + graph_svg(inc) + "</div>")
        o.append(_table(["From", "To", "Reason", "Events"], [[h(l["a"]), h(l["b"]), h(l["reason"]), l["events"]] for l in inc["links"]]))
        o.append("<p style='margin:18px 0 6px'><b>Timeline</b></p>")
        o.append("<div class='fig'>" + timeline_svg(inc, by_id) + "</div>")
        o.append(f"<details><summary>All {inc['event_count']} events of {inc['id']}</summary>")
        o.append(_table(["Time (UTC)", "Platform", "Host", "Event", "User", "Source IP", "Target / detail", "Flags"],
                        [_event_row(by_id[i]) for i in inc["event_ids"]]))
        o.append("</details>")
    if corr["unlinked_alerts"]:
        o.append("<h3>Alerts not linked to any incident</h3>")
        o.append(_table(["Time (UTC)", "Platform", "Host", "Event", "User", "Source IP", "Target / detail", "Flags"],
                        [_event_row(by_id[i]) for i in corr["unlinked_alerts"]]))

    o.append("<h2>4. Evidence integrity and chain of custody</h2>")
    o.append(f'<p>Result of re-verifying the whole ledger and every evidence file: {"<span class=ok>ALL CHECKS PASSED</span>" if ok else "<span class=bad>TAMPERING OR ERROR DETECTED</span>"}. '
             f'Signed with HMAC: <b>{"yes" if ctx.get("hmac_used") else "no (plain hash chain: a fully rewritten chain would not be detected without the anchor)"}</b>. '
             f'Ledger head hash at verification: <span class="mono">{h(ctx["head_hash"] or "")}</span><br>'
             f'<span class="note">The final anchor hash (after this report was recorded in the ledger) is printed on the console and saved in <code>custody_head.txt</code>. Note it down outside the case folder: it is what detects deletion of the last ledger entries.</span></p>')
    o.append("<b>Evidence acquired</b>")
    o.append(_table(["Source", "File", "Size (bytes)", "SHA-256", "Copy verified"],
                    [[PLAT_NAME[a["source"]], h(a["file"]), a["size"], f'<span class="mono">{a["sha256"]}</span>',
                      '<span class="ok">yes</span>' if a["copy_verified"] else '<span class="bad">NO</span>'] for a in ctx["acquired"]]))
    for m in ctx["acquire_msgs"]:
        o.append(f"<p class='note'>{h(m)}</p>")
    o.append("<details><summary>Verification details (every ledger entry and file)</summary>")
    o.append(_table(["Type", "Item", "Result", "Note"], [[c["type"], h(c["item"]), '<span class="ok">OK</span>' if c["ok"] else '<span class="bad">FAIL</span>', h(c["note"])] for c in ctx["custody_checks"]]))
    o.append("</details>")

    host_ev = [e for e in events if e["source"] == "host"]
    if host_ev:
        import collections
        import json as _json
        import os as _os
        cnt = collections.Counter(e["event_type"] for e in host_ev)
        col = next((e for e in host_ev if e["event_type"] == "collection"), None)
        o.append("<h2>5. Live host evidence</h2>")
        if col:
            o.append(f"<p>{h(col['detail'] or '')} · host <b>{h(col['host'])}</b> · collected {h(col['time_utc'].replace('T', ' '))}</p>")
        o.append(_table(["Processes", "Network sockets", "Listeners", "Accounts", "Persistence entries", "Recent files", "Flagged"],
                        [[cnt["process_snapshot"], cnt["connection_snapshot"], cnt["listener_snapshot"], cnt["account_snapshot"],
                          cnt["persistence_entry"], cnt["file_snapshot"], sum(1 for e in host_ev if e["flags"])]]))
        mp = _os.path.join(ctx["case_dir"], "evidence", "host", "manifest.json")
        if _os.path.exists(mp):
            man = _json.load(open(mp, encoding="utf-8"))
            if man.get("limited"):
                o.append("<p class='note'><b>Collection limits (evidence that could NOT be collected):</b></p><ul class='note'>" +
                         "".join(f"<li>{h(v)}</li>" for v in man["limited"].values()) + "</ul>")
            o.append(f"<details><summary>Commands run and errors during collection</summary><p class='note'>Collector v{h(str(man.get('collector_version')))}, "
                     f"{man.get('duration_s')} s. Commands: {h('; '.join(c['cmd'] + ' (rc ' + str(c['rc']) + ')' for c in man.get('commands', [])) or 'none')}. "
                     f"Errors: {h('; '.join(man.get('errors', [])) or 'none')}.</p></details>")

    cloud_ev = [e for e in events if e["source"] == "aws" and e["event_type"] in CLOUD_STATE_TYPES]
    if cloud_ev:
        import collections as _c
        import json as _json
        import os as _os
        cc = _c.Counter(e["event_type"] for e in cloud_ev)
        o.append("<h2>6. Cloud account state (AWS)</h2>")
        o.append("<p class='note'>Configuration of the account when the investigation started. Findings here describe exposure and are listed under alerts; they only join an incident when they touch an entity of that incident.</p>")
        o.append(_table(["Trails", "Users", "Access keys", "Buckets", "Security groups", "Findings"],
                        [[cc["trail_state"], cc["iam_user_state"], cc["access_key_state"], cc["bucket_state"], cc["sg_state"], sum(1 for e in cloud_ev if e["flags"])]]))
        mp = _os.path.join(ctx["case_dir"], "evidence", "cloud", "manifest.json")
        if _os.path.exists(mp):
            man = _json.load(open(mp, encoding="utf-8"))
            if man.get("limited") or man.get("errors"):
                o.append("<p class='note'><b>Cloud state that could NOT be collected:</b></p><ul class='note'>" + "".join(f"<li>{h(v)}</li>" for v in man.get("limited", {}).values()) +
                         "".join(f"<li>{h(v)}</li>" for v in man.get("errors", [])) + "</ul>")

    o.append("<h2>7. Processing summary</h2>")
    o.append(_table(["Source", "Records seen", "Normalized", "Ignored (outside catalogue)", "Parse errors"],
                    [[PLAT_NAME[k], v["records_seen"], v["normalized"], v["ignored"], v["errors"]] for k, v in ctx["stats"].items()]))
    tm = ctx["timings"]
    o.append(_table(["Stage", "Time (s)"], [[k.replace("_", " "), f"{v:.3f}"] for k, v in tm.items() if k != "total"]))

    o.append("<h2>8. Method and limitations</h2>"
             "<p class='note'>Evidence was acquired read-only and copied with SHA-256 verification; every format was normalised into one "
             "UTC event schema; detection used the CP-DFIR rule set mapped to MITRE ATT&amp;CK; events were linked into incidents through "
             "shared entities (attacker IP address, credential file, cloud access key); every step was recorded in an HMAC-signed, "
             "hash-chained custody ledger. Findings are leads for the investigator to confirm, not automatic conclusions.</p><ul class='note'>"
             "<li>Detection is rule-based; thresholds are in <code>config.py</code>.</li>"
             "<li>Linux session attribution assumes a command belongs to the latest login of the same user on the same host (auth.log has no session id for sudo).</li>"
             "<li>The credential link uses the analyst-supplied <code>credential_inventory</code> in <code>case_config.json</code>; the logs alone do not show which key is stored in a file.</li>"
             "<li>&ldquo;Internal&rdquo; addresses are private ranges plus <code>internal_ranges</code> in the case config.</li></ul>")

    o.append("<h2>Appendix A. Full normalised timeline</h2>")
    lim = 1500
    o.append(f"<details><summary>Show events (first {min(lim, len(events))} of {len(events)})</summary>")
    o.append(_table(["Time (UTC)", "Platform", "Host", "Event", "User", "Source IP", "Target / detail", "Flags"], [_event_row(e) for e in events[:lim]]))
    o.append("</details>")
    o.append(page_close(f"Case {h(cid)} · generated {now}"))
    return "".join(o)


def write_report(ctx, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_report(ctx))
