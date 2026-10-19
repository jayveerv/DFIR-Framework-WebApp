/* CP-DFIR Investigation Console — single-page front end for webapp/app.py */
"use strict";
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = n => (n == null ? "–" : Math.round(n).toLocaleString("en-US"));
const bytes = n => n == null ? "–" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
const utc = t => t ? String(t).replace("T", " ").replace("Z", "Z") : "–";
const ago = t => { if (!t) return "–"; const s = (Date.now() - Date.parse(t)) / 1000;
  return s < 60 ? "just now" : s < 3600 ? Math.floor(s / 60) + " min ago" : s < 86400 ? Math.floor(s / 3600) + " h ago" : new Date(t).toLocaleDateString(); };
const PN = {windows:"Windows", linux:"Linux", aws:"AWS CloudTrail", host:"Live host", cloud:"AWS account state"};
const PC = {windows:"var(--win)", linux:"var(--lin)", aws:"var(--aws)", host:"var(--host)", cloud:"var(--cloud)"};
const KC = {windows_xml:"var(--win)", windows_evtx:"var(--win)", linux_auth:"var(--lin)", cloudtrail:"var(--aws)", cloud_state:"var(--cloud)", host_artifact:"var(--host)"};
const SVC = {high:"var(--rd)", medium:"var(--am)", low:"var(--mu2)", info:"var(--mu2)"};
const plat = p => `<span class="plat" style="--pc:${PC[p] || "var(--mu)"}">${esc(PN[p] || p)}</span>`;
const sev = s => `<span class="tag sev-${esc(String(s).toLowerCase())}">${esc(String(s).toUpperCase())}</span>`;
const I = {
 ov:'<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z"/>',
 col:'<path d="M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z"/><path d="M4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
 cor:'<circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7 7.5 10.5 16M17 7.5 13.5 16M7.5 6h9"/>',
 inv:'<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/><path d="M8 11h6M11 8v6"/>',
 mit:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
 cld:'<path d="M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18z"/>',
 cus:'<path d="M12 3 20 6v6c0 5-3.4 8.5-8 9.5C7.4 20.5 4 17 4 12V6z"/><path d="m9 12 2 2 4-4"/>',
 exp:'<path d="M4 6h16M4 12h16M4 18h10"/>', rep:'<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
 act:'<path d="M3 12h4l3-8 4 16 3-8h4"/>', fold:'<path d="M3 7a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
 res:'<path d="M3 20h18"/><path d="m4 16 5-5 4 3 7-8"/><path d="M15 6h5v5"/>', sys:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
 usr:'<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>', plus:'<path d="M12 5v14M5 12h14"/>',
 up:'<path d="M12 16V4M6 10l6-6 6 6"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>', play:'<path d="M7 4v16l13-8z"/>',
 bolt:'<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>', key:'<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14.5 8.5l2 2"/>',
 lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>', tgt:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5"/>',
 chk:'<path d="m5 12 5 5L20 7"/>', x:'<path d="M6 6l12 12M18 6 6 18"/>', alert:'<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
 trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>', dl:'<path d="M12 4v12M6 10l6 6 6-6"/><path d="M4 20h16"/>',
 term:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>', win:'<rect x="3" y="3" width="8" height="8"/><rect x="13" y="3" width="8" height="8"/><rect x="3" y="13" width="8" height="8"/><rect x="13" y="13" width="8" height="8"/>',
 lab:'<path d="M9 3h6M10 3v6L4 19a2 2 0 0 0 2 3h12a2 2 0 0 0 2-3L14 9V3"/>', cpu:'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
 out:'<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 16l4-4-4-4M14 12H4"/>', ref:'<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
 copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>', moon:'<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>', ext:'<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>'};
const ic = (k, s = 18) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${I[k] || ""}</svg>`;
const LOGO = `<svg width="34" height="34" viewBox="0 0 48 48"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#22D3EE"/><stop offset="1" stop-color="#A78BFA"/></linearGradient></defs>
<path d="M24 3 42 10v13c0 11-7.6 19.6-18 22C13.6 42.6 6 34 6 23V10z" fill="none" stroke="url(#lg)" stroke-width="3"/>
<circle cx="22" cy="22" r="7" fill="none" stroke="url(#lg)" stroke-width="2.6"/><path d="m27 27 6 6" stroke="url(#lg)" stroke-width="3" stroke-linecap="round"/></svg>`;
const TITLE = "A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, Correlation, and Cloud Forensic Investigation";

/* ---------------------------------------------------------------- state & api */
const S = {sess:null, case:null, res:null, cid:null, inc:0, exp:{page:0, q:"", source:"", flagged:false, incident:""}, verify:null, samples:null};
async function api(method, url, body, raw) {
  const o = {method, headers:{"X-Requested-With":"cpdfir"}, credentials:"same-origin"};
  if (body instanceof FormData) o.body = body;
  else if (body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
  const r = await fetch(url, o);
  if (r.status === 401 && !url.startsWith("/api/login")) { S.sess = null; location.hash = "#/login"; throw new Error("login required"); }
  let d = null; try { d = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error((d && d.error) || `${r.status} ${r.statusText}`);
  return d;
}
function toast(msg, c) { const t = document.createElement("div"); t.className = "toast"; t.style.setProperty("--c", c || "var(--cy)"); t.innerHTML = msg; $("#toasts").appendChild(t); setTimeout(() => t.remove(), 4200); }
const fail = e => toast(esc(e.message || e), "var(--rd)");

/* tooltip */
const tip = $("#tip");
document.addEventListener("mouseover", e => { const t = e.target.closest("[data-tip]"); if (t) { tip.innerHTML = t.dataset.tip; tip.style.display = "block"; mvTip(e); } });
document.addEventListener("mousemove", e => { if (tip.style.display === "block") { if (!e.target.closest("[data-tip]")) tip.style.display = "none"; else mvTip(e); } });
function mvTip(e) { tip.style.left = Math.min(e.clientX + 14, innerWidth - 420) + "px"; tip.style.top = Math.min(e.clientY + 14, innerHeight - tip.offsetHeight - 8) + "px"; }

/* modal */
function modal(title, body, foot, wide) {
  $("#modal").innerHTML = `<div class="mbg"><div class="modal ${wide ? "wide" : ""}"><div class="mh"><h2>${title}</h2><button class="btn sm ghost x" data-close>${ic("x", 15)}</button></div>
  <div class="mb">${body}</div>${foot ? `<div class="mf">${foot}</div>` : ""}</div></div>`;
  $("#modal [data-close]").onclick = closeModal;
  $("#modal .mbg").addEventListener("mousedown", e => { if (e.target.classList.contains("mbg") && !S.jobRunning) closeModal(); });
}
function closeModal() { $("#modal").innerHTML = ""; if (S.onClose) { const f = S.onClose; S.onClose = null; f(); } }
document.addEventListener("keydown", e => { if (e.key === "Escape" && $("#modal").innerHTML && !S.jobRunning) closeModal(); });

/* ---------------------------------------------------------------- jobs */
async function runJob(jobId, title, after) {
  S.jobRunning = true;
  modal(`<span class="spin" id="jsp"></span> ${esc(title)}`, `<div class="console" id="jcon"></div><div id="jres" style="margin-top:12px"></div>`,
    `<button class="btn" id="jclose" disabled>Close</button><button class="btn pri hide" id="jview">View results</button>`, true);
  let since = 0, j;
  const con = $("#jcon");
  while (true) {
    try { j = await api("GET", `/api/jobs/${jobId}?since=${since}`); } catch (e) { await new Promise(r => setTimeout(r, 1000)); continue; }
    if (j.lines.length) {
      con.insertAdjacentHTML("beforeend", j.lines.map(l => `<span class="t">${esc(l.t)}</span>  <span class="${/ERROR|FAIL|failed/.test(l.m) ? "e" : /VERIFIED|OK\b|passed/.test(l.m) ? "ok" : ""}">${esc(l.m)}</span>\n`).join(""));
      con.scrollTop = con.scrollHeight; since = j.n;
    }
    if (j.status !== "running") break;
    await new Promise(r => setTimeout(r, 450));
  }
  S.jobRunning = false;
  const sp = $("#jsp"); if (sp) sp.outerHTML = j.status === "done" ? `<span class="ok">${ic("chk", 18)}</span>` : `<span class="bad">${ic("x", 18)}</span>`;
  const r = j.result || {};
  $("#jres").innerHTML = j.status === "done"
    ? (r.incidents != null ? `<div class="info gr"><b>Analysis complete.</b> ${fmt(r.events)} events · ${fmt(r.alerts)} flagged · <b>${r.incidents}</b> incident(s)${r.high ? `, ${r.high} high` : ""} · custody ${r.custody_ok ? "VERIFIED" : "FAILED"}</div>` : `<div class="info gr"><b>Done.</b></div>`)
    : `<div class="info rd"><b>Failed:</b> ${esc(j.error)}</div>`;
  $("#jclose").disabled = false; $("#jclose").onclick = closeModal;
  if (j.status === "done" && r.incidents != null && S.cid) { const v = $("#jview"); v.classList.remove("hide"); v.onclick = () => { closeModal(); location.hash = `#/c/${S.cid}/${r.incidents ? "investigation" : "overview"}`; }; }
  S.onClose = after || null;
  return j;
}
async function startJob(kind, body, title) {
  try { const r = await api("POST", `/api/cases/${S.cid}/jobs/${kind}`, body || {}); await runJob(r.job, title, () => openCase(S.cid, true)); }
  catch (e) { fail(e); }
}

/* ---------------------------------------------------------------- router */
window.addEventListener("hashchange", route);
async function route() {
  const h = location.hash.replace(/^#\/?/, "").split("/");
  if (!S.sess) { try { S.sess = await api("GET", "/api/session"); } catch (e) { S.sess = null; } }
  if (!S.sess) return;
  if (S.sess.setup_needed) return viewSetup();
  if (!S.sess.user) return viewLogin();
  if (h[0] === "login" || h[0] === "setup" || !h[0]) { location.hash = "#/cases"; return; }
  if (h[0] === "c" && h[1]) return openCase(h[1], false, h[2] || "overview");
  S.cid = null; S.case = null; S.res = null;
  if (h[0] === "research") return shell(viewResearch, "research", "Research results");
  if (h[0] === "system") return shell(viewSystem, "system", "System & self-test");
  if (h[0] === "users") return shell(viewUsers, "users", "Users & audit log");
  return shell(viewCases, "cases", "Cases");
}

/* ---------------------------------------------------------------- auth */
function authPage(inner) {
  $("#app").innerHTML = `<div class="auth"><div class="authbox"><div class="authlogo">${LOGO.replace('width="34" height="34"', 'width="46" height="46"')}<div><b>CP-DFIR</b><small>Investigation Console</small></div></div>
  <div class="card">${inner}</div><div class="ttlbig">${esc(TITLE)}</div></div></div>`;
}
function viewLogin() {
  authPage(`<h2>Analyst sign in</h2><div class="sub">Every action you take is recorded in the case activity log and the chain-of-custody ledger.</div>
  <form id="lf"><div class="fr"><label class="f">Username</label><input class="in" name="username" autocomplete="username" autofocus></div>
  <div class="fr"><label class="f">Password</label><input class="in" type="password" name="password" autocomplete="current-password"></div>
  <div class="err" id="lerr"></div><button class="btn pri" style="width:100%;justify-content:center">${ic("lock", 16)} Sign in</button></form>`);
  $("#lf").onsubmit = async e => { e.preventDefault(); const f = new FormData(e.target);
    try { await api("POST", "/api/login", {username:f.get("username"), password:f.get("password")}); S.sess = null; location.hash = "#/cases"; route(); }
    catch (er) { $("#lerr").textContent = er.message; } };
}
function viewSetup() {
  authPage(`<h2>First-time setup</h2><div class="sub">Create the administrator account for this console. More analysts can be added later.</div>
  <form id="sf"><div class="fr"><label class="f">Full name (shown as the investigator in reports and the custody ledger)</label><input class="in" name="name" placeholder="Jayveer Vasava" autofocus></div>
  <div class="fr"><label class="f">Username</label><input class="in" name="username" placeholder="jayveer" autocomplete="username"></div>
  <div class="fr"><label class="f">Password (min. 8 characters)</label><input class="in" type="password" name="password" autocomplete="new-password"></div>
  <div class="fr"><label class="f">Confirm password</label><input class="in" type="password" name="password2" autocomplete="new-password"></div>
  <div class="err" id="serr"></div><button class="btn pri" style="width:100%;justify-content:center">${ic("chk", 16)} Create account</button></form>`);
  $("#sf").onsubmit = async e => { e.preventDefault(); const f = new FormData(e.target);
    if (f.get("password") !== f.get("password2")) { $("#serr").textContent = "passwords do not match"; return; }
    try { await api("POST", "/api/setup", {name:f.get("name"), username:f.get("username"), password:f.get("password")}); S.sess = null; location.hash = "#/cases"; route(); }
    catch (er) { $("#serr").textContent = er.message; } };
}
async function logout() { try { await api("POST", "/api/logout"); } catch (e) {} S.sess = null; location.hash = "#/login"; route(); }

/* ---------------------------------------------------------------- shell */
function navHtml(active) {
  const u = S.sess.user, c = S.case, r = S.res;
  const a = (href, k, label, key, cnt, red) => `<a href="${href}" class="${active === key ? "on" : ""}">${ic(k, 17)}<span>${label}</span>${cnt != null ? `<span class="cnt ${red ? "r" : ""}">${cnt}</span>` : ""}</a>`;
  let h = `<div class="grp">Workspace</div>${a("#/cases", "fold", "All cases", "cases")}`;
  if (c) {
    const b = `#/c/${c.id}/`, lr = c.last_run || {};
    h += `<div class="grp">Open case</div><div class="casebox"><div class="id">${esc(c.id)}</div><div class="t">${esc(c.title)}</div><div style="margin-top:6px"><span class="status ${c.job ? "running" : c.status}">${c.job ? "job running" : esc(c.status)}</span></div></div>
    ${a(b + "overview", "ov", "Overview", "overview")}${a(b + "evidence", "col", "Evidence", "evidence", c.evidence_items.length)}
    ${a(b + "investigation", "inv", "Investigation", "investigation", r && r.ready ? r.incidents.length : null, r && r.ready && r.incidents.some(i => i.severity === "High"))}
    ${a(b + "mitre", "mit", "MITRE ATT&amp;CK", "mitre", r && r.ready ? r.techs.filter(t => t.hits).length : null)}
    ${a(b + "cloud", "cld", "Cloud posture", "cloud", r && r.ready ? r.posture.length : null, r && r.ready && r.posture.some(p => p.sv === "high"))}
    ${a(b + "explorer", "exp", "Evidence explorer", "explorer", lr.events != null ? fmt(lr.events) : null)}
    ${a(b + "custody", "cus", "Chain of custody", "custody")}${a(b + "report", "rep", "Report &amp; export", "report")}${a(b + "activity", "act", "Activity log", "activity")}`;
  }
  h += `<div class="grp">Framework</div>${a("#/research", "res", "Research results", "research")}${a("#/system", "sys", "System &amp; self-test", "system")}
  ${u.role === "admin" ? a("#/users", "usr", "Users &amp; audit", "users") : ""}
  <div class="foot">${esc(S.sess.app)} v${esc(S.sess.version)}<br>Developed by Jayveer Vasava${S.sess.public_mode ? '<br><span class="warn">Public demo mode</span>' : ""}</div>`;
  return h;
}
function shell(view, active, crumb) {
  const u = S.sess.user;
  if (!$("#main") || !$("#nav")) {
    $("#app").innerHTML = `<div class="top"><a class="brand" href="#/cases">${LOGO}<div><b>CP-DFIR</b><small>Investigation Console</small></div></a>
    <div class="crumb" id="crumb"></div><span id="tpill"></span>
    <button class="tbtn" id="theme" title="Light / dark theme">${ic("moon", 15)}</button>
    <div class="who"><div class="av">${esc((u.name || u.username).split(/\s+/).map(x => x[0]).join("").slice(0, 2).toUpperCase())}</div><div>${esc(u.name)}<br><span style="font-size:11px;color:var(--mu2)">${esc(u.role)}</span></div></div>
    <button class="tbtn" id="lo" title="Sign out">${ic("out", 15)}</button></div><div class="wrap"><nav id="nav"></nav><main id="main"></main></div>`;
    $("#theme").onclick = () => { const l = document.documentElement.classList.toggle("light"); try { localStorage.setItem("cpdfir-theme", l ? "light" : "dark"); } catch (e) {} };
    $("#lo").onclick = logout;
  }
  $("#nav").innerHTML = navHtml(active);
  $("#crumb").innerHTML = S.case ? `<b>${esc(S.case.id)}</b> · ${esc(S.case.title)} <span style="color:var(--mu2)">/ ${esc(crumb)}</span>` : `<b>${esc(crumb)}</b>`;
  const c = S.case, lv = c && c.last_verify;
  $("#tpill").innerHTML = c && c.last_run ? (lv ? `<span class="pill ${lv.ok ? "ok" : "bad"}">${lv.ok ? '<span class="dot"></span>' : ic("x", 12)} custody ${lv.ok ? "verified" : "TAMPERED"} ${ago(lv.time)}</span>`
    : `<span class="pill ${c.last_run.custody_ok ? "ok" : "bad"}">${c.last_run.custody_ok ? '<span class="dot"></span>' : ""} custody ${c.last_run.custody_ok ? "verified at analysis" : "FAILED"}</span>`) : "";
  const m = $("#main"); m.innerHTML = `<div class="view" id="v"></div>`;
  window.scrollTo(0, 0);
  try { const out = view($("#v")); if (out && out.catch) out.catch(fail); } catch (e) { fail(e); console.error(e); }
}
const head = (kw, t, p, acts) => `<div class="sh"><div><div class="kw">${kw}</div><h1>${t}</h1>${p ? `<p>${p}</p>` : ""}</div>${acts ? `<div class="acts">${acts}</div>` : ""}</div>`;
const kpi = (v, l, s, c, icon) => `<div class="card kpi" style="--c:${c}"><div class="ic">${ic(icon, 20)}</div><div class="v">${v}</div><div class="l">${l}</div>${s ? `<div class="s">${s}</div>` : ""}</div>`;

/* ---------------------------------------------------------------- cases list */
async function viewCases(v) {
  v.innerHTML = head("Workspace", "Cases", "Each case holds its evidence, analysis results, chain-of-custody ledger and report. Create a case, add evidence, run the framework.",
    `<button class="btn pri" id="nc">${ic("plus", 16)} New case</button>`) + `<div id="cl"><div class="empty"><span class="spin"></span></div></div>`;
  $("#nc").onclick = newCaseModal;
  const cs = await api("GET", "/api/cases");
  if (!cs.length) {
    $("#cl").innerHTML = `<div class="card empty">${ic("fold", 40)}<div class="big">No cases yet</div><div class="note">Create a case and upload logs, collect live evidence from this computer or AWS, or start with a simulated attack scenario.</div>
    <div class="acts" style="justify-content:center;margin-top:16px"><button class="btn pri" id="nc2">${ic("plus", 16)} New case</button><button class="btn" id="demo">${ic("lab", 16)} Demo case (scenario S1 + cloud)</button></div></div>`;
    $("#nc2").onclick = newCaseModal;
    $("#demo").onclick = () => createCase({title:"Demo — cross-platform attack (S1)", description:"Simulated attack: Windows RDP brute force, Linux SSH compromise and AWS access-key abuse by one attacker.", sample:"S1_cloud"});
    return;
  }
  const tot = cs.reduce((a, c) => (a.inc += c.incidents || 0, a.high += c.high || 0, a.ev += c.events || 0, a.an += c.analyzed ? 1 : 0, a), {inc:0, high:0, ev:0, an:0});
  $("#cl").innerHTML = `<div class="g g4" style="margin-bottom:18px">${kpi(cs.length, "Cases", `${tot.an} analysed`, "var(--cy)", "fold")}${kpi(fmt(tot.ev), "Events normalised", "across all cases", "var(--vi)", "col")}
  ${kpi(tot.inc, "Incidents found", "correlated attack chains", "var(--am)", "cor")}${kpi(tot.high, "High-severity incidents", "need attention", "var(--rd)", "alert")}</div>
  <div class="cases">${cs.map(c => `<div class="card cc" data-id="${esc(c.id)}"><div style="display:flex;align-items:center;gap:8px"><span class="id">${esc(c.id)}</span><span style="margin-left:auto" class="status ${c.job ? "running" : c.status}">${c.job ? "running" : esc(c.status)}</span></div>
    <div class="t">${esc(c.title)}</div><div class="d">${esc(c.description) || '<span style="color:var(--mu2)">no description</span>'}</div>
    <div class="st"><div><b>${c.evidence}</b><span>evidence files</span></div><div><b class="${c.incidents ? (c.high ? "bad" : "warn") : ""}">${c.incidents ?? "–"}</b><span>incidents</span></div><div><b>${c.alerts != null ? fmt(c.alerts) : "–"}</b><span>flagged events</span></div></div>
    <div class="ft">${c.sources.map(plat).join(" ") || "no evidence yet"}<span style="margin-left:auto">${c.analyzed ? "analysed " + ago(c.analyzed) : "created " + ago(c.created)}</span>
    ${c.custody_ok === true ? `<span class="ok" data-tip="chain of custody verified">${ic("cus", 14)}</span>` : c.custody_ok === false ? `<span class="bad" data-tip="custody verification FAILED">${ic("alert", 14)}</span>` : ""}</div></div>`).join("")}</div>`;
  $$(".cc").forEach(x => x.onclick = () => location.hash = `#/c/${x.dataset.id}/overview`);
}
async function samples() { if (!S.samples) S.samples = await api("GET", "/api/samples"); return S.samples; }
async function newCaseModal() {
  const sm = await samples().catch(() => ({}));
  modal("New case", `<form id="ncf"><div class="fr"><label class="f">Case title</label><input class="in" name="title" placeholder="e.g. Suspicious SSH logins on web01" required></div>
  <div class="fr"><label class="f">Description (optional)</label><textarea class="in" name="description" style="font-family:inherit;font-size:13px" placeholder="What happened, who reported it, scope ..."></textarea></div>
  <div class="fr"><label class="f">Start with</label><select class="in" name="sample"><option value="">Empty case — I will add my own evidence</option>
  ${Object.entries(sm).map(([k, d]) => `<option value="${esc(k)}">Simulated scenario ${esc(k)} — ${esc(d)}</option>`).join("")}</select>
  <div class="hint">Simulated scenarios come from the framework's ground-truth generator and are useful for demonstrations.</div></div>
  <details><summary class="note" style="cursor:pointer;margin-bottom:10px">Case settings (can be changed later)</summary>${cfgForm({linux_timezone_offset:"+05:30", linux_log_year:new Date().getFullYear()})}</details>
  <div class="err" id="ncerr"></div></form>`, `<button class="btn" data-close>Cancel</button><button class="btn pri" id="ncgo">${ic("plus", 15)} Create case</button>`);
  $("#modal [data-close].btn:not(.x)") && ($$("#modal [data-close]").forEach(b => b.onclick = closeModal));
  $("#ncgo").onclick = () => { const f = new FormData($("#ncf")); const d = Object.fromEntries(f.entries()); if (!d.title.trim()) { $("#ncerr").textContent = "give the case a title"; return; } createCase(d); };
}
async function createCase(d) {
  try {
    const r = await api("POST", "/api/cases", d);
    closeModal(); toast(`Case <b>${esc(r.id)}</b> created`, "var(--gr)");
    if (r.job) { S.cid = r.id; location.hash = `#/c/${r.id}/overview`; await new Promise(x => setTimeout(x, 150)); await runJob(r.job, "Loading simulated evidence and analysing", () => openCase(r.id, true)); }
    else location.hash = `#/c/${r.id}/evidence`;
  } catch (e) { const er = $("#ncerr"); if (er) er.textContent = e.message; else fail(e); }
}
function cfgForm(c) {
  const inv = Object.entries(c.credential_inventory || {}).map(([k, v]) => `${k} = ${v}`).join("\n");
  return `<div class="row"><div class="fr"><label class="f">Linux log time zone</label><input class="in" name="linux_timezone_offset" value="${esc(c.linux_timezone_offset || "+05:30")}"><div class="hint">auth.log is in local time; IST = +05:30</div></div>
  <div class="fr"><label class="f">Linux log year</label><input class="in" name="linux_log_year" type="number" value="${esc(c.linux_log_year || new Date().getFullYear())}"><div class="hint">classic syslog lines have no year</div></div></div>
  <div class="fr"><label class="f">Internal IP ranges (besides RFC 1918)</label><input class="in" name="internal_ranges" value="${esc((c.internal_ranges || []).join(", "))}" placeholder="198.51.100.0/24, 203.0.113.0/28"><div class="hint">addresses here are treated as trusted, e.g. the office NAT</div></div>
  <div class="fr"><label class="f">Credential inventory — links a credential file on a host to the AWS key it holds</label><textarea class="in" name="credential_inventory" placeholder="web01:/home/ubuntu/.aws/credentials = AKIAEXAMPLE0001">${esc(inv)}</textarea><div class="hint">one per line: host:/path = ACCESS_KEY_ID. This is what lets the framework join a Linux credential read to AWS API calls made with that key.</div></div>
  <div class="fr"><label class="f">Privileged source allowlist (optional)</label><input class="in" name="privileged_source_allowlist" value="${esc((c.privileged_source_allowlist || []).join(", "))}" placeholder="10.0.5.10/32"><div class="hint">admin logons are expected only from these; others are flagged. Empty = rule off.</div></div>`;
}

/* ---------------------------------------------------------------- case */
const TABS = {overview:["Overview", tOverview], evidence:["Evidence", tEvidence], investigation:["Investigation", tInvestigation], mitre:["MITRE ATT&CK", tMitre],
  cloud:["Cloud posture", tCloud], explorer:["Evidence explorer", tExplorer], custody:["Chain of custody", tCustody], report:["Report & export", tReport], activity:["Activity log", tActivity]};
async function openCase(cid, refresh, tab) {
  tab = tab || S.tab || "overview"; if (!TABS[tab]) tab = "overview";
  if (refresh || S.cid !== cid || !S.case) {
    if (S.cid !== cid) { S.inc = 0; S.exp = {page:0, q:"", source:"", flagged:false, incident:""}; S.verify = null; }
    S.cid = cid;
    try { S.case = await api("GET", `/api/cases/${cid}`); } catch (e) { fail(e); location.hash = "#/cases"; return; }
    S.res = S.case.last_run ? await api("GET", `/api/cases/${cid}/results`).catch(() => null) : null;
  }
  S.tab = tab;
  const cur = location.hash.split("/")[3];
  if (refresh && cur && cur !== tab && TABS[cur]) tab = S.tab = cur;
  shell(TABS[tab][1], tab, TABS[tab][0]);
}
const ready = () => S.res && S.res.ready;
function needRun(v, what) {
  const c = S.case;
  v.innerHTML += `<div class="card empty">${ic(c.evidence_items.length ? "play" : "up", 40)}<div class="big">${c.evidence_items.length ? "Run the analysis to see " + what : "Add evidence first"}</div>
  <div class="note">${c.evidence_items.length ? `${c.evidence_items.length} evidence file(s) are waiting to be analysed.` : "Upload logs or run a collector on the Evidence page."}</div>
  <div class="acts" style="justify-content:center;margin-top:16px">${c.evidence_items.length ? `<button class="btn pri" data-run>${ic("play", 15)} Analyse now</button>` : `<a class="btn pri" href="#/c/${c.id}/evidence">${ic("up", 15)} Add evidence</a>`}</div></div>`;
  wire(v);
}
function wire(v) { v.querySelectorAll("[data-run]").forEach(b => b.onclick = analyse); v.querySelectorAll("[data-verify]").forEach(b => b.onclick = () => { location.hash = `#/c/${S.cid}/custody`; setTimeout(verify, 200); }); }
function analyse() { startJob("analyze", {}, `Analysing ${S.cid}`); }
const staleBox = () => S.case.status === "stale" ? `<div class="info" style="margin-bottom:16px"><b>Results are out of date.</b> Evidence or settings changed after the last analysis. <button class="btn sm" data-run style="margin-left:8px">${ic("ref", 13)} Re-analyse</button></div>` : "";

/* ---- overview */
function tOverview(v) {
  const c = S.case, lr = c.last_run;
  const acts = `<button class="btn pri" data-run ${c.evidence_items.length ? "" : "disabled"}>${ic("play", 15)} ${lr ? "Re-analyse" : "Analyse"}</button>${lr ? `<button class="btn" data-verify>${ic("cus", 15)} Verify custody</button>` : ""}`;
  v.innerHTML = head(esc(c.id), esc(c.title), esc(c.description) || `Created ${utc(c.created)} by ${esc(c.created_by)}`, acts);
  if (!ready()) { needRun(v, "the results"); return; }
  const R = S.res, run = R.run, cross = R.incidents.filter(i => i.cross).length;
  const order = [["acquisition", "Acquisition", "copy + SHA-256 before/after"], ["normalization", "Normalization", "common schema, UTC"], ["correlation", "Correlation", `${R.total_rules} rules + entity graph`],
    ["output_and_custody", "Custody", "hash-chained ledger"], ["custody_verification", "Verification", "chain + file hashes"], ["reporting", "Report", "self-contained HTML"]];
  const fl = R.plat_flag, ft = Object.values(fl).reduce((a, b) => a + b, 0);
  v.innerHTML += staleBox() + `<div class="g g5" style="margin-bottom:16px">${kpi(fmt(run.events), "Events normalised", `${Object.keys(run.stats).length} source type(s)`, "var(--cy)", "col")}
  ${kpi(fmt(run.alerts), "Events flagged", `${R.fired.length} rule(s) fired`, "var(--am)", "bolt")}
  ${kpi(run.incidents, "Incidents", `${run.high} high severity`, run.high ? "var(--rd)" : "var(--gr)", "alert")}
  ${kpi(cross, "Cross-platform", "incidents spanning platforms", "var(--vi)", "cor")}
  ${kpi(run.custody_ok ? "OK" : "FAIL", "Chain of custody", "HMAC-signed · " + R.ledger.length + " entries", run.custody_ok ? "var(--gr)" : "var(--rd)", "cus")}</div>
  <div class="card" style="margin-bottom:16px"><h3><i>${ic("bolt", 15)}</i>Framework pipeline — last run<span class="r note">${utc(run.time)} by ${esc(run.by)} · total ${(run.timings.total || 0).toFixed(3)} s</span></h3>
  <div class="flow">${order.map(([k, n, d], i) => `${i ? `<div class="fa">${ic("play", 12)}</div>` : ""}<div class="fs"><div class="n">STAGE ${i + 1}</div><div class="x">${n}</div><div class="y">${d}</div><div class="tm">${run.timings[k] != null ? (run.timings[k] * 1000).toFixed(1) + " ms" : "–"}</div></div>`).join("")}</div></div>
  <div class="g g32" style="margin-bottom:16px"><div class="card"><h3><i>${ic("alert", 15)}</i>Incidents</h3>${R.incidents.length ? `<div class="tw"><table><thead><tr><th>ID</th><th>Severity</th><th>Window (UTC)</th><th>Platforms</th><th>Events</th><th>Techniques</th></tr></thead><tbody>
  ${R.incidents.map((i, k) => `<tr class="click" data-inc="${k}"><td class="mono" style="white-space:nowrap"><b>${esc(i.id)}</b></td><td>${sev(i.severity)}</td><td class="mono">${utc(i.start)}<br><span style="color:var(--mu2)">→ ${utc(i.end)}</span></td><td>${i.platforms.map(plat).join("<br>")}</td><td class="mono">${i.count}</td><td>${i.techniques.slice(0, 5).map(t => `<span class="tag cy">${esc(t.id)}</span>`).join("")}${i.techniques.length > 5 ? `<span class="tag">+${i.techniques.length - 5}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`
  : `<div class="info gr"><b>No incident.</b> No connected chain of suspicious activity was found${R.unlinked.length ? `; ${R.unlinked.length} isolated alert(s) are listed on the Investigation page` : ""}.</div>`}</div>
  <div class="card"><h3><i>${ic("cor", 15)}</i>Flagged events by platform</h3>${ft ? donut(fl) : '<div class="note">nothing flagged</div>'}
  ${R.top_ips.length ? `<h3 style="margin-top:18px"><i>${ic("tgt", 15)}</i>Top external IPs in alerts</h3>${R.top_ips.slice(0, 6).map(([ip, n]) => `<div style="display:grid;grid-template-columns:130px 1fr 40px;gap:10px;align-items:center;margin:5px 0;font-size:12.5px"><span class="mono">${esc(ip)}</span><div class="bar"><i style="width:${n / R.top_ips[0][1] * 100}%;background:linear-gradient(90deg,var(--rd),var(--am))"></i></div><b class="mono" style="text-align:right">${n}</b></div>`).join("")}` : ""}</div></div>
  <div class="g g2"><div class="card"><h3><i>${ic("col", 15)}</i>Evidence sources</h3><div class="tw"><table><thead><tr><th>Source</th><th>Records</th><th>Normalised</th><th>Ignored</th><th>Errors</th></tr></thead><tbody>
  ${Object.entries(run.stats).map(([s, x]) => `<tr><td>${plat(s)}</td><td class="mono">${fmt(x.records_seen)}</td><td class="mono">${fmt(x.normalized)}</td><td class="mono">${fmt(x.ignored)}</td><td class="mono ${x.errors ? "bad" : ""}">${fmt(x.errors)}</td></tr>`).join("")}</tbody></table></div>
  ${(run.messages || []).length ? `<div class="note" style="margin-top:8px">${run.messages.map(esc).join("<br>")}</div>` : ""}</div>
  <div class="card"><h3><i>${ic("bolt", 15)}</i>Detection rules fired</h3><div class="tw max" style="max-height:300px"><table><thead><tr><th>Rule</th><th>ATT&amp;CK</th><th>Sev.</th><th>Events</th></tr></thead><tbody>
  ${R.fired.map(f => `<tr><td>${esc(f.name)}<div class="mono" style="color:var(--mu2)">${esc(f.rule)}</div></td><td><span class="tag cy" data-tip="${esc(f.tech.tactic)}: ${esc(f.tech.name)}">${esc(f.tech.id)}</span></td><td>${sev(f.severity)}</td><td class="mono">${f.count}</td></tr>`).join("") || '<tr><td colspan="4" class="note">none</td></tr>'}</tbody></table></div></div></div>`;
  wire(v);
  v.querySelectorAll("[data-inc]").forEach(r => r.onclick = () => { S.inc = +r.dataset.inc; location.hash = `#/c/${S.cid}/investigation`; });
}
function donut(m) {
  const E = Object.entries(m).sort((a, b) => b[1] - a[1]), T = E.reduce((a, b) => a + b[1], 0); let a0 = -Math.PI / 2, s = "";
  E.forEach(([k, n]) => { const a1 = a0 + n / T * Math.PI * 2, L = a1 - a0 > Math.PI ? 1 : 0, R = 54, r = 34;
    const p = (a, rr) => `${70 + rr * Math.cos(a)} ${70 + rr * Math.sin(a)}`;
    s += E.length === 1 ? `<circle cx="70" cy="70" r="44" fill="none" stroke="${PC[k]}" stroke-width="20"/>` : `<path d="M${p(a0, R)} A${R} ${R} 0 ${L} 1 ${p(a1, R)} L${p(a1, r)} A${r} ${r} 0 ${L} 0 ${p(a0, r)}z" fill="${PC[k]}" stroke="var(--panel)" stroke-width="2" data-tip="${esc(PN[k] || k)}: ${n}"/>`; a0 = a1; });
  return `<div class="donutw"><svg width="140" height="140" viewBox="0 0 140 140">${s}<text x="70" y="68" text-anchor="middle" font-size="22" font-weight="700" fill="var(--tx)">${T}</text><text x="70" y="86" text-anchor="middle" font-size="10" fill="var(--mu)">flagged</text></svg>
  <div class="lgl">${E.map(([k, n]) => `<div><i style="background:${PC[k]}"></i>${esc(PN[k] || k)}<b>${n}</b></div>`).join("")}</div></div>`;
}

/* ---- evidence */
function tEvidence(v) {
  const c = S.case, items = c.evidence_items, pm = S.sess.public_mode, win = S.sess.platform === "win32";
  v.innerHTML = head("Evidence intake", "Evidence", "Originals are stored read-only with their SHA-256 at intake. At analysis time the framework copies them into the case, hashes them again and records every step in the custody ledger.",
    `<button class="btn pri" data-run ${items.length ? "" : "disabled"}>${ic("play", 15)} ${c.last_run ? "Re-analyse" : "Analyse"} ${items.length} file(s)</button>`) + staleBox() +
  `<div class="g g32"><div><div class="card" style="margin-bottom:16px"><h3><i>${ic("up", 15)}</i>Upload evidence</h3>
  <div class="drop" id="drop">${ic("up", 34)}<div class="big">Drop files here or click to choose</div><div class="note">Windows <span class="mono">.evtx</span> / wevtutil <span class="mono">.xml</span> · Linux <span class="mono">auth.log</span> / <span class="mono">secure</span> · AWS <span class="mono">cloudtrail.json</span> · host/ and cloud/ artifacts · <span class="mono">case_config.json</span> · or a <span class="mono">.zip</span> of any of these</div></div>
  <input type="file" id="fi" multiple class="hide">
  <div class="row" style="margin-top:12px;align-items:center"><div style="flex:2"><label class="f">File type</label><select class="in" id="kind"><option value="">Detect automatically</option>${Object.entries(c.kinds).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join("")}</select></div><div class="note" style="flex:3">Auto-detection reads the file content (EVTX header, XML events, syslog lines, CloudTrail records). Unsupported files are skipped and reported.</div></div>
  <div id="upres"></div></div>
  <div class="card"><h3><i>${ic("fold", 15)}</i>Evidence in this case<span class="r note">${items.length} file(s) · ${bytes(items.reduce((a, b) => a + b.size, 0))}</span></h3>
  ${items.length ? `<div class="tw max"><table><thead><tr><th>File</th><th>Type</th><th>SHA-256 at intake</th><th>Size</th><th>Added</th><th></th></tr></thead><tbody>
  ${items.map(it => `<tr><td style="word-break:break-all"><b>${esc(it.name)}</b></td><td><span class="kind" style="--pc:${KC[it.kind]}">${esc(c.kinds[it.kind] || it.kind)}</span></td>
  <td class="mono" style="white-space:nowrap"><span data-tip="${esc(it.sha256)}">${esc(it.sha256.slice(0, 12))}…</span> <button class="btn sm ghost" data-copy="${esc(it.sha256)}" title="copy">${ic("copy", 12)}</button></td><td class="mono" style="white-space:nowrap">${bytes(it.size)}</td>
  <td style="font-size:11.5px;white-space:nowrap">${esc(it.added_by)} · <span style="color:var(--mu2)">${ago(it.added)}</span><div class="mono" style="font-size:10.5px;color:var(--mu2)">${esc(it.origin)}</div></td>
  <td style="white-space:nowrap"><a class="btn sm ghost" href="/api/cases/${c.id}/evidence/${it.id}/download" title="download original">${ic("dl", 13)}</a><button class="btn sm ghost danger" data-del="${it.id}" title="remove">${ic("trash", 13)}</button></td></tr>`).join("")}</tbody></table></div>`
  : `<div class="empty" style="padding:20px"><div class="note">No evidence yet — upload files or use a collector.</div></div>`}</div>
  <div class="card" style="margin-top:16px"><h3><i>${ic("sys", 15)}</i>Case settings</h3><form id="cfgf">${cfgForm(c.config)}<button class="btn" type="submit">${ic("chk", 14)} Save settings</button></form></div></div>
  <div><div class="card" style="margin-bottom:16px"><h3><i>${ic("bolt", 15)}</i>Collect evidence</h3>
  ${coll("triage", "cpu", "var(--host)", "Live triage — this computer", "Processes, network connections, accounts, persistence, recent files and security logs, read-only, in order of volatility.", pm ? "disabled in public demo" : "")}
  ${coll("aws", "cld", "var(--aws)", "AWS — CloudTrail + account state", "Read-only API calls: CloudTrail events, IAM users/keys/MFA, roles, S3 public access, security groups, trails.")}
  ${coll("ssh", "term", "var(--lin)", "Linux server — auth log over SSH", "Copies /var/log/auth.log (or /var/log/secure) with key-based SSH.", pm ? "disabled in public demo" : "")}
  ${coll("winlog", "win", "var(--win)", "Windows — export Security log", "wevtutil export of this computer's Security log (run the console as Administrator).", pm ? "disabled in public demo" : (win ? "" : "only when the console runs on Windows"))}
  ${coll("sample", "lab", "var(--vi)", "Simulated attack scenario", "Adds the framework's generated Windows + Linux + AWS logs for scenario S1–S5 (with ground truth).")}</div></div></div>`;
  wire(v);
  const fi = $("#fi"), dr = $("#drop");
  dr.onclick = () => fi.click(); fi.onchange = () => upload(fi.files);
  dr.ondragover = e => { e.preventDefault(); dr.classList.add("over"); }; dr.ondragleave = () => dr.classList.remove("over");
  dr.ondrop = e => { e.preventDefault(); dr.classList.remove("over"); upload(e.dataTransfer.files); };
  v.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => { navigator.clipboard && navigator.clipboard.writeText(b.dataset.copy); toast("SHA-256 copied"); });
  v.querySelectorAll("[data-del]").forEach(b => b.onclick = () => delEvidence(b.dataset.del));
  v.querySelectorAll("[data-coll]").forEach(b => b.onclick = () => COLL[b.dataset.coll]());
  $("#cfgf").onsubmit = async e => { e.preventDefault(); try { await api("PATCH", `/api/cases/${c.id}`, Object.fromEntries(new FormData(e.target).entries())); toast("Settings saved", "var(--gr)"); openCase(c.id, true); } catch (er) { fail(er); } };
}
const coll = (k, icon, c, x, y, dis) => `<div class="coll" style="--c:${c}"><div class="ic">${ic(icon, 20)}</div><div><div class="x">${x}</div><div class="y">${y}${dis ? `<br><span class="warn">${dis}</span>` : ""}</div></div><button class="btn sm b" data-coll="${k}" ${dis ? "disabled" : ""}>${ic("play", 12)} Start</button></div>`;
async function upload(files) {
  if (!files || !files.length) return;
  const fd = new FormData(); [...files].forEach(f => fd.append("files", f)); const k = $("#kind").value; if (k) fd.append("kind", k);
  $("#upres").innerHTML = `<div class="note" style="margin-top:12px"><span class="spin"></span> uploading ${files.length} file(s) and computing SHA-256 ...</div>`;
  try {
    const r = await api("POST", `/api/cases/${S.cid}/evidence`, fd);
    await openCase(S.cid, true, "evidence");
    $("#upres").innerHTML = `<div class="tw" style="margin-top:12px"><table><thead><tr><th>File</th><th>Result</th><th>SHA-256</th></tr></thead><tbody>${r.report.map(x => `<tr><td>${esc(x.name)}</td><td>${x.ok ? `<span class="ok">${ic("chk", 13)}</span> ${esc(S.case.kinds[x.kind] || x.kind)}${x.note ? " — " + esc(x.note) : ""}` : `<span class="bad">${ic("x", 13)}</span> ${esc(x.note)}`}</td><td class="mono">${x.sha256 ? esc(x.sha256.slice(0, 20)) + "…" : ""}</td></tr>`).join("")}</tbody></table></div>`;
    const n = r.report.filter(x => x.ok && x.kind !== "zip" && x.kind !== "case_config").length;
    toast(`${n} evidence file(s) added`, n ? "var(--gr)" : "var(--am)");
  } catch (e) { $("#upres").innerHTML = ""; fail(e); }
}
async function delEvidence(id) {
  const it = S.case.evidence_items.find(x => x.id === id);
  modal("Remove evidence", `<div class="note">Remove <b>${esc(it.name)}</b> (<span class="mono">${esc(it.sha256.slice(0, 16))}…</span>) from this case? The removal is recorded in the activity log. Re-analyse afterwards.</div>`,
    `<button class="btn" data-close>Cancel</button><button class="btn danger" id="dg">${ic("trash", 14)} Remove</button>`);
  $$("#modal [data-close]").forEach(b => b.onclick = closeModal);
  $("#dg").onclick = async () => { try { await api("DELETE", `/api/cases/${S.cid}/evidence/${id}`); closeModal(); toast("Evidence removed"); openCase(S.cid, true, "evidence"); } catch (e) { fail(e); } };
}
function formModal(title, body, go, label) {
  modal(title, `<form id="mf">${body}<label class="chk"><input type="checkbox" name="analyze" checked> Analyse the case right after collecting</label><div class="err" id="merr"></div></form>`,
    `<button class="btn" data-close>Cancel</button><button class="btn pri" id="mgo">${ic("play", 14)} ${label || "Start"}</button>`);
  $$("#modal [data-close]").forEach(b => b.onclick = closeModal);
  $("#mgo").onclick = () => { const f = new FormData($("#mf")); const d = Object.fromEntries(f.entries()); d.analyze = f.get("analyze") === "on"; $$("#mf input[type=checkbox]").forEach(x => d[x.name] = x.checked); go(d); };
}
const COLL = {
  triage: () => formModal("Live triage of this computer", `<div class="info cy" style="margin-bottom:14px"><b>Read-only collection</b> of the computer this console runs on: system info, processes (with executable SHA-256), network sockets, local accounts and admin groups, persistence (Run keys, services, scheduled tasks / cron, systemd, authorized_keys), recent files in temp/download folders, and the security logs. On Windows run the console as Administrator to include the Security log.</div>
    <div class="row"><div class="fr"><label class="f">Recent-file window (days)</label><input class="in" type="number" name="days" value="7" min="1" max="90"></div></div>
    <label class="chk"><input type="checkbox" name="logs" checked> Include security logs (Security/System/PowerShell .evtx on Windows, auth.log or journal on Linux)</label>`,
    d => { d.days = +d.days || 7; closeModal(); startJob("triage", d, "Live triage of this computer"); }, "Collect"),
  aws: () => formModal("AWS CloudTrail and account state", `<div class="info cy" style="margin-bottom:14px"><b>Read-only.</b> Use an IAM user with the ReadOnlyAccess policy (or cloudtrail:LookupEvents plus the List/Get/Describe calls). Keys are used for this collection only and are <b>not stored</b>. Leave the keys empty to use the AWS profile configured on this computer (<span class="mono">aws configure</span>).</div>
    <div class="row"><div class="fr"><label class="f">Access key ID</label><input class="in" name="access_key" placeholder="AKIA..." autocomplete="off"></div><div class="fr"><label class="f">Secret access key</label><input class="in" type="password" name="secret_key" autocomplete="off"></div></div>
    <div class="row"><div class="fr"><label class="f">Session token (temporary credentials only)</label><input class="in" type="password" name="session_token" autocomplete="off"></div><div class="fr"><label class="f">or AWS profile name</label><input class="in" name="profile" placeholder="default"></div></div>
    <div class="row"><div class="fr"><label class="f">Region</label><input class="in" name="region" value="ap-south-1"></div><div class="fr"><label class="f">CloudTrail days (max 90)</label><input class="in" type="number" name="days" value="7" min="1" max="90"></div></div>
    <label class="chk"><input type="checkbox" name="state" checked> Also collect the account state (IAM, keys, MFA, roles, S3, security groups, trails)</label>
    <label class="chk"><input type="checkbox" name="all_regions"> Security groups in every region</label>`,
    d => { d.days = +d.days || 7; closeModal(); startJob("aws", d, "Collecting from AWS"); }, "Collect"),
  ssh: () => formModal("Linux server over SSH", `<div class="info cy" style="margin-bottom:14px"><b>Key-based SSH</b> (it never asks for a password). The private key is written to a temporary file for this one connection and deleted afterwards. The SSH client of this computer is used.</div>
    <div class="row"><div class="fr"><label class="f">Host / IP</label><input class="in" name="host" placeholder="203.0.113.10"></div><div class="fr"><label class="f">User</label><input class="in" name="username" value="ubuntu"></div><div class="fr" style="max-width:110px"><label class="f">Port</label><input class="in" type="number" name="port" value="22"></div></div>
    <div class="fr"><label class="f">Log path</label><input class="in" name="path" value="/var/log/auth.log"><div class="hint">RHEL / CentOS / Amazon Linux: /var/log/secure</div></div>
    <div class="fr"><label class="f">Private key (paste the PEM / OpenSSH key, or leave empty to use this computer's ssh agent / default key)</label><textarea class="in" name="key_text" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></div>
    <label class="chk"><input type="checkbox" name="sudo" checked> Use sudo to read the log</label>`,
    d => { if (!d.host) { $("#merr").textContent = "give the host"; return; } closeModal(); startJob("ssh", d, `Copying ${d.path} from ${d.host}`); }, "Collect"),
  winlog: () => formModal("Export the Windows Security log", `<div class="info cy" style="margin-bottom:14px">Runs <span class="mono">wevtutil qe Security /f:xml</span> on this computer. Requires the console to be started as Administrator.</div>
    <div class="fr"><label class="f">Number of most recent events</label><input class="in" type="number" name="count" value="5000" min="100" max="200000"></div>`,
    d => { closeModal(); startJob("winlog", d, "Exporting the Windows Security log"); }, "Export"),
  sample: async () => { const sm = await samples(); formModal("Add a simulated scenario", `<div class="fr"><label class="f">Scenario</label><select class="in" name="scenario">${Object.entries(sm).map(([k, d]) => `<option value="${esc(k)}">${esc(k)} — ${esc(d)}</option>`).join("")}</select></div>
    <div class="note">Generated by <span class="mono">generate_data.py</span>. The scenario's case_config.json (credential inventory, internal ranges) is merged into this case's settings.</div>`,
    d => { closeModal(); startJob("sample", d, `Adding scenario ${d.scenario}`); }, "Add"); },
};

/* ---- investigation */
function tInvestigation(v) {
  v.innerHTML = head("Attack investigation", "Reconstructed attack", "The framework linked these events through shared entities (attacker IP, credential file, cloud access key). Drag nodes, scroll to zoom, hover anything for evidence details.");
  if (!ready()) { needRun(v, "the attack reconstruction"); return; }
  const R = S.res; if (S.inc >= R.incidents.length) S.inc = 0;
  v.innerHTML += staleBox();
  if (!R.incidents.length) {
    v.innerHTML += `<div class="info gr" style="margin-bottom:16px"><b>No incident in this case.</b> The framework did not find a connected chain of suspicious activity.</div>`;
  } else {
    v.innerHTML += `<div class="card" style="margin-bottom:16px;display:flex;gap:18px;align-items:center;flex-wrap:wrap"><div><div class="kw" style="margin-bottom:6px">Incident</div><div class="chips" id="incChips">${R.incidents.map((x, i) => `<span class="chip ${i === S.inc ? "on" : ""}" data-i="${i}">${esc(x.id)} · ${esc(x.severity)}</span>`).join("")}</div></div><div id="incHead" style="margin-left:auto;text-align:right"></div></div>
    <div class="card" style="margin-bottom:16px"><h3><i>${ic("cor", 15)}</i>Entity graph — how the evidence was linked</h3><div class="gwrap" id="gwrap"></div>
    <div class="legend"><span><i style="background:var(--rd)"></i>Attacker IP</span><span><i style="background:var(--am)"></i>Credential file</span><span><i style="background:var(--cy)"></i>Cloud access key</span><span style="margin-left:auto">platform dots: ${["windows", "linux", "aws", "host"].map(plat).join(" ")}</span></div></div>
    <div class="card" style="margin-bottom:16px"><h3><i>${ic("res", 15)}</i>Cross-platform timeline</h3><div id="tl"></div></div>
    <div class="g g23" style="margin-bottom:16px"><div class="card"><h3><i>${ic("alert", 15)}</i>Attack story</h3><ol class="story" id="story"></ol></div>
    <div class="card"><h3><i>${ic("mit", 15)}</i>Kill chain — ATT&amp;CK stages in order</h3><ol class="kc2" id="kc"></ol></div></div>
    <div class="card" style="margin-bottom:16px"><h3><i>${ic("exp", 15)}</i>Incident events<span class="r"><button class="btn sm" id="toexp">${ic("ext", 12)} Open in explorer</button></span></h3><div id="ievt"></div></div>`;
  }
  if (R.unlinked.length) v.innerHTML += `<div class="card"><h3><i>${ic("bolt", 15)}</i>Alerts not linked to an incident<span class="r note">${R.unlinked.length} event(s) — flagged by a rule but sharing no entity with an attack chain</span></h3>${evTable(R.unlinked.slice(0, 300), true)}</div>`;
  wire(v); wireEvRows(v);
  if (!R.incidents.length) return;
  v.querySelectorAll("#incChips .chip").forEach(x => x.onclick = () => { S.inc = +x.dataset.i; tInvestigation(v); });
  drawInc(R.incidents[S.inc]);
  $("#toexp").onclick = () => { S.exp = {page:0, q:"", source:"", flagged:false, incident:R.incidents[S.inc].id}; location.hash = `#/c/${S.cid}/explorer`; };
}
function drawInc(inc) {
  $("#incHead").innerHTML = `<div>${sev(inc.severity)} ${inc.cross ? '<span class="tag cy">CROSS-PLATFORM</span>' : '<span class="tag">SINGLE PLATFORM</span>'}</div>
  <div class="mono" style="margin-top:6px;color:var(--mu)">${utc(inc.start)} → ${utc(inc.end)}</div><div style="margin-top:4px">${inc.platforms.map(plat).join(" &nbsp;")} · <b>${inc.count}</b> events · <b>${inc.techniques.length}</b> techniques</div>`;
  $("#story").innerHTML = inc.stages.map(s => `<li style="--c:${SVC[s.severity]}"><div class="t">${utc(s.first)} · ${(s.sources || []).map(x => `<span style="color:${PC[x]}">${esc(PN[x] || x)}</span>`).join(" + ")} · ${(s.hosts || []).map(esc).join(", ")}</div>
  <div class="n"><b>${esc(s.name)}</b> <span class="tag cy">${esc(s.technique)}</span> ${s.count > 1 ? `<span class="note">× ${s.count}</span>` : ""}</div></li>`).join("");
  graph(inc); timeline(inc);
  $("#kc").innerHTML = inc.stages.map((s, i) => `<li style="--c:${SVC[s.severity]}"><div class="k">${String(i + 1).padStart(2, "0")}</div><div class="t">${(s.first || "").slice(11).replace("Z", " UTC")} · ${(s.sources || []).map(x => `<span style="color:${PC[x]}">${esc(PN[x] || x)}</span>`).join(" + ")}</div>
  <div class="n">${esc(s.name)}</div><div><span class="tag cy">${esc(s.technique)}</span> ${sev(s.severity)} <span class="note">${s.count} event${s.count === 1 ? "" : "s"}</span></div></li>`).join("");
  $("#ievt").innerHTML = evTable(inc.events.slice(0, 400)) + (inc.events_total > 400 ? `<div class="note" style="margin-top:8px">showing 400 of ${inc.events_total} — open the explorer for all</div>` : "");
  wireEvRows($("#ievt"));
}
function evTable(rows, showInc) {
  return `<div class="tw max"><table><thead><tr><th>Time (UTC)</th><th>Source</th><th>Host</th><th>Event</th><th>User</th><th>Src IP</th><th>Target / detail</th><th>Rules</th>${showInc ? "" : ""}</tr></thead><tbody>
  ${rows.map(e => `<tr class="click" data-ev="${esc(e.id)}"><td class="mono" style="white-space:nowrap">${utc(e.t)}</td><td>${plat(e.s)}</td><td class="mono">${esc(e.h)}</td><td class="mono">${esc(e.ty)}</td><td class="mono">${esc(e.u)}</td><td class="mono">${esc(e.ip)}</td>
  <td class="trunc" title="${esc(e.tg)}">${esc(e.tg)}</td><td>${e.f.length ? `<span class="tag sev-${esc(e.sv)}" data-tip="${esc(e.f.join(", "))}">${esc(e.f[0])}${e.f.length > 1 ? " +" + (e.f.length - 1) : ""}</span>` : '<span style="color:var(--mu2)">–</span>'}</td></tr>`).join("") || '<tr><td colspan="8" class="note">no events</td></tr>'}</tbody></table></div>`;
}
function wireEvRows(root) { root.querySelectorAll("[data-ev]").forEach(r => r.onclick = () => showEvent(r.dataset.ev)); }
async function showEvent(id) {
  try {
    const e = await api("GET", `/api/cases/${S.cid}/events/${id}`);
    const kv = [["Event ID", e.event_id], ["Time (UTC)", e.time_utc], ["Source", PN[e.source] || e.source], ["Host", e.host], ["Event type", e.event_type], ["User", e.user], ["Source IP", e.src_ip],
      ["Target", e.target], ["Outcome", e.outcome], ["Detail", e.detail], ["Session", e.session_id], ["Access key", e.key_id], ["New key", e.new_key_id], ["Incident", e.incident],
      ["Severity", e.severity], ["Rules", (e.flags || []).join(", ")], ["ATT&CK", (e.techniques || []).join(", ")], ["Evidence file", `${e.source_file} : line/record ${e.line_ref}`]].filter(x => x[1] != null && x[1] !== "");
    modal(`Event <span class="mono">${esc(e.event_id)}</span>`, `<div class="kv">${kv.map(([k, x]) => `<div>${esc(k)}</div><div class="${/ID|Time|IP|key|file/i.test(k) ? "mono" : ""}">${esc(x)}</div>`).join("")}</div>
    <h3 style="font-size:12px;color:var(--mu);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 8px">Original record</h3><pre class="json">${esc(e.excerpt || e.raw || "")}${e.extra ? "\n\n" + esc(JSON.stringify(e.extra, null, 1)) : ""}</pre>
    <div class="note">Provenance: the record can be found in the acquired evidence copy <span class="mono">${esc(e.source_file)}</span>, whose SHA-256 is in the custody ledger.</div>`, "", true);
  } catch (er) { fail(er); }
}
function graph(inc) {
  const KCOL = {ip:"var(--rd)", cred:"var(--am)", key:"var(--cy)"}, KX = {ip:150, cred:520, key:890}, TT = {ip:"ATTACKER IP", cred:"CREDENTIAL FILE", key:"CLOUD ACCESS KEY"};
  const cols = {ip:[], cred:[], key:[]}; inc.entities.forEach(n => (cols[n.kind] || (cols[n.kind] = [])).push(n));
  const mx = Math.max(1, ...Object.values(cols).map(l => l.length)), W = 1060, H = Math.max(260, 70 + mx * 84);
  const present = Object.keys(cols).filter(k => cols[k].length); present.forEach((k, i) => KX[k] = present.length === 1 ? W / 2 : Math.round(150 + i * (W - 300) / (present.length - 1)));
  const pos = {}; Object.entries(cols).forEach(([k, l]) => l.forEach((n, i) => { pos[n.id] = {x:KX[k] || 520, y:H / 2 + (i - (l.length - 1) / 2) * 84 + 12, n}; }));
  const SH = {"credential file read in session":"credential read", "credential inventory (file holds key)":"file holds key", "key created by key":"key created"};
  let s = `<svg id="gsvg" viewBox="0 0 ${W} ${H}"><defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--mu)"/></marker>
  <filter id="gl"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><g id="vp">`;
  Object.entries(TT).forEach(([k, t]) => { if (cols[k].length) s += `<text x="${KX[k]}" y="26" text-anchor="middle" font-size="11" letter-spacing="1.6" font-weight="700" fill="${KCOL[k]}">${t}</text>`; });
  inc.links.forEach(l => { if (pos[l.a] && pos[l.b]) s += `<g class="ed" data-a="${esc(l.a)}" data-b="${esc(l.b)}"><path class="edge" stroke="var(--mu)" stroke-width="1.8" fill="none" marker-end="url(#ar)"/><text font-size="10.5" text-anchor="middle" fill="var(--mu)" style="paint-order:stroke;stroke:var(--bg2);stroke-width:4px">${esc(SH[l.reason] || l.reason)} · ${l.events}</text></g>`; });
  Object.values(pos).forEach(p => { const n = p.n, lab = n.id.split(":").slice(1).join(":"), short = lab.length > 26 ? "…" + lab.slice(-25) : lab, c = KCOL[n.kind] || "var(--vi)";
    s += `<g class="gnode" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})" data-tip="<b>${esc(n.kind.toUpperCase())}</b><br><span class=mono>${esc(lab)}</span><br>${esc(n.platforms.map(x => PN[x] || x).join(" + "))} · ${n.events} events">
    <rect x="-108" y="-26" width="216" height="52" rx="12" fill="color-mix(in srgb,${c} 16%,var(--panel))" stroke="${c}" stroke-width="1.6" filter="url(#gl)"/>
    <text x="-95" y="-4" font-size="12" font-weight="700" fill="var(--tx)" font-family="Consolas,monospace">${esc(short)}</text>
    <text x="-95" y="14" font-size="10.5" fill="var(--mu)">${n.events} event${n.events === 1 ? "" : "s"}</text>
    ${n.platforms.map((x, i) => `<circle cx="${92 - i * 14}" cy="12" r="5" fill="${PC[x] || "var(--mu)"}"/>`).join("")}</g>`; });
  s += `</g></svg><div class="gtools"><button id="zi">+</button><button id="zo">−</button><button id="zr">⟲</button></div>`;
  $("#gwrap").innerHTML = s;
  const svg = $("#gsvg"), vp = $("#vp"); let T = {x:0, y:0, k:1};
  const apply = () => vp.setAttribute("transform", `translate(${T.x},${T.y}) scale(${T.k})`);
  const upd = () => svg.querySelectorAll(".ed").forEach(e => { const a = pos[e.dataset.a], b = pos[e.dataset.b]; let d, mx2, my;
    if (Math.abs(a.x - b.x) < 5) { const x = a.x + 108; d = `M${x} ${a.y}C${x + 70} ${a.y} ${x + 70} ${b.y} ${x + 4} ${b.y}`; mx2 = x + 56; my = (a.y + b.y) / 2; }
    else { const s1 = a.x < b.x ? 1 : -1, x1 = a.x + 108 * s1, x2 = b.x - 112 * s1; d = `M${x1} ${a.y}C${(x1 + x2) / 2} ${a.y} ${(x1 + x2) / 2} ${b.y} ${x2} ${b.y}`; mx2 = (x1 + x2) / 2; my = (a.y + b.y) / 2 - 6; }
    e.querySelector("path").setAttribute("d", d); const t = e.querySelector("text"); t.setAttribute("x", mx2); t.setAttribute("y", my); });
  upd();
  const pt = ev => { const r = svg.getBoundingClientRect(), sx = W / r.width, sy = H / r.height; return {x:((ev.clientX - r.left) * sx - T.x) / T.k, y:((ev.clientY - r.top) * sy - T.y) / T.k}; };
  let drag = null, pan = null;
  svg.querySelectorAll(".gnode").forEach(g => g.addEventListener("mousedown", ev => { ev.stopPropagation(); const p = pos[g.dataset.id], q = pt(ev); drag = {g, p, dx:q.x - p.x, dy:q.y - p.y}; }));
  svg.addEventListener("mousedown", ev => { pan = {x:ev.clientX, y:ev.clientY, tx:T.x, ty:T.y}; });
  const mm = ev => { if (!document.body.contains(svg)) return window.removeEventListener("mousemove", mm);
    if (drag) { const q = pt(ev); drag.p.x = q.x - drag.dx; drag.p.y = q.y - drag.dy; drag.g.setAttribute("transform", `translate(${drag.p.x},${drag.p.y})`); upd(); }
    else if (pan) { const r = svg.getBoundingClientRect(); T.x = pan.tx + (ev.clientX - pan.x) * W / r.width; T.y = pan.ty + (ev.clientY - pan.y) * H / r.height; apply(); } };
  window.addEventListener("mousemove", mm); window.addEventListener("mouseup", () => { drag = null; pan = null; });
  const zoom = f => { T.x = W / 2 - (W / 2 - T.x) * f; T.y = H / 2 - (H / 2 - T.y) * f; T.k *= f; apply(); };
  svg.addEventListener("wheel", ev => { ev.preventDefault(); zoom(ev.deltaY < 0 ? 1.1 : 1 / 1.1); }, {passive:false});
  $("#zi").onclick = () => zoom(1.2); $("#zo").onclick = () => zoom(1 / 1.2); $("#zr").onclick = () => { T = {x:0, y:0, k:1}; apply(); };
}
function timeline(inc) {
  const ev = inc.events; if (!ev.length) { $("#tl").innerHTML = ""; return; }
  const lanes = ["windows", "linux", "aws", "host", "cloud"].filter(l => ev.some(e => e.s === l)), W = 1200, L = 130, R = 30, top = 14, lh = 58, H = top + lanes.length * lh + 34;
  const t0 = Math.min(...ev.map(e => e.e)), t1 = Math.max(...ev.map(e => e.e)), sp = Math.max(t1 - t0, 1), X = t => L + (t - t0) / sp * (W - L - R);
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%">`;
  lanes.forEach((l, i) => { const y = top + i * lh; s += `<rect x="${L - 6}" y="${y}" width="${W - L - R + 12}" height="${lh - 12}" rx="9" fill="color-mix(in srgb,${PC[l]} 7%,transparent)" stroke="color-mix(in srgb,${PC[l]} 30%,transparent)"/>
    <text x="${L - 16}" y="${y + lh / 2 - 2}" text-anchor="end" font-size="12.5" font-weight="700" fill="${PC[l]}">${esc(PN[l])}</text>`; });
  for (let k = 0; k <= 6; k++) { const t = t0 + sp * k / 6, x = X(t); s += `<line x1="${x}" x2="${x}" y1="${top}" y2="${top + lanes.length * lh - 10}" stroke="var(--line)" stroke-dasharray="3 4"/><text x="${x}" y="${H - 10}" text-anchor="middle" font-size="11" fill="var(--mu)" font-family="Consolas,monospace">${new Date(t * 1000).toISOString().slice(11, 19)}Z</text>`; }
  ev.forEach((e, j) => { const i = lanes.indexOf(e.s), y = top + i * lh + (lh - 12) / 2 + ((j % 5) - 2) * 4, r = e.f.length ? 6.5 : 4, col = e.f.length ? SVC[e.sv] : "var(--mu2)";
    s += `<circle cx="${X(e.e)}" cy="${y}" r="${r}" fill="${col}" stroke="var(--bg2)" stroke-width="1.5" style="filter:drop-shadow(0 0 4px ${col})" data-tip="<span class=mono>${esc(e.t)}</span><br><b>${esc(PN[e.s] || e.s)} · ${esc(e.ty)}</b><br>user ${esc(e.u || "–")} · IP ${esc(e.ip || "–")} · ${esc(e.h)}<br>${esc(e.tg)}${e.f.length ? "<br>⚑ " + esc(e.f.join(", ")) : ""}"/>`; });
  s += `</svg><div class="legend"><span><i style="background:var(--rd)"></i>high-severity alert</span><span><i style="background:var(--am)"></i>medium-severity alert</span><span><i style="background:var(--mu2)"></i>related event (not alerted)</span></div>`;
  $("#tl").innerHTML = s;
}

/* ---- mitre */
function tMitre(v) {
  v.innerHTML = head("MITRE ATT&CK", "Techniques observed in this case", "Every detection rule of the framework is mapped to one ATT&CK technique. Highlighted cells are techniques whose rules fired on this case's evidence; faded cells are covered by a rule but were not seen here.");
  if (!ready()) { needRun(v, "the ATT&CK mapping"); return; }
  const R = S.res, T = R.techs, hit = T.filter(t => t.hits);
  const tac = [...new Set(hit.map(t => t.tactic))];
  v.innerHTML += staleBox() + `<div class="g g4" style="margin-bottom:16px">${kpi(hit.length, "Techniques observed", `of ${T.length} covered by rules`, "var(--rd)", "tgt")}${kpi(tac.length, "Tactics observed", `of ${R.tactics.length}`, "var(--am)", "mit")}
  ${kpi(R.fired.length, "Rules fired", `of ${R.total_rules} rules`, "var(--cy)", "bolt")}${kpi(fmt(R.run.alerts), "Flagged events", "carry a technique id", "var(--vi)", "exp")}</div>
  <div class="card"><div class="mx">${R.tactics.map(tc => { const L = T.filter(t => t.tactic === tc).sort((a, b) => b.hits - a.hits);
    return `<div class="col"><h4>${esc(tc)}<span>${L.filter(t => t.hits).length}/${L.length}</span></h4>${L.map(t => `<div class="tc ${t.hits ? "v" : ""}" data-tip="<b>${esc(t.id)} · ${esc(t.name)}</b><br>${t.rules.map(r => (r.hits ? "⚑ " + r.hits + " × " : "○ ") + "<span class=mono>" + esc(r.rule) + "</span> — " + esc(r.desc)).join("<br>")}"><b>${esc(t.id)}</b>${esc(t.name)}${t.hits ? `<br><span class="n">${t.hits} event${t.hits > 1 ? "s" : ""}</span>` : ""}</div>`).join("")}</div>`; }).join("")}</div>
  <div class="legend"><span><i style="background:linear-gradient(160deg,var(--rd),var(--am))"></i>observed in this case</span><span><i style="background:var(--panel2);border:1px solid var(--line2)"></i>rule exists, not observed</span></div></div>`;
  wire(v);
}

/* ---- cloud */
function tCloud(v) {
  v.innerHTML = head("Cloud forensics", "AWS account posture", "Account-state findings from the read-only collector (cloudstate.py): what an attacker could do, what was switched off and what was exposed. Posture findings alone do not create an incident; they are joined to one when an abused key belongs to the account.");
  if (!ready()) { needRun(v, "cloud findings"); return; }
  const R = S.res, has = R.run.stats.cloud;
  v.innerHTML += staleBox();
  if (!has) { v.innerHTML += `<div class="card empty">${ic("cld", 40)}<div class="big">No AWS account state in this case</div><div class="note">Collect it with the AWS collector (read-only keys) or add scenario S1_cloud.</div>
    <div class="acts" style="justify-content:center;margin-top:16px"><a class="btn pri" href="#/c/${S.cid}/evidence">${ic("cld", 15)} Go to collectors</a></div></div>`; wire(v); return; }
  const P = R.posture, hi = P.filter(p => p.sv === "high").length;
  v.innerHTML += `<div class="g g4" style="margin-bottom:16px">${kpi(P.length, "Posture findings", "misconfigurations", P.length ? "var(--am)" : "var(--gr)", "alert")}${kpi(hi, "High severity", "e.g. admin without MFA, public bucket", hi ? "var(--rd)" : "var(--gr)", "bolt")}
  ${kpi(R.cloud_inventory.length, "Account objects", "users, keys, buckets, groups, trails", "var(--cy)", "cld")}${kpi(R.run.stats.cloud.errors || 0, "Unreadable artifacts", "denied calls are 'unknown', not 'missing'", "var(--mu2)", "lock")}</div>
  <div class="card" style="margin-bottom:16px"><h3><i>${ic("alert", 15)}</i>Findings</h3><div class="tw max"><table><thead><tr><th>Severity</th><th>Finding</th><th>Object</th><th>Detail</th><th>ATT&amp;CK</th></tr></thead><tbody>
  ${P.map(p => `<tr class="click" data-ev="${esc(p.id)}"><td>${sev(p.sv)}</td><td>${p.why.map(esc).join("<br>")}</td><td class="mono">${esc(p.tg)}</td><td class="note">${esc(p.ty)}</td><td>${p.f.map(f => `<span class="tag">${esc(f)}</span>`).join("")}</td></tr>`).join("") || '<tr><td colspan="5"><span class="ok">No misconfiguration found.</span></td></tr>'}</tbody></table></div></div>
  <div class="card"><h3><i>${ic("cld", 15)}</i>Collected account state</h3>${evTable(R.cloud_inventory)}</div>`;
  wire(v); wireEvRows(v);
}

/* ---- explorer */
function tExplorer(v) {
  v.innerHTML = head("Evidence explorer", "All normalised events", "Every record from every source in one schema and in UTC. Search any field; click a row for the full record and its provenance.");
  if (!ready()) { needRun(v, "events"); return; }
  const X = S.exp;
  v.innerHTML += `<div class="card"><div class="acts" style="margin-bottom:12px"><input class="in" id="q" placeholder="search user, IP, host, event, rule, key ..." style="max-width:380px" value="${esc(X.q)}">
  <select class="in" id="src" style="max-width:200px"><option value="">all sources</option></select>
  <select class="in" id="xin" style="max-width:170px"><option value="">all incidents</option>${S.res.incidents.map(i => `<option ${X.incident === i.id ? "selected" : ""}>${esc(i.id)}</option>`).join("")}</select>
  <label class="chk"><input type="checkbox" id="fl" ${X.flagged ? "checked" : ""}> flagged only</label><span class="note" id="cnt" style="margin-left:auto"></span>
  <a class="btn sm" href="/api/cases/${S.cid}/file/timeline?download=1">${ic("dl", 13)} timeline.csv</a></div><div id="et"></div><div class="pager" id="pg"></div></div>`;
  let tmr; const load = async () => {
    const p = new URLSearchParams({q:X.q, source:X.source, flagged:X.flagged ? "1" : "", incident:X.incident, page:X.page, size:100});
    const d = await api("GET", `/api/cases/${S.cid}/events?${p}`);
    const sel = $("#src"); if (sel && sel.options.length === 1) d.sources.forEach(s => sel.insertAdjacentHTML("beforeend", `<option value="${esc(s)}" ${X.source === s ? "selected" : ""}>${esc(PN[s] || s)}</option>`));
    $("#cnt").textContent = `${fmt(d.total)} event(s)`;
    $("#et").innerHTML = evTable(d.rows); wireEvRows($("#et"));
    const pages = Math.max(1, Math.ceil(d.total / d.size));
    $("#pg").innerHTML = `<button class="btn sm" id="pp" ${X.page ? "" : "disabled"}>‹ prev</button><span>page ${X.page + 1} / ${pages}</span><button class="btn sm" id="pn" ${X.page + 1 < pages ? "" : "disabled"}>next ›</button>`;
    $("#pp").onclick = () => { X.page--; load(); }; $("#pn").onclick = () => { X.page++; load(); };
  };
  $("#q").oninput = e => { clearTimeout(tmr); tmr = setTimeout(() => { X.q = e.target.value; X.page = 0; load(); }, 250); };
  $("#src").onchange = e => { X.source = e.target.value; X.page = 0; load(); };
  $("#xin").onchange = e => { X.incident = e.target.value; X.page = 0; load(); };
  $("#fl").onchange = e => { X.flagged = e.target.checked; X.page = 0; load(); };
  load().catch(fail);
}

/* ---- custody */
function tCustody(v) {
  v.innerHTML = head("Chain of custody", "Tamper-evident evidence ledger", "Every acquisition, processing step, export and the report is a ledger entry whose SHA-256 includes the previous entry's hash and is HMAC-signed with the console's key. The newest entry's hash (the anchor) is stored outside the case folder.",
    ready() ? `<button class="btn pri" id="vb">${ic("cus", 15)} Verify now</button>` : "");
  if (!ready()) { needRun(v, "the custody ledger"); return; }
  const R = S.res, V = S.verify, bad = new Set((V && !V.ok ? V.failed : []).map(c => (c.item.match(/^entry (\d+)/) || [])[1]).filter(Boolean).map(Number));
  v.innerHTML += `<div id="vres">${V ? verifyBox(V) : `<div class="info cy" style="margin-bottom:16px"><b>Not verified in this session.</b> Press <b>Verify now</b>: every ledger entry, every HMAC, the anchor hash and the current SHA-256 of every recorded file are checked again.</div>`}</div>
  <div class="g g2" style="margin-bottom:16px"><div class="card"><h3><i>${ic("key", 15)}</i>Anchor hash (kept outside the case folder)</h3><div class="mono" style="word-break:break-all;font-size:12.5px;color:var(--gr)">${esc(R.anchor || "–")}</div>
  <div class="note" style="margin-top:8px">Stored in the console's <span class="mono">webapp_data/anchors.json</span>, not inside the case. Deleting the last ledger entries or rewriting the chain is detected by comparing against it. Note it in your case notes too.</div>
  <div class="tw" style="margin-top:10px;max-height:150px"><table><thead><tr><th>Analysis run</th><th>By</th><th>Anchor</th></tr></thead><tbody>${(S.case.anchors || []).slice().reverse().map(a => `<tr><td class="mono">${utc(a.time)}</td><td>${esc(a.by)}</td><td class="mono">${esc(a.head.slice(0, 20))}…</td></tr>`).join("")}</tbody></table></div></div>
  <div class="card"><h3><i>${ic("lab", 15)}</i>Tampering demonstration (for the viva)</h3><div class="note" style="margin-bottom:12px">Really changes a file of this analysed case so you can show that verification catches it, then puts the original back. Evidence originals in uploads/ are never touched.</div>
  <div id="tdst" class="note" style="margin-bottom:10px"></div><div class="acts"><button class="btn danger" data-t="evidence">${ic("alert", 14)} Modify an evidence file</button><button class="btn danger" data-t="ledger">${ic("alert", 14)} Edit a ledger entry</button><button class="btn" data-t="restore">${ic("ref", 14)} Restore</button></div></div></div>
  <div class="card"><h3><i>${ic("lock", 15)}</i>Ledger — ${R.ledger.length} hash-chained entries<span class="r note">HMAC-SHA256 signed · actor = analyst who ran the step</span></h3><div class="chain">
  ${R.ledger.map((b, i) => `${i ? `<div class="arw"><svg width="22" height="14" viewBox="0 0 30 14"><path d="M0 7h26M20 2l6 5-6 5" fill="none" stroke="currentColor" stroke-width="2"/></svg></div>` : ""}
  <div class="blk ${bad.has(b.seq) ? "bad" : ""}" data-tip="<b>#${b.seq} ${esc(b.stage)} · ${esc(b.action)}</b><br>${esc(b.target)}<br><span class=mono>${esc(b.time)}</span><br>actor: ${esc(b.actor)}<br>prev: <span class=mono>${esc((b.prev || "").slice(0, 32))}…</span><br>hash: <span class=mono>${esc((b.hash || "").slice(0, 32))}…</span>${b.sha ? "<br>file SHA-256: <span class=mono>" + esc(b.sha.slice(0, 32)) + "…</span>" : ""}">
  <div class="sq">#${b.seq} · ${esc(b.stage)}</div><div class="a">${esc(b.action)}</div><div class="tg">${esc(b.target)}</div>
  <div class="hs">prev&nbsp; ${esc((b.prev || "").slice(0, 10))}…<br>hash&nbsp; <em>${esc((b.hash || "").slice(0, 10))}…</em>${b.hmac ? "<br>hmac&nbsp; ✓ signed" : ""}</div></div>`).join("")}</div>
  <div class="tw max" style="margin-top:12px"><table><thead><tr><th>#</th><th>Stage</th><th>Action</th><th>Target</th><th>Time (UTC)</th><th>Actor</th><th>File SHA-256</th></tr></thead><tbody>
  ${R.ledger.map(b => `<tr><td class="mono">${b.seq}</td><td>${esc(b.stage)}</td><td>${esc(b.action)}</td><td class="mono">${esc(b.target)}</td><td class="mono">${utc(b.time)}</td><td>${esc(b.actor)}</td><td class="mono">${esc((b.sha || "").slice(0, 24))}${b.sha ? "…" : ""}</td></tr>`).join("")}</tbody></table></div></div>`;
  $("#vb").onclick = verify; wire(v);
  v.querySelectorAll("[data-t]").forEach(b => b.onclick = () => tamper(b.dataset.t));
  tamperStatus();
}
function verifyBox(V) {
  return `<div class="bigres ${V.ok ? "ok" : "bad"}"><div class="ic">${ic(V.ok ? "cus" : "alert", 28)}</div><div><div class="x">${V.ok ? "VERIFIED — evidence and ledger intact" : "TAMPERING DETECTED"}</div>
  <div class="y">${V.entries} ledger entries · ${V.files} files re-hashed · HMAC checked · anchor ${V.anchor ? "compared" : "not available"} · ${utc(V.time)} by ${esc(V.by)}</div></div></div>
  ${V.failed.length ? `<div class="card" style="margin-bottom:16px;border-color:var(--rd)"><h3 class="bad"><i class="bad">${ic("x", 15)}</i>What failed</h3>${V.failed.map(c => `<div class="vr"><span class="bad">${ic("x", 14)}</span><b>${esc(c.item)}</b><span class="mono">${esc(c.note)}</span></div>`).join("")}</div>` : ""}
  <details class="card" style="margin-bottom:16px"><summary class="note" style="cursor:pointer">All ${V.checks.length} checks</summary><div style="margin-top:10px;max-height:300px;overflow:auto">${V.checks.map(c => `<div class="vr"><span class="${c.ok ? "ok" : "bad"}">${ic(c.ok ? "chk" : "x", 14)}</span>${esc(c.item)}<span class="mono" style="margin-left:auto">${esc(c.note)}</span></div>`).join("")}</div></details>`;
}
async function verify() {
  try { const b = $("#vb"); if (b) { b.disabled = true; b.innerHTML = `<span class="spin"></span> Verifying ...`; }
    S.verify = await api("POST", `/api/cases/${S.cid}/verify`);
    toast(S.verify.ok ? "Chain of custody VERIFIED" : "TAMPERING DETECTED", S.verify.ok ? "var(--gr)" : "var(--rd)");
    await openCase(S.cid, true, "custody");
  } catch (e) { fail(e); }
}
async function tamperStatus() { try { const s = await api("POST", `/api/cases/${S.cid}/tamper`, {action:"status"}); const el = $("#tdst"); if (el) el.innerHTML = s.active ? `<span class="bad">${ic("alert", 13)} Active: ${esc(s.what)} — verify, then restore.</span>` : `<span class="ok">${ic("chk", 13)} No tampering demo active.</span>`; } catch (e) {} }
async function tamper(a) { try { const r = await api("POST", `/api/cases/${S.cid}/tamper`, {action:a}); toast(esc(r.what), a === "restore" ? "var(--gr)" : "var(--am)"); S.verify = null; await openCase(S.cid, true, "custody"); } catch (e) { fail(e); } }

/* ---- report */
function tReport(v) {
  v.innerHTML = head("Reporting", "Forensic report & exports", "The framework's self-contained HTML report (no internet or JavaScript needed) and the raw outputs. Every export is recorded in the activity log.");
  if (!ready()) { needRun(v, "the report"); return; }
  const b = `/api/cases/${S.cid}/file/`;
  v.innerHTML += staleBox() + `<div class="card" style="margin-bottom:16px"><div class="acts"><a class="btn pri" href="${b}report" target="_blank">${ic("ext", 14)} Open report in new tab</a><a class="btn" href="${b}report?download=1">${ic("dl", 14)} report.html</a>
  <a class="btn" href="${b}timeline?download=1">${ic("dl", 14)} timeline.csv</a><a class="btn" href="${b}events?download=1">${ic("dl", 14)} normalized_events.json</a><a class="btn" href="${b}incidents?download=1">${ic("dl", 14)} incidents.json</a>
  <a class="btn" href="${b}ledger?download=1">${ic("dl", 14)} custody_ledger.jsonl</a><a class="btn" href="/api/cases/${S.cid}/bundle">${ic("fold", 14)} Full case bundle (.zip)</a></div>
  <div class="note" style="margin-top:10px">To print or save as PDF: open the report in a new tab and use the browser's Print → Save as PDF.</div></div>
  <iframe class="rep" src="${b}report" title="report"></iframe>`;
  wire(v);
}

/* ---- activity */
async function tActivity(v) {
  v.innerHTML = head("Audit trail", "Case activity log", "Who did what and when: case creation, every evidence upload with its SHA-256, collectors, analyses, verifications, tampering demos and exports.");
  const a = await api("GET", `/api/cases/${S.cid}/activity`);
  v.innerHTML += `<div class="card"><div class="tw max" style="max-height:70vh"><table><thead><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Details</th></tr></thead><tbody>
  ${a.map(x => `<tr><td class="mono">${utc(x.time)}</td><td>${esc(x.user || "–")}</td><td><span class="tag ${/fail|tamper/.test(x.action) ? "rd" : /done|verified|created/.test(x.action) ? "gr" : "cy"}">${esc(x.action)}</span></td><td class="mono" style="font-size:11px;max-width:620px;white-space:pre-wrap;word-break:break-word">${esc(actDetail(x))}</td></tr>`).join("")}</tbody></table></div></div>`;
}
function actDetail(x) {
  const d = x.details || {};
  if (d.files) return d.files.map(f => `${f.ok ? "+" : "-"} ${f.name}${f.kind ? " [" + f.kind + "]" : ""}${f.sha256 ? " " + f.sha256.slice(0, 16) + "…" : ""}${f.note ? " (" + f.note + ")" : ""}`).join("\n");
  return Object.entries(d).filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ·  ");
}

/* ---------------------------------------------------------------- framework pages */
async function viewResearch(v) {
  const info = await api("GET", "/api/system/info");
  const N = {"dashboard.html":"Evaluation dashboard", "evaluation_report.html":"Evaluation report (simulated)", "real_data_report.html":"Real-data validation"};
  v.innerHTML = head("Framework evaluation", "Research results", "Results of the framework's evaluation (python main.py evaluate / real-eval): precision, recall and F1 on simulated scenarios, tampering tests, scalability, and validation on real public datasets.");
  if (!info.research.length) { v.innerHTML += `<div class="card empty"><div class="big">No results yet</div><div class="note">Run <span class="mono">python main.py evaluate</span> and <span class="mono">python main.py real-eval</span>.</div></div>`; return; }
  v.innerHTML += `<div class="card" style="margin-bottom:14px"><div class="chips" id="rch">${info.research.map((n, i) => `<span class="chip ${i ? "" : "on"}" data-n="${n}">${N[n]}</span>`).join("")}<a class="btn sm" id="rop" target="_blank" style="margin-left:auto">${ic("ext", 12)} Open in new tab</a></div></div>
  <iframe class="rep" id="rif" style="height:80vh;background:var(--bg)"></iframe>`;
  const show = n => { $("#rif").src = "/research/" + n; $("#rop").href = "/research/" + n; $$("#rch .chip").forEach(c => c.classList.toggle("on", c.dataset.n === n)); };
  $$("#rch .chip").forEach(c => c.onclick = () => show(c.dataset.n)); show(info.research[0]);
}
async function viewSystem(v) {
  const i = await api("GET", "/api/system/info");
  v.innerHTML = head("System", "System & self-test", "Environment of this console and the framework's own unit tests.", `<button class="btn pri" id="st">${ic("play", 15)} Run self-test</button>`) +
  `<div class="g g2"><div class="card"><h3><i>${ic("sys", 15)}</i>Environment</h3><div class="kv"><div>Host</div><div class="mono">${esc(i.host)}</div><div>System</div><div class="mono">${esc(i.system)}</div><div>Python</div><div class="mono">${esc(i.python)}</div>
  ${Object.entries(i.modules).map(([k, x]) => `<div>${esc(k)}</div><div class="mono ${x ? "" : "warn"}">${x ? esc(x) : "not installed"}</div>`).join("")}
  <div>Data folder</div><div class="mono" style="word-break:break-all">${esc(i.data_dir)}</div><div>Custody HMAC key</div><div class="mono" style="word-break:break-all">${esc(i.custody_key)}</div><div>Cases</div><div>${i.cases}</div>
  <div>Mode</div><div>${i.public_mode ? '<span class="warn">public demo (host collectors disabled)</span>' : "local"}</div></div>
  <div class="note" style="margin-top:12px">Back up <span class="mono">custody.key</span> and <span class="mono">anchors.json</span> with the cases: without the key the HMAC of old ledgers cannot be checked. CLI check of a case: <span class="mono">python main.py verify --case webapp_data/cases/&lt;ID&gt;/case --custody-key-file webapp_data/custody.key --anchor &lt;hash&gt;</span></div></div>
  <div class="card"><h3><i>${ic("mit", 15)}</i>Detection engine</h3><div class="g g2" style="margin-bottom:12px">${kpi(i.rules, "Detection rules", "", "var(--am)", "bolt")}${kpi(i.techniques, "ATT&CK techniques", "", "var(--cy)", "tgt")}</div>
  ${Object.entries(i.families).map(([f, n]) => `<div style="display:grid;grid-template-columns:1fr 40px;gap:8px;font-size:12.8px;margin:4px 0"><span>${esc(f)}</span><b class="mono" style="text-align:right">${n}</b></div>`).join("")}</div></div>
  <div class="card" style="margin-top:16px"><h3><i>${ic("key", 15)}</i>Change my password</h3><form id="pw" class="row" style="align-items:flex-end"><div><label class="f">Current password</label><input class="in" type="password" name="old"></div><div><label class="f">New password</label><input class="in" type="password" name="new"></div><div style="flex:0"><button class="btn">${ic("chk", 14)} Change</button></div></form></div>`;
  $("#st").onclick = async () => { try { const r = await api("POST", "/api/system/selftest"); runJob(r.job, "Framework self-test (unit tests)"); } catch (e) { fail(e); } };
  $("#pw").onsubmit = async e => { e.preventDefault(); try { await api("POST", "/api/password", Object.fromEntries(new FormData(e.target).entries())); toast("Password changed", "var(--gr)"); e.target.reset(); } catch (er) { fail(er); } };
}
async function viewUsers(v) {
  const [us, au] = await Promise.all([api("GET", "/api/users"), api("GET", "/api/audit")]);
  v.innerHTML = head("Administration", "Users & audit log", "Analyst accounts of this console and the global audit log (logins, failed logins, case actions).") +
  `<div class="g g2" style="margin-bottom:16px"><div class="card"><h3><i>${ic("usr", 15)}</i>Analysts</h3><div class="tw"><table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>
  ${us.map(u => `<tr><td class="mono">${esc(u.username)}</td><td>${esc(u.name)}</td><td><span class="tag ${u.role === "admin" ? "am" : "cy"}">${esc(u.role)}</span></td><td class="mono">${utc(u.created)}</td><td>${u.username !== S.sess.user.username ? `<button class="btn sm ghost danger" data-du="${esc(u.username)}">${ic("trash", 13)}</button>` : ""}</td></tr>`).join("")}</tbody></table></div></div>
  <div class="card"><h3><i>${ic("plus", 15)}</i>Add analyst</h3><form id="uf"><div class="row"><div class="fr"><label class="f">Full name</label><input class="in" name="name"></div><div class="fr"><label class="f">Username</label><input class="in" name="username"></div></div>
  <div class="row"><div class="fr"><label class="f">Password (min. 8)</label><input class="in" type="password" name="password"></div><div class="fr"><label class="f">Role</label><select class="in" name="role"><option value="analyst">analyst</option><option value="admin">admin</option></select></div></div>
  <button class="btn pri">${ic("plus", 14)} Add</button></form></div></div>
  <div class="card"><h3><i>${ic("act", 15)}</i>Global audit log (latest 500)</h3><div class="tw max" style="max-height:60vh"><table><thead><tr><th>Time (UTC)</th><th>User</th><th>IP</th><th>Action</th><th>Case</th><th>Details</th></tr></thead><tbody>
  ${au.map(x => `<tr><td class="mono">${utc(x.time)}</td><td>${esc(x.user || "–")}</td><td class="mono">${esc(x.ip || "")}</td><td><span class="tag ${/fail|tamper|deleted/.test(x.action) ? "rd" : "cy"}">${esc(x.action)}</span></td><td class="mono">${x.case ? `<a href="#/c/${esc(x.case)}/activity">${esc(x.case)}</a>` : ""}</td><td class="mono" style="font-size:11px;max-width:460px;white-space:pre-wrap;word-break:break-word">${esc(actDetail(x))}</td></tr>`).join("")}</tbody></table></div></div>
  <div class="card" style="margin-top:16px"><h3 class="bad"><i class="bad">${ic("trash", 15)}</i>Delete a case</h3><form id="dcf" class="row" style="align-items:flex-end"><div><label class="f">Case ID (type it exactly)</label><input class="in" name="confirm" placeholder="CASE-2026-0001"></div><div style="flex:0"><button class="btn danger">${ic("trash", 14)} Delete permanently</button></div></form><div class="hint">Deletes the case folder (evidence, results, ledger). The deletion is kept in the global audit log.</div></div>`;
  $("#uf").onsubmit = async e => { e.preventDefault(); try { await api("POST", "/api/users", Object.fromEntries(new FormData(e.target).entries())); toast("Analyst added", "var(--gr)"); shell(viewUsers, "users", "Users & audit log"); } catch (er) { fail(er); } };
  v.querySelectorAll("[data-du]").forEach(b => b.onclick = async () => { try { await api("DELETE", `/api/users/${b.dataset.du}`); toast("User removed"); shell(viewUsers, "users", "Users & audit log"); } catch (e) { fail(e); } });
  $("#dcf").onsubmit = async e => { e.preventDefault(); const id = new FormData(e.target).get("confirm").trim(); try { await api("DELETE", `/api/cases/${id}`, {confirm:id}); toast(`Case ${esc(id)} deleted`); shell(viewUsers, "users", "Users & audit log"); } catch (er) { fail(er); } };
}

/* ---------------------------------------------------------------- go */
route();
