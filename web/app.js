const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

const STEPS = [
  ["models", "Connect · Token Factory"], ["checkout", "Check out repo"], ["scan", "Scan · OSV.dev"],
  ["triage", "Triage · Nemotron Nano"], ["research", "Research · Tavily"], ["plan", "Plan · Nemotron Super"],
  ["exploit", "Exploit proof · Super"], ["test", "Upgrade & test"], ["fix", "Repair · Super → Ultra"], ["pr", "Pull request"],
];
const TIERS = ["nano", "super", "ultra"];
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3 };
let state, source, selectedCase = "";

// ---------- tabs ----------
document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => showTab(b.dataset.tab)));
function showTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "bench") loadBench();
}

// ---------- agent graph ----------
const NODES = {
  repo:    { x: 70,  y: 125, label: "Repository", sub: "requirements.txt", c: "--muted" },
  osv:     { x: 215, y: 55,  label: "OSV.dev", sub: "advisories", c: "--bad" },
  nano:    { x: 370, y: 55,  label: "Nemotron Nano", sub: "triage", c: "--nano" },
  tavily:  { x: 290, y: 195, label: "Tavily", sub: "migration research", c: "--tavily" },
  super:   { x: 520, y: 125, label: "Nemotron Super", sub: "plan + repair", c: "--super" },
  sandbox: { x: 690, y: 125, label: "Sandbox", sub: "venv + pytest", c: "--info" },
  ultra:   { x: 690, y: 210, label: "Nemotron Ultra", sub: "escalation", c: "--ultra" },
  pr:      { x: 870, y: 125, label: "Pull request", sub: "verified", c: "--ok" },
};
const EDGES = [
  ["repo", "osv"], ["osv", "nano"], ["repo", "tavily"], ["nano", "super"], ["tavily", "super"],
  ["super", "sandbox"], ["sandbox", "super", -38], ["sandbox", "ultra", 18], ["ultra", "sandbox", 18], ["sandbox", "pr"],
];
const NW = 132, NH = 46;

function edgePath(a, b, bend = 0) {
  const A = NODES[a], B = NODES[b];
  const x1 = A.x + (B.x > A.x ? NW / 2 : B.x < A.x ? -NW / 2 : bend), y1 = A.y + (B.y > A.y && B.x === A.x ? NH / 2 : B.y < A.y && B.x === A.x ? -NH / 2 : 0);
  const x2 = B.x + (B.x > A.x ? -NW / 2 : B.x < A.x ? NW / 2 : bend), y2 = B.y + (B.y > A.y && B.x === A.x ? -NH / 2 : B.y < A.y && B.x === A.x ? NH / 2 : 0);
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2 + (B.x !== A.x ? bend * 2.2 : 0);
  return `M${x1},${y1} Q${mx},${my} ${x2},${y2}`;
}
function buildGraph() {
  const g = $("#graph");
  const edges = EDGES.map(([a, b, bend]) => `<path class="edge" id="e-${a}-${b}" d="${edgePath(a, b, bend || 0)}"/>`).join("");
  const nodes = Object.entries(NODES).map(([k, n]) => `
    <g class="node" id="n-${k}" style="--c:var(${n.c})" transform="translate(${n.x - NW / 2},${n.y - NH / 2})">
      <rect class="halo" width="${NW}" height="${NH}" rx="12"/>
      <rect width="${NW}" height="${NH}" rx="12"/>
      <text x="${NW / 2}" y="20">${n.label}</text>
      <text class="sub" x="${NW / 2}" y="35">${n.sub}</text>
    </g>`).join("");
  g.innerHTML = `<g id="edges">${edges}</g><g id="packets"></g>${nodes}`;
}
function node(k, st) {
  const el = $("#n-" + k);
  if (!el) return;
  if (st === "active") document.querySelectorAll(".node.active").forEach((n) => { if (n !== el) { n.classList.remove("active"); n.classList.add("done"); } });
  el.classList.remove("active", "done");
  if (st) el.classList.add(st);
}
function pulse(a, b, color = "var(--accent)") {
  const path = $(`#e-${a}-${b}`);
  if (!path) return;
  path.classList.add("lit");
  setTimeout(() => path.classList.remove("lit"), 1600);
  if (reduced) return;
  const len = path.getTotalLength();
  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  dot.setAttribute("r", 5); dot.setAttribute("class", "packet"); dot.style.fill = color; dot.style.color = color;
  $("#packets").appendChild(dot);
  const t0 = performance.now(), dur = 900;
  (function step(now) {
    const p = Math.min((now - t0) / dur, 1), pt = path.getPointAtLength(len * (1 - Math.pow(1 - p, 2)));
    dot.setAttribute("cx", pt.x); dot.setAttribute("cy", pt.y);
    p < 1 ? requestAnimationFrame(step) : dot.remove();
  })(t0);
}
function phase(t) { $("#phase").textContent = t; }

// ---------- boot ----------
async function boot() {
  buildGraph();
  const [h, cases, runs] = await Promise.all([
    window.ppHealth,
    fetch("/api/cases").then((r) => r.json()).catch(() => []),
    fetch("/api/runs").then((r) => r.json()).catch(() => []),
  ]);
  if (h.remote_repos === false) { $("#repo").disabled = true; $("#repo").placeholder = "Remote repos are disabled on this public demo. Pick a case above."; }
  $("#cases").innerHTML = cases.map((c, i) => `<button type="button" class="case ${i === 0 ? "active" : ""}" data-id="${esc(c.id)}" role="radio">
    <b>case:${esc(c.id)}</b><small>${c.pins.map(esc).join(" · ")}</small></button>`).join("");
  selectedCase = cases[0] ? "case:" + cases[0].id : "";
  document.querySelectorAll(".case").forEach((b) => (b.onclick = () => {
    document.querySelectorAll(".case").forEach((x) => x.classList.toggle("active", x === b));
    selectedCase = "case:" + b.dataset.id; $("#repo").value = "";
  }));
  $("#history").innerHTML = '<option value="">▶ Replay a recorded run…</option>' +
    runs.map((r) => `<option value="${r.id}">${r.ok === true ? "✓" : r.ok === false ? "✗" : "·"} ${esc(r.repo)} · ${r.id}</option>`).join("");
  reset();
  const qs = new URLSearchParams(location.search), replay = qs.get("replay");
  if (qs.get("repo")) $("#repo").value = qs.get("repo");
  if (replay) listen(replay, 4);
}

function reset() {
  state = { exploit: null, risk: null, reach: {}, patches: [], findings: [], triage: {}, plan: null, tests: [], diff: "", report: "", evidence: [], research: [],
            usage: Object.fromEntries(TIERS.map((t) => [t, { calls: 0, tok: 0, s: 0, model: "" }])), total: 0 };
  $("#steps").innerHTML = STEPS.map(([k, t]) => `<li id="s-${k}"><span class="dot"></span><div>${t}<small></small></div></li>`).join("");
  $("#tests").innerHTML = '<li class="muted">No test runs yet</li>';
  ["adv", "tests", "att", "tok", "time"].forEach((k) => ($("#k-" + k).textContent = "–"));
  $("#term").innerHTML = "";
  $("#tab-advisories").innerHTML = '<div class="empty">Scanning…</div>';
  $("#tab-evidence").innerHTML = '<div class="empty">Migration sources from Tavily and the exact lines the agent relied on appear here.</div>';
  $("#tab-diff").innerHTML = '<div class="empty">The verified patch appears here.</div>';
  $("#tab-proof").innerHTML = '<div class="empty">PatchPilot writes an exploit test, shows it working on the old version, then proves the fix closes it.</div>';
  $("#tab-reach").innerHTML = '<div class="empty">Where your code calls each vulnerable package.</div>';
  $("#tab-debate").innerHTML = '<div class="empty">When a fix fails, each model’s diagnosis appears here side by side.</div>';
  $("#speak").hidden = true; speechSynthesis?.cancel();
  $("#tab-report").innerHTML = '<div class="empty">The pull-request description appears here.</div>';
  $("#costNote").textContent = "";
  $("#banner").hidden = true;
  $("#exposure").className = "exposure card glass"; $("#expNum").textContent = "—";
  $("#sevlegend").textContent = "Run the agent to measure exposure";
  document.querySelectorAll(".sevbar i").forEach((i) => (i.style.width = "0"));
  buildGraph(); phase("idle");
  renderRouting();
}

// ---------- run / replay ----------
$("#runForm").onsubmit = async (e) => {
  e.preventDefault();
  const repo = $("#repo").value.trim() || selectedCase;
  const r = await fetch("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo }) });
  if (!r.ok) return banner(esc((await r.json().catch(() => ({}))).detail || "Could not start run"), false);
  listen((await r.json()).id, 0);
};
$("#replayBtn").onclick = () => { const id = $("#history").value; if (id) listen(id, 4); };

function listen(id, replay) {
  if (source) source.close();
  reset();
  $("#runBtn").disabled = true;
  showTab("terminal");
  term("sys", `$ patchpilot run ${id}${replay ? "  --replay" : ""}`);
  source = new EventSource(`/api/runs/${id}/events?replay=${replay}`);
  source.onmessage = (m) => handle(JSON.parse(m.data));
  source.onerror = () => { source.close(); $("#runBtn").disabled = false; };
}

// ---------- events ----------
function handle(ev) {
  if (ev.t != null) $("#k-time").textContent = fmtTime(ev.t);
  switch (ev.type) {
    case "start": term("sys", `target ${ev.repo}`); node("repo", "active"); break;
    case "step": onStep(ev); break;
    case "log": term("dim", ev.msg, ev.t); break;
    case "findings": onFindings(ev.findings); break;
    case "triage": state.triage = indexTriage(ev.triage); renderAdvisories(); break;
    case "research":
      state.research.push(ev); node("tavily", "active"); pulse("repo", "tavily", "var(--tavily)");
      term("tavily", `tavily › ${ev.query}`, ev.t);
      ev.results.forEach((r) => r.url && term("dim", `   ↳ ${r.title}`));
      renderEvidence(); break;
    case "plan": state.plan = ev.plan; renderAdvisories(); pulse("nano", "super", "var(--super)"); pulse("tavily", "super", "var(--tavily)");
      ev.plan.upgrades.forEach((u) => term("super", `plan › ${u.package} ${u.from} → ${u.to}${u.breaking ? "  [breaking]" : ""}`, ev.t)); break;
    case "model_call": onModel(ev); break;
    case "test": onTest(ev); break;
    case "patch":
      bumpKpi("#k-att", ev.attempt);
      term(ev.tier, `${ev.tier} › patch #${ev.attempt}: ${ev.explanation}`, ev.t);
      ev.files.forEach((f) => term("dim", `   ✎ ${f}`));
      state.patches.push(ev); renderDebate();
      (ev.evidence || []).forEach((e) => state.evidence.push({ ...e, attempt: ev.attempt, tier: ev.tier }));
      pulse(ev.tier, "sandbox", `var(--${ev.tier})`); renderEvidence(); break;
    case "reach": state.reach = ev.packages; renderReach(); break;
    case "exploit": onExploit(ev); break;
    case "risk": state.risk = ev; renderProof(); break;
    case "diff": state.diff = ev.diff; renderDiff(); break;
    case "report": state.report = ev.markdown; renderReport(); break;
    case "error": term("bad", `error › ${ev.msg}`, ev.t); banner(esc(ev.msg), false); phase("error"); break;
    case "done": onDone(ev); break;
  }
}

function onStep(ev) {
  const li = $("#s-" + ev.key);
  if (!li) return;
  li.className = ev.status;
  li.querySelector(".dot").textContent = ev.status === "done" ? "✓" : ev.status === "failed" ? "!" : "";
  if (ev.status === "done" && ev.t != null) li.querySelector("small").textContent = fmtTime(ev.t);
  if (ev.status === "running") { phase(ev.title || ev.key); term("sys", `▸ ${ev.title || ev.key}`, ev.t); }
  if (ev.key === "models" && ev.detail) { TIERS.forEach((t) => (state.usage[t].model = ev.detail[t] || "")); renderRouting();
    TIERS.forEach((t) => term(t, `${t.padEnd(5)} → ${ev.detail[t]}`)); }
  if (ev.key === "scan" && ev.status === "running") { node("osv", "active"); pulse("repo", "osv", "var(--bad)"); }
  if (ev.key === "test" && ev.status === "running") { node("sandbox", "active"); pulse("super", "sandbox"); }
  if (ev.key === "pr" && ev.status === "done") { node("pr", "active"); pulse("sandbox", "pr", "var(--ok)"); }
}

function onFindings(findings) {
  state.findings = findings;
  const all = findings.flatMap((f) => f.vulns);
  state.total = all.length;
  bumpKpi("#k-adv", all.length);
  term(all.length ? "bad" : "ok", `osv › ${all.length} advisories across ${findings.length} package(s)`);
  findings.forEach((f) => f.vulns.forEach((v) => term("dim", `   ${(v.severity || "N/A").padEnd(8)} ${v.cve || v.id}  ${f.package}`)));
  countTo($("#expNum"), all.length, 900);
  $("#exposure").classList.toggle("hot", all.length > 0);
  const n = (s) => all.filter((v) => (v.severity || "LOW") === s || (s === "MODERATE" && v.severity === "MEDIUM")).length;
  const parts = { c: n("CRITICAL"), h: n("HIGH"), m: n("MODERATE"), l: all.length - n("CRITICAL") - n("HIGH") - n("MODERATE") };
  Object.entries(parts).forEach(([k, v]) => ($(`.sevbar .${k}`).style.width = (all.length ? (v / all.length) * 100 : 0) + "%"));
  $("#sevlegend").textContent = `${parts.c} critical · ${parts.h} high · ${parts.m} moderate · ${parts.l} other`;
  renderAdvisories(); showTab("advisories");
}

function onModel(ev) {
  if (ev.status === "start") {
    node(ev.tier, "active");
    if (ev.tier === "nano") pulse("osv", "nano", "var(--nano)");
    if (ev.tier === "ultra") pulse("sandbox", "ultra", "var(--ultra)");
    if (ev.tier === "super" && /Fix/.test(ev.purpose)) pulse("sandbox", "super", "var(--super)");
    return term(ev.tier, `${ev.tier} › ${ev.purpose} …`, ev.t);
  }
  const u = state.usage[ev.tier];
  u.calls++; u.tok += ev.tokens_in + ev.tokens_out; u.s += ev.seconds; u.model = ev.model;
  term("dim", `   ✓ ${ev.tokens_in}→${ev.tokens_out} tok in ${ev.seconds}s`);
  bumpKpi("#k-tok", TIERS.reduce((n, t) => n + state.usage[t].tok, 0).toLocaleString());
  renderRouting();
}

function onTest(ev) {
  state.tests.push(ev);
  node("sandbox", "active");
  term(ev.ok ? "ok" : "bad", `pytest › ${ev.label}: ${ev.ok ? "PASS" : "FAIL"}  ${ev.summary}`, ev.t);
  if (!ev.ok && ev.output) ev.output.split("\n").filter((l) => /Error|FAILED|assert/.test(l)).slice(0, 6).forEach((l) => term("dim", "   " + l.trim()));
  renderTests();
}

function onDone(ev) {
  if (source) source.close();
  $("#runBtn").disabled = false;
  if (ev.usage) {
    TIERS.forEach((t) => { const r = ev.usage.tiers[t]; if (r) Object.assign(state.usage[t], { calls: r.calls, tok: r.in + r.out, s: r.seconds, model: r.model }); });
    renderRouting();
    $("#costNote").innerHTML = ev.usage.priced
      ? `Run cost <b>$${ev.usage.total.toFixed(4)}</b> vs $${ev.usage.all_ultra.toFixed(4)} if every call used Ultra: <b>${Math.round((1 - ev.usage.total / ev.usage.all_ultra) * 100)}% saved</b> by routing.`
      : savingsByTokens();
  }
  if (ev.seconds) $("#k-time").textContent = fmtTime(ev.seconds);
  if (ev.clean) { phase("clean"); return banner("No known advisories. Nothing to patch.", true); }
  state.done = ev; $("#speak").hidden = false;
  if (ev.ok) {
    phase("secured ✓"); node("pr", "active"); pulse("sandbox", "pr", "var(--ok)");
    $("#exposure").classList.remove("hot"); $("#exposure").classList.add("safe"); countTo($("#expNum"), 0, 1300);
    document.querySelectorAll(".sevbar i").forEach((i) => (i.style.width = "0"));
    $("#sevlegend").textContent = `${state.total} advisories resolved · all tests passing`;
    term("ok", `✔ secured: ${state.total} advisories cleared in ${fmtTime(ev.seconds || 0)} with ${ev.attempts} repair attempt(s)`);
    const pr = ev.pr ? ` <a href="${esc(ev.pr.url)}" target="_blank" rel="noopener">Open PR ↗</a>` : "";
    banner(`Secured. All tests passing after ${ev.attempts} repair attempt(s).` + pr, true);
    confetti(); setTimeout(() => showTab("diff"), 1800);
  } else if (ev.attempts != null) { phase("needs review"); banner("Could not reach green tests. Patch needs human review.", false); }
  $("#term").insertAdjacentHTML("beforeend", '<span class="cursor"></span>');
}

// ---------- exploit proof, risk, reachability, debate ----------
function onExploit(ev) {
  if (ev.stage === "before") {
    state.exploit = ev;
    term(ev.vulnerable ? "bad" : "dim", `exploit › ${ev.title}: ${ev.vulnerable ? "VULNERABLE (attack works on old pins)" : "old pins not exploitable by this test"}`, ev.t);
  } else {
    Object.assign(state.exploit || (state.exploit = {}), ev);
    term(ev.closed ? "ok" : "bad", `exploit › after fix: ${ev.verdict}`, ev.t);
  }
  renderProof();
}

function renderProof() {
  const x = state.exploit, r = state.risk;
  if (!x && !r) return;
  const stage = (label, cls, val) => `<div class="pf-stage ${cls}"><small>${label}</small><b>${esc(val)}</b></div>`;
  const ex = x ? `<div class="pf card glass">
      <div class="pf-head"><span class="chip super">exploit proof</span><b>${esc(x.title)}</b><span class="muted">${esc(x.advisory || "")}</span></div>
      <div class="pf-flow">
        ${stage("Old version", x.vulnerable ? "bad" : "na", x.vulnerable ? "Exploited ✗" : "Not reproduced")}
        <span class="pf-arrow">→</span>
        ${stage("Patched", x.closed ? "ok" : x.after ? "bad" : "na", x.after ? (x.closed ? "Blocked ✓" : "Still open") : "Running…")}
        <span class="pf-arrow">→</span>
        ${stage("Verdict", x.verdict === "proven closed" ? "ok" : "na", x.verdict || "pending")}
      </div>
      <details><summary>Show exploit test</summary><pre class="diff">${esc(x.code || "")}</pre></details></div>` : "";
  const rk = r ? `<div class="card glass risk ${r.level}">
      <div class="gauge" style="--v:${r.score}"><b>${r.score}</b><small>${r.level} risk</small></div>
      <div class="factors">${r.factors.map((f) => `<div><span>${esc(f.name)}</span><span class="muted">${esc(f.detail)}</span><b>${f.points > 0 ? "+" : ""}${f.points}</b></div>`).join("")}</div></div>` : "";
  $("#tab-proof").innerHTML = ex + rk;
}

function renderReach() {
  const entries = Object.entries(state.reach);
  if (!entries.length) return;
  $("#tab-reach").innerHTML = entries.map(([pkg, hits]) => {
    const files = {};
    hits.forEach((h) => { const m = /^(.+?):(\d+): (.*)$/.exec(h); if (m) (files[m[1]] ||= []).push([m[2], m[3]]); });
    const fk = Object.keys(files);
    return `<div class="reach"><div class="r-pkg"><span class="sev HIGH">vuln</span><b>${esc(pkg)}</b><small>${hits.length} call-site(s)</small></div>
      <div class="r-files">${fk.length ? fk.map((f) => `<div class="r-file"><div class="r-name">📄 ${esc(f)}</div>
        ${files[f].map(([ln, code]) => `<div class="r-line"><span>${ln}</span><code>${esc(code)}</code></div>`).join("")}</div>`).join("")
        : '<div class="muted r-none">Not imported directly. Likely a transitive dependency.</div>'}</div></div>`;
  }).join("");
}

function renderDebate() {
  $("#tab-debate").innerHTML = `<div class="debate">${state.patches.map((p) => `<div class="db card glass" style="--c:var(--${p.tier})">
    <div class="db-head"><span class="chip ${p.tier}">${p.tier}</span><b>Attempt #${p.attempt}</b></div>
    <small>Diagnosis</small><p>${esc(p.diagnosis || "—")}</p><small>Fix</small><p>${esc(p.explanation)}</p>
    <div class="muted">${p.files.map((f) => "✎ " + esc(f)).join("<br>")}</div></div>`).join("")}</div>`;
}

$("#speak").onclick = () => {
  if (!("speechSynthesis" in window)) return banner("Voice is not supported in this browser", false);
  const d = state.done || {}, x = state.exploit, r = state.risk;
  const parts = [d.clean ? "No known vulnerabilities. Nothing to patch." :
    `PatchPilot found ${state.total} advisories across ${state.findings.length} packages.`];
  state.plan?.upgrades.forEach((u) => parts.push(`${u.package} upgraded from ${u.from} to ${u.to}.`));
  if (d.ok) parts.push(`All tests pass after ${d.attempts} repair attempts.`);
  else if (!d.clean) parts.push("The patch needs human review.");
  if (x?.verdict) parts.push(`Exploit proof: ${x.verdict}.`);
  if (r) parts.push(`Risk score ${r.score}, ${r.level}.`);
  speechSynthesis.cancel();
  speechSynthesis.speak(Object.assign(new SpeechSynthesisUtterance(parts.join(" ")), { rate: 1.05 }));
};

// ---------- renderers ----------
function term(kind, text, t) {
  const el = $("#term");
  const stamp = t != null ? `<span class="t">[${String(fmtTime(t)).padStart(6)}]</span> ` : "         ";
  el.insertAdjacentHTML("beforeend", `${stamp}<span class="${kind}">${esc(text)}</span>\n`);
  el.scrollTop = el.scrollHeight;
}

function indexTriage(tri) {
  const out = {};
  const list = Array.isArray(tri) ? tri : Object.values(tri || {}).find(Array.isArray) || [];
  list.forEach((x) => { if (x && x.id) out[x.id] = x; if (x && x.cve) out[x.cve] = x; });
  return out;
}

function renderAdvisories() {
  if (!state.findings.length) return ($("#tab-advisories").innerHTML = '<div class="empty">No advisories found.</div>');
  $("#tab-advisories").innerHTML = state.findings.map((f) => {
    const up = state.plan?.upgrades.find((u) => u.package.toLowerCase() === f.package.toLowerCase());
    const vulns = [...f.vulns].sort((a, b) => (SEV_RANK[a.severity] ?? 4) - (SEV_RANK[b.severity] ?? 4));
    return `<div class="pkg"><div class="pkg-head"><b>${esc(f.package)}</b><span class="ver">${esc(f.current)}</span><span class="muted">→</span>
      <span class="to">${esc(up ? up.to : "…")}</span><span class="tag">${f.vulns.length} advisories</span>
      ${up?.breaking ? '<span class="tag brk">⚠ breaking upgrade</span>' : ""}</div>
      ${vulns.map((v) => {
        const tr = state.triage[v.id] || state.triage[v.cve];
        const r = tr ? (tr.affected ?? tr.reachable ?? tr.exploitable) : null;
        const yes = r === true || r === "yes", no = r === false || r === "no";
        return `<div class="adv"><span class="sev ${v.severity || "NA"}">${v.severity || "N/A"}</span>
          <a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.cve || v.id)}</a>
          <div><div>${esc(v.summary)}</div>${tr ? `<div class="verdict"><span class="chip nano">nano</span> ${esc(tr.rationale || tr.reason || "")}</div>` : ""}</div>
          ${tr ? `<span class="tag ${yes ? "yes" : ""}">${yes ? "● reachable" : no ? "○ not reached" : esc(String(r ?? ""))}</span>` : "<span></span>"}</div>`;
      }).join("")}</div>`;
  }).join("");
}

function renderEvidence() {
  const quotes = state.evidence.map((e) => `<div class="ev-card"><span class="chip ${e.tier}">${e.tier} · patch #${e.attempt}</span>
    <blockquote>“${esc(e.quote)}”</blockquote><div class="src">${e.url ? `<a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.url)}</a>` : "migration notes"}</div></div>`).join("");
  const srcs = state.research.flatMap((r) => r.results.filter((x) => x.url).map((x) => `<li><span class="pk">${esc(r.package)}</span><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.title)}</a></li>`)).join("");
  $("#tab-evidence").innerHTML =
    (quotes ? `<div class="ev-section">Lines the agent relied on</div>${quotes}` : "") +
    (srcs ? `<div class="ev-section">Sources found by Tavily</div><ul class="src-list">${srcs}</ul>` : "") ||
    '<div class="empty">No research yet (is TAVILY_API_KEY set?).</div>';
}

function savingsByTokens() {
  const tot = TIERS.reduce((n, t) => n + state.usage[t].tok, 0);
  if (!tot) return "";
  const off = Math.round((1 - state.usage.ultra.tok / tot) * 100);
  return `<b>${off}%</b> of tokens ran on Nano/Super instead of Ultra. Set PRICE_* in .env to see it in dollars.`;
}

function renderRouting() {
  const max = Math.max(1, ...TIERS.map((t) => state.usage[t].tok));
  $("#routing").innerHTML = TIERS.map((t) => {
    const u = state.usage[t];
    return `<div class="tier"><div class="top"><span class="chip ${t}">${t}</span><span class="nums">${u.calls}× · ${u.tok.toLocaleString()} tok · ${u.s.toFixed(1)}s</span></div>
      <div class="model" title="${esc(u.model)}">${esc(u.model || "—")}</div>
      <div class="bar"><i style="width:${(u.tok / max) * 100}%;background:var(--${t});color:var(--${t})"></i></div></div>`;
  }).join("");
}

function renderTests() {
  $("#tests").innerHTML = state.tests.map((t) => `<li class="${t.ok ? "ok" : "bad"}"><span class="st">${t.ok ? "✓" : "✗"}</span>
    <div>${esc(t.label)}<small>${esc(t.summary)}</small></div></li>`).join("");
  const last = state.tests[state.tests.length - 1];
  const p = +(/(\d+) passed/.exec(last.summary)?.[1] || 0), f = +(/(\d+) failed/.exec(last.summary)?.[1] || 0);
  bumpKpi("#k-tests", p + f ? `${p}/${p + f}` : last.ok ? "✓" : "✗");
}

function renderDiff() {
  if (!state.diff) return;
  const html = state.diff.split("\n").map((l) => {
    const cls = l.startsWith("+++") || l.startsWith("---") ? "file" : l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "";
    return cls ? `<span class="${cls}">${esc(l)}</span>` : esc(l) + "\n";
  }).join("");
  $("#tab-diff").innerHTML = `<div class="toolbar"><button class="btn ghost" id="dlPatch">⇩ Download .patch</button></div><pre class="diff">${html}</pre>`;
  $("#dlPatch").onclick = () => download("patchpilot.patch", state.diff);
}

function renderReport() {
  const md = state.report.split("\n").map((l) => {
    let h = esc(l).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    if (l.startsWith("### ")) return `<h3>${h.slice(4)}</h3>`;
    if (l.startsWith("## ")) return `<h2>${h.slice(3)}</h2>`;
    if (l.startsWith("- ")) return `<li>${h.slice(2)}</li>`;
    if (l.startsWith("&gt; ")) return `<blockquote>${h.slice(5)}</blockquote>`;
    return h ? `<p>${h}</p>` : "";
  }).join("");
  $("#tab-report").innerHTML = `<div class="toolbar"><button class="btn ghost" id="copyMd">⧉ Copy markdown</button></div><div class="report">${md}</div>`;
  $("#copyMd").onclick = () => navigator.clipboard?.writeText(state.report).then(() => banner("Copied PR description", true));
}

async function loadBench() {
  const rows = await fetch("/api/bench").then((r) => r.json()).catch(() => []);
  if (!rows.length) return;
  const sum = (r, k) => Object.values(r.usage?.tiers || {}).reduce((n, t) => n + (t[k] || 0), 0);
  const ok = rows.filter((r) => r.ok).length;
  $("#tab-bench").innerHTML = `<p><b>${ok}/${rows.length}</b> cases fixed with all tests passing.</p>
    <table class="bench"><thead><tr><th>Case</th><th>Result</th><th>Attempts</th><th>Time</th><th>Tokens</th><th>Cost</th><th></th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td><code>${esc(r.repo)}</code></td><td>${r.ok ? '<span style="color:var(--ok)">✓ green</span>' : '<span style="color:var(--bad)">✗ review</span>'}</td>
      <td class="num">${r.attempts ?? "–"}</td><td class="num">${r.seconds ? fmtTime(r.seconds) : "–"}</td>
      <td class="num">${(sum(r, "in") + sum(r, "out")).toLocaleString()}</td>
      <td class="num">${r.usage?.priced ? "$" + r.usage.total.toFixed(4) : "–"}</td>
      <td><button class="btn ghost" data-run="${esc(r.run)}">Replay</button></td></tr>`).join("")}</tbody></table>`;
  document.querySelectorAll("[data-run]").forEach((b) => (b.onclick = () => listen(b.dataset.run, 4)));
}

// ---------- effects ----------
function bumpKpi(sel, val) { const el = $(sel); el.textContent = val; el.classList.remove("bump"); void el.offsetWidth; el.classList.add("bump"); }
function countTo(el, to, ms) {
  const from = parseInt(el.textContent) || 0, t0 = performance.now();
  if (reduced) return (el.textContent = to);
  (function f(now) { const p = Math.min((now - t0) / ms, 1); el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(f); })(t0);
}
function confetti() {
  if (reduced) return;
  const c = $("#confetti"), ctx = c.getContext("2d");
  c.width = innerWidth; c.height = innerHeight;
  const colors = ["#76b900", "#b4ff3a", "#4cc2ff", "#b98cff", "#ffffff", "#3ce39b"];
  const ps = Array.from({ length: 180 }, () => ({ x: innerWidth / 2 + (Math.random() - .5) * 200, y: innerHeight * .35,
    vx: (Math.random() - .5) * 16, vy: -Math.random() * 16 - 4, r: Math.random() * 6 + 3, c: colors[(Math.random() * colors.length) | 0], a: Math.random() * 6, va: (Math.random() - .5) * .3 }));
  let frames = 0;
  (function draw() {
    ctx.clearRect(0, 0, c.width, c.height);
    ps.forEach((p) => { p.vy += .35; p.vx *= .99; p.x += p.vx; p.y += p.vy; p.a += p.va;
      ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.a); ctx.fillStyle = p.c; ctx.fillRect(-p.r / 2, -p.r / 4, p.r, p.r / 2); ctx.restore(); });
    if (++frames < 220) requestAnimationFrame(draw); else ctx.clearRect(0, 0, c.width, c.height);
  })();
}
function banner(html, ok) {
  const b = $("#banner");
  b.innerHTML = html; b.className = "banner " + (ok ? "ok" : "bad"); b.hidden = false;
  clearTimeout(b._t); b._t = setTimeout(() => (b.hidden = true), 9000);
}
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" })); a.download = name; a.click();
}
function fmtTime(s) { s = Math.round(s); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`; }

boot();
