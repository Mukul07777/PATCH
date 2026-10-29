const $ = (s) => document.querySelector(s);
const esc = window.ppEsc;
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

// Stage labels name the model behind each tier: configured MODEL_* ids from /api/health, then the ids a run reports.
const TIERS = ["nano", "super", "ultra"];
const modelNames = { nano: "Nano tier", super: "Super tier", ultra: "Ultra tier" };
const shortModel = (id) => String(id || "").split("/").pop().replace(/:free$/, "");
const STEPS = [
  ["models", () => "Connect · LLM provider"], ["checkout", () => "Check out repo"], ["scan", () => "Scan · OSV.dev"],
  ["triage", () => `Triage · ${modelNames.nano}`], ["research", () => "Research via Tavily"], ["plan", () => `Plan · ${modelNames.super}`],
  ["exploit", () => "Exploit proof"], ["redteam", () => "Red-team variants"], ["lock", () => "Behaviour lock"], ["test", () => "Upgrade & test"],
  ["fix", () => `Repair · ${modelNames.super} → ${modelNames.ultra}`], ["pr", () => "Pull request"],
];
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3 };
let state, source, target = null, noLLM = false;  // target: {project} or {repo} to fix; noLLM: no NEBIUS_API_KEY, only replays
function setModelNames(models) {
  let changed = false;
  TIERS.forEach((t) => { if (models && models[t]) { modelNames[t] = shortModel(models[t]); changed = true; } });
  if (!changed) return;
  STEPS.forEach(([k, label]) => { const d = document.querySelector(`#s-${k} > div`); if (d && d.firstChild) d.firstChild.nodeValue = label(); });
  TIERS.forEach((t) => { const tx = document.querySelector(`#n-${t} text:not(.sub)`); if (tx) tx.textContent = graphLabel(t); });
}
// Graph nodes name the tier (full model ids are in the Model routing panel), so no id is ever cut off
const graphLabel = (t) => "Nemotron " + t[0].toUpperCase() + t.slice(1);

// ---------- tabs ----------
const TAB_BTNS = [...document.querySelectorAll(".tab[data-tab]")];
TAB_BTNS.forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
// WAI-ARIA tabs: arrow keys / Home / End move between all tabs (the tablist scrolls sideways on narrow screens).
$(".tabs[role=tablist]").addEventListener("keydown", (e) => {
  const i = TAB_BTNS.indexOf(document.activeElement);
  if (i < 0) return;
  const n = TAB_BTNS.length, to = { ArrowRight: (i + 1) % n, ArrowDown: (i + 1) % n, ArrowLeft: (i - 1 + n) % n, ArrowUp: (i - 1 + n) % n, Home: 0, End: n - 1 }[e.key];
  if (to == null) return;
  e.preventDefault();
  showTab(TAB_BTNS[to].dataset.tab);
  TAB_BTNS[to].focus();
});
// each tab groups several sections; callers may name a section (e.g. "ledger") and get its tab
const TAB_OF = { advisories: "findings", reach: "findings", terminal: "live", debate: "live", ledger: "proof",
  behaviour: "proof", proof: "proof", diff: "changes", report: "changes", drift: "changes", evidence: "changes" };
function showTab(section) {
  const name = TAB_OF[section] || section;
  TAB_BTNS.forEach((b) => {
    const on = b.dataset.tab === name;
    b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1;
  });
  document.querySelectorAll(".panel").forEach((p) => { const on = p.id === "grp-" + name; p.classList.toggle("active", on); p.hidden = !on; });
  // keep the active tab visible in the sideways-scrolling tablist without scrolling the page
  const btn = TAB_BTNS.find((b) => b.dataset.tab === name), list = btn?.parentElement;
  if (list && list.scrollWidth > list.clientWidth) list.scrollLeft = Math.max(0, btn.offsetLeft - list.offsetLeft - 24);
  // a named section further down its tab is scrolled into view
  const sub = document.querySelector(`.sub[data-sub="${section}"]`);
  if (sub && sub.previousElementSibling) sub.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
}

// ---------- agent graph ----------
const NODES = {
  repo:    { x: 70,  y: 125, label: "Repository", sub: "requirements.txt", c: "--muted" },
  osv:     { x: 215, y: 55,  label: "OSV.dev", sub: "advisories", c: "--bad" },
  nano:    { x: 370, y: 55,  get label() { return graphLabel("nano"); }, sub: "triage", c: "--nano" },
  tavily:  { x: 290, y: 195, label: "Tavily", sub: "migration research", c: "--tavily" },
  super:   { x: 520, y: 125, get label() { return graphLabel("super"); }, sub: "plan + repair", c: "--super" },
  sandbox: { x: 690, y: 125, label: "Sandbox", sub: "venv + pytest", c: "--info" },
  ultra:   { x: 690, y: 210, get label() { return graphLabel("ultra"); }, sub: "escalation", c: "--ultra" },
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
    <g class="node" id="n-${k}" data-css="--c:var(${n.c})" transform="translate(${n.x - NW / 2},${n.y - NH / 2})">
      <rect class="halo" width="${NW}" height="${NH}" rx="12"/>
      <rect width="${NW}" height="${NH}" rx="12"/>
      <text x="${NW / 2}" y="20">${esc(n.label)}</text>
      <text class="sub" x="${NW / 2}" y="35">${n.sub}</text>
    </g>`).join("");
  g.innerHTML = `<g id="edges">${edges}</g><g id="packets"></g>${nodes}`;
  window.ppCss(g);
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
  const [h, runs] = await Promise.all([
    window.ppHealth,
    window.ppReady.then(() => fetch("/api/runs")).then((r) => r.json()).catch(() => []),
  ]);
  setModelNames(h && h.models);
  buildGraph();
  if (h && h.nebius === false) {
    noLLM = true; $("#runBtn").disabled = true; $("#runBtn").setAttribute("aria-describedby", "noKey"); $("#noKey").hidden = false;
  }
  if (h.remote_repos === false) { $("#repo").disabled = true; $("#repo").placeholder = "Remote repos are off on this server"; $("#remoteOff").hidden = false; }
  const runList = Array.isArray(runs) ? runs : [];
  // shipped demo recordings are kept apart from this server's own runs so nobody mistakes them for their results
  const opt = (r) => `<option value="${esc(r.id)}">${r.ok === true ? "✓" : r.ok === false ? "✗" : "·"} ${esc(r.repo)} · ${esc(r.id)}</option>`;
  const own = runList.filter((r) => !r.sample), samples = runList.filter((r) => r.sample);
  $("#history").innerHTML = '<option value="">▶ Sample recordings: replay a run…</option>'
    + (own.length ? `<optgroup label="Your runs">${own.map(opt).join("")}</optgroup>` : "")
    + (samples.length ? `<optgroup label="Sample recordings (demo data)">${samples.map(opt).join("")}</optgroup>` : "");
  reset();
  const qs = new URLSearchParams(location.search), replay = qs.get("replay");
  await setTarget(qs.get("project"));
  if (qs.get("repo") && !$("#repo").disabled && !target) $("#repo").value = qs.get("repo");
  if (replay) listen(replay, 4);
  else if (!userStarted) {
    const best = await pickBestRun(runList);
    if (best && !userStarted) { if (qs.get("demo")) startDemo(); listen(best, qs.get("demo") ? 8 : 10, { auto: true }); }
  }
}

// ---------- auto replay + guided demo ----------
let userStarted = false, autoReplay = false, demo = null;
async function runTypes(id) {
  const txt = await fetch(`/api/runs/${encodeURIComponent(id)}/events`).then((r) => r.text()).catch(() => "");
  const evs = txt.split(/\r?\n/).filter((l) => l.startsWith("data: ")).map((l) => { try { return JSON.parse(l.slice(6)); } catch { return null; } }).filter(Boolean);
  const trust = evs.find((e) => e.type === "ledger")?.trust || 0;
  return { size: new Set(evs.map((e) => e.type)).size, trust };
}
async function pickBestRun(runs) {
  const ok = runs.filter((r) => r.ok === true).slice(0, 5);
  if (!ok.length) return null;
  // richest run first (most distinct event types), then the strongest certificate, then newest
  const sizes = await Promise.all(ok.map((r) => runTypes(r.id).then((t) => t.size * 1000 + t.trust)));
  let best = 0; sizes.forEach((n, i) => { if (n > sizes[best]) best = i; });
  return ok[best].id;
}
function setReplayBadge(on) { autoReplay = on; $("#replayBadge").hidden = !on; $("#realBtn").hidden = !on; }
$("#realBtn").onclick = () => {
  if (source) source.close();
  setReplayBadge(false); stopDemo(); reset(); $("#runBtn").disabled = noLLM;
  $(".launch").scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "center" });
  ($("#repo").disabled ? $("#runBtn") : $("#repo")).focus({ preventScroll: true });
};

const CHAPTERS = [
  ["Find", "advisories", "Scanning every pinned dependency against OSV.dev for real, published vulnerabilities."],
  ["Prioritize", "advisories", "Nemotron Nano ranks the advisories: which are severe, and which your code actually reaches."],
  ["Predict", "drift", "Before running anything, the drift radar compares old and new library APIs and predicts which of your lines will break."],
  ["Fix", "terminal", "Upgrading the dependency and running your own tests. When they fail, Nemotron rewrites the code and tries again."],
  ["Attack", "proof", "The red team fires attack variants at the app to check the hole is really closed, not just hidden."],
  ["Prove", "ledger", "The exploit that worked before the fix now fails. Every claim is checked and signed in a certificate, with an OpenVEX statement and the new release's provenance and OpenSSF Scorecard."],
  ["Ship", "diff", "Tests green, exploit closed: here is the verified patch, ready to open as a pull request."],
];
const CHAPTER_OF = { findings: 0, triage: 1, threat: 1, drift: 2, plan: 2, patch: 3, test: 3, redteam: 4, ledger: 5, diff: 6, report: 6, done: 6 };
function startDemo() {
  demo = { at: -1 };
  $("#sbSteps").innerHTML = CHAPTERS.map(([t], i) => `<li id="sb-${i}"><i>${i + 1}.</i> <span>${esc(t)}</span></li>`).join("");
  $("#storyBar").hidden = false; document.body.classList.add("demo"); $("#sbTitle").textContent = "Starting…"; $("#sbCap").textContent = "Replaying a recorded run. Sit back: the console will walk you through it.";
}
function stopDemo() { demo = null; $("#storyBar").hidden = true; document.body.classList.remove("demo"); }
$("#sbExit").onclick = () => stopDemo();
function storyStep(ev) {
  if (!demo) return;
  let c = CHAPTER_OF[ev.type];
  if (ev.type === "exploit") c = ev.stage === "after" ? 5 : 4;
  if (c == null || c <= demo.at) return false;
  demo.at = c;
  const [title, tab, cap] = CHAPTERS[c];
  CHAPTERS.forEach((_, i) => { const li = $("#sb-" + i); li.className = i < c ? "done" : i === c ? "on" : ""; });
  $("#sbTitle").textContent = `${c + 1}/7 · ${title}`;
  const cp = $("#sbCap"); cp.textContent = cap; cp.classList.remove("fade"); void cp.offsetWidth; if (!reduced) cp.classList.add("fade");
  showTab(tab);
  return true;
}
if ($("#demoBtn")) $("#demoBtn").onclick = (e) => {
  e.preventDefault(); userStarted = true;
  pickBestRun([...$("#history").options].slice(1).map((o) => ({ id: o.value, ok: o.textContent.startsWith("✓") })))
    .then((best) => { if (!best) return; startDemo(); listen(best, 8, { auto: true }); });
};

function reset() {
  state = { runId: null, trust: null, vex: null, guard: [], threat: null, drift: null, exploit: null, risk: null, redteam: null, behaviour: null, ledger: null, reach: {}, patches: [], findings: [], triage: {}, plan: null, tests: [], diff: "", report: "", evidence: [], research: [],
            usage: Object.fromEntries(TIERS.map((t) => [t, { calls: 0, tok: 0, s: 0, model: "" }])), total: 0 };
  renderTierbar(); $("#runSummary").hidden = true; $("#runSummary").innerHTML = "";
  $("#steps").innerHTML = STEPS.map(([k, t]) => `<li id="s-${k}"><span class="dot"></span><div>${esc(t())}<small></small></div></li>`).join("");
  $("#tests").innerHTML = '<li class="muted">No test runs yet</li>';
  ["adv", "tests", "att", "tok", "time"].forEach((k) => ($("#k-" + k).textContent = "–"));
  $("#term").innerHTML = "";
  $("#tab-advisories").innerHTML = '<div class="empty">Scanning…</div>';
  $("#tab-evidence").innerHTML = '<div class="empty">Migration sources from Tavily and the exact lines the agent relied on appear here.</div>';
  $("#tab-diff").innerHTML = '<div class="empty">The verified patch appears here.</div>';
  $("#tab-drift").innerHTML = '<div class="empty">Before any test runs, PatchPilot inspects the old and new library APIs and predicts exactly which of your lines will break.</div>';
  $("#tab-ledger").innerHTML = '<div class="empty">When the run finishes, every claim the PR makes is listed here with how it was verified.</div>';
  $("#tab-proof").innerHTML = '<div class="empty">PatchPilot writes an exploit test, shows it working on the old version, then proves the fix closes it.</div>';
  $("#tab-reach").innerHTML = '<div class="empty">Where your code calls each vulnerable package.</div>';
  $("#tab-behaviour").innerHTML = '<div class="empty">Before the upgrade, PatchPilot records what your own functions return. After the fix, every one must return the same thing, even if your repo has no tests.</div>';
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
  userStarted = true; if (source) source.close(); setReplayBadge(false); stopDemo();
  const repo = $("#repo").value.trim();
  const body = repo ? { repo } : target && target.project ? { project: target.project } : null;
  if (!body) return banner('Choose a project to fix first: open <a href="/projects">Projects</a> and press <b>Fix with agent</b>.', false);
  let run;
  try { run = await window.ppApi("/api/runs", { method: "POST", body: JSON.stringify(body) }); }
  catch (x) { return banner(esc(x.message || "Could not start run"), false); }
  listen(run.id, 0);
};
$("#noKeyLink").onclick = (e) => { e.preventDefault(); $("#history").focus(); };
$("#replayBtn").onclick = () => { const id = $("#history").value; if (id) { userStarted = true; stopDemo(); listen(id, 4); } };

// The fix target: a project from /projects (?project=<id>) or, when remote repos are on, a pasted GitHub URL.
async function setTarget(pid) {
  const box = $("#target");
  target = null;
  if (!pid || !/^\d+$/.test(pid)) {
    box.innerHTML = 'Pick what to fix on the <a href="/projects">Projects</a> page (or add the sample projects there), then press <b>Fix with agent</b>.';
    return;
  }
  await window.ppReady;
  const p = await fetch(`/api/projects/${pid}`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
  if (!p) { box.innerHTML = 'That project no longer exists. <a href="/projects">Back to projects</a>.'; return; }
  const name = `<b>${esc(p.name)}</b> <span class="muted">${esc(p.source_type === "sample" ? "sample project" : p.source)}</span>`;
  if (p.source_type === "upload" || p.source_type === "path") {
    box.innerHTML = `${name}<br>${p.source_type === "upload" ? "Uploaded manifests can be scanned but not fixed: the agent needs your code and tests to verify a fix. Add the project as a GitHub repository instead." : "Fix mode is not available for local path projects yet."} <a href="/projects?id=${p.id}">View its scan results</a>.`;
    $("#runBtn").disabled = true;
    return;
  }
  target = { project: p.id };
  box.innerHTML = `Fixing ${name} · <a href="/projects?id=${p.id}">project page</a>`;
}

// provider pill: live runs show the configured host; replays show the host the recorded run used
function providerFromModels(models) {
  const ids = Object.values(models || {}).filter(Boolean);
  if (ids.some((m) => m.endsWith(":free"))) return "OpenRouter";
  if (ids.some((m) => /^nvidia\/Nemotron-/.test(m))) return "Token Factory";  // capitalised ids are Token Factory's
  return "";
}
let runProvider = "";
function setProviderPill(replay, name) {
  if (name) runProvider = name;
  window.ppHealth.then((h) => {
    const pill = document.querySelector("#pills .pill");
    if (!pill) return;
    const label = replay ? `${runProvider || h.provider || "LLM"} · recorded` : (h.provider || "LLM");
    pill.classList.toggle("on", !!(replay || h.nebius));
    pill.querySelector("i").nextSibling.textContent = label;
    const sr = pill.querySelector(".sr-only");
    if (sr) sr.textContent = replay ? "" : (h.nebius ? " connected" : " not configured");
  });
}

function listen(id, replay, opts = {}) {
  if (source) source.close();
  reset();
  runProvider = "";
  setProviderPill(replay);
  state.runId = id;
  if ([...$("#history").options].some((o) => o.value === id)) $("#history").value = id;
  setReplayBadge(!!opts.auto);
  $("#runBtn").disabled = true;
  showTab("terminal");
  term("sys", `$ patchpilot run ${id}${replay ? "  --replay" : ""}`);
  source = new EventSource(`/api/runs/${encodeURIComponent(id)}/events?replay=${replay}`);
  const queue = [], src = source; let pumping = false, finished = false;
  const pump = async () => {
    if (pumping) return; pumping = true;
    while (queue.length && source === src) {
      const ev = queue.shift();
      const advanced = demo ? storyStep(ev) : false;
      handle(ev);
      if (advanced && demo) await new Promise((r) => setTimeout(r, 3800)); // let each chapter breathe
    }
    pumping = false;
  };
  src.addEventListener("message", (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    if (ev.type === "done") finished = true;
    if (replay && (ev.provider || (ev.type === "step" && ev.key === "models" && ev.detail)))
      setProviderPill(replay, ev.provider || (runProvider ? "" : providerFromModels(ev.detail)));
    queue.push(ev); pump();
  });
  src.addEventListener("error", () => {
    src.close(); $("#runBtn").disabled = noLLM;
    if (!finished && source === src) { banner("Connection lost. The event stream closed before the run finished.", false); phase("disconnected"); }
  });
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
      renderEvidence(); renderTierbar("tavily", `Searching: ${ev.package}`); break;
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
    case "reachability": state.reachability = ev.advisories; renderReach(); break;
    case "exploit": onExploit(ev); break;
    case "risk": state.risk = ev; renderProof(); break;
    case "trust": state.trust = ev.packages || {}; onTrust(); break;
    case "guard": state.guard.push(ev);
      term(ev.verdict === "block" ? "bad" : "dim", `guard › ${ev.kind}: ${ev.verdict}${ev.source ? ` (${ev.source})` : ""}`, ev.t); renderProof(); break;
    case "vex": state.vex = ev.document; { const n = vexCounts(ev.document); term("dim", `openvex › ${n.fixed} fixed · ${n.affected} affected · ${n.not_affected} not_affected`, ev.t); }
      if (state.ledger) renderLedger(); break;
    case "redteam": onRedteam(ev); break;
    case "behaviour": onBehaviour(ev); break;
    case "threat": onThreat(ev); break;
    case "drift": onDrift(ev); break;
    case "deps": term("dim", `deps › added ${(ev.added || []).map(d => `${d.package}==${d.version}`).join(", ")}`, ev.t); break;
    case "ledger": state.ledger = ev; renderLedger(); if (!demo) setTimeout(() => showTab("ledger"), 2600); break;
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
  if (ev.key === "models" && ev.detail) { TIERS.forEach((t) => (state.usage[t].model = ev.detail[t] || "")); renderRouting(); setModelNames(ev.detail);
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
    renderTierbar(ev.tier, ev.purpose);
    return term(ev.tier, `${ev.tier} › ${ev.purpose} …`, ev.t);
  }
  const u = state.usage[ev.tier];
  u.calls++; u.tok += ev.tokens_in + ev.tokens_out; u.s += ev.seconds; u.model = ev.model;
  term("dim", `   ✓ ${ev.tokens_in}→${ev.tokens_out} tok in ${ev.seconds}s`);
  bumpKpi("#k-tok", TIERS.reduce((n, t) => n + state.usage[t].tok, 0).toLocaleString());
  renderRouting(); renderTierbar();
}

// Live tier strip: which Nemotron tier (or Tavily) is working right now, with real call counts from the event stream.
const TB_IDLE = { nano: "Triage and symbol inference", super: "Upgrade plan and first-pass fixes", ultra: "Escalation on hard failures", tavily: "Migration-guide research" };
let tbTimer = null;
function renderTierbar(active, text) {
  document.querySelectorAll("#tierbar .tb-cell").forEach((c) => {
    const t = c.dataset.t, on = t === active;
    const n = t === "tavily" ? (state.research || []).length : state.usage[t].calls;
    c.querySelector(".tb-n").textContent = t === "tavily" ? `${n} search${n === 1 ? "" : "es"}` : `${n} call${n === 1 ? "" : "s"}`;
    if (active) { c.classList.toggle("on", on); c.querySelector(".tb-p").textContent = on ? text : (c.classList.contains("used") ? c.querySelector(".tb-p").textContent : TB_IDLE[t]); }
    if (on) c.classList.add("used");
    if (!active && !state.runId && !n) c.classList.remove("on", "used");
  });
  if (active) { clearTimeout(tbTimer); tbTimer = setTimeout(() => document.querySelectorAll("#tierbar .tb-cell.on").forEach((c) => c.classList.remove("on")), 2500); }
}

// End-of-run summary, computed only from events already received.
function renderSummary(ev) {
  const el = $("#runSummary");
    const first = state.tests.find((t) => t.label !== "baseline") || state.tests[0], last = state.tests[state.tests.length - 1];
  const tests = (t) => String(t.summary || "").replace(/ in [\d.]+s$/, "").replace(/, \d+ warnings?/, "");
  const x = state.exploit || {};
  const files = new Set((state.diff.match(/^\+\+\+ b\/.+$/gm) || []).map((l) => l.slice(6)));
  const calls = TIERS.map((t) => `<span class="chip ${t}">${t} ${state.usage[t].calls}</span>`).join(" ") + ` <span class="chip tavily">tavily ${state.research.length}</span>`;
  const cell = (k, v) => `<div><small>${k}</small><b>${v}</b></div>`;
  el.innerHTML = `<h2>${ev.ok ? (ev.rescue ? "Rescued: the dependency PR is green" : "Run summary: fixed and verified") : "Run summary: needs review"}</h2><div class="sum-grid">`
    + cell("CVEs fixed", ev.ok ? `${state.total} of ${state.total}` : `0 of ${state.total}`)
    + cell("Tests before → after", first && last ? `${esc(tests(first))} → ${esc(tests(last))}` : "–")
    + cell("Exploit before → after", x.title ? `${x.vulnerable ? "Exploited" : "Not reproduced"} → ${x.after ? (x.closed ? "Blocked" : "Still open") : "not run"}` : "No exploit proof")
    + cell("Behaviour lock", state.behaviour && state.behaviour.rows ? `${state.behaviour.preserved}/${state.behaviour.rows.length} identical` : "not recorded")
    + cell("Files changed", files.size ? `${files.size}` : "–")
    + `</div><p class="sum-calls">Model calls by tier ${calls}</p>`;
  el.hidden = false;
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
  $("#runBtn").disabled = noLLM;
  if (ev.usage) {
    TIERS.forEach((t) => { const r = ev.usage.tiers[t]; if (r) Object.assign(state.usage[t], { calls: r.calls, tok: r.in + r.out, s: r.seconds, model: r.model }); });
    renderRouting();
    $("#costNote").innerHTML = ev.usage.priced
      ? `Run cost <b>$${ev.usage.total.toFixed(4)}</b> vs $${ev.usage.all_ultra.toFixed(4)} if every call used Ultra: <b>${Math.round((1 - ev.usage.total / ev.usage.all_ultra) * 100)}% saved</b> by routing.`
      : savingsByTokens();
  }
  if (ev.seconds) $("#k-time").textContent = fmtTime(ev.seconds);
  if (ev.clean) { phase("clean"); return banner("No known advisories. Nothing to patch.", true); }
  state.done = ev; $("#speak").hidden = false; renderSummary(ev);
  if (ev.ok) {
    phase("secured ✓"); node("pr", "active"); pulse("sandbox", "pr", "var(--ok)");
    $("#exposure").classList.remove("hot"); $("#exposure").classList.add("safe"); countTo($("#expNum"), 0, 1300);
    document.querySelectorAll(".sevbar i").forEach((i) => (i.style.width = "0"));
    $("#sevlegend").textContent = `${state.total} advisories resolved · all tests passing`;
    term("ok", `✔ secured: ${state.total} advisories cleared in ${fmtTime(ev.seconds || 0)} with ${ev.attempts} repair attempt(s)`);
    const pr = ev.pr && /^https:\/\//i.test(ev.pr.url || "") ? ` <a href="${esc(ev.pr.url)}" target="_blank" rel="noopener">Open PR <span aria-hidden="true">↗</span></a>` : "";
    banner(`Secured. All tests passing after ${ev.attempts} repair attempt(s).` + pr, true);
    confetti(); if (!demo) setTimeout(() => showTab("diff"), 1800);
  } else if (ev.attempts != null) { phase("needs review"); banner("Could not reach green tests. Patch needs human review.", false); }
  else if (ev.error) { phase("error"); term("bad", `error › ${ev.error}`); banner(esc(ev.error), false); }
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
  if (!x && !r && !state.trust && !state.guard.length) return;
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
      <div class="gauge" data-css="--v:${r.score}"><b>${r.score}</b><small>${r.level} risk</small></div>
      <div class="factors">${r.factors.map((f) => `<div><span>${esc(f.name)}</span><span class="muted">${esc(f.detail)}</span><b>${f.points > 0 ? "+" : ""}${f.points}</b></div>`).join("")}</div></div>` : "";
  $("#tab-proof").innerHTML = renderGuard() + ex + renderRedteam() + renderTrust() + rk;
  window.ppCss($("#tab-proof"));
}

// ---------- guardrails + supply-chain trust ----------
function renderGuard() {
  const g = state.guard;
  const env = '<p class="hint guard-env"><span class="r-chip rs-no">on</span> Sandbox env: API keys withheld. The scanned repo\'s install and tests run with an allow-listed environment, never your tokens.</p>';
  if (!g.length) return `<div class="guard-static">${env}</div>`;
  const blocked = g.filter((e) => e.verdict === "block").length;
  return `<div class="card glass pf guard"><div class="pf-head"><span class="chip nano">guardrails</span><b>${g.length} item(s) screened</b>
    <span class="muted">${blocked ? `${blocked} blocked` : "all allowed"}</span></div>
    <div class="rt">${g.map((e) => `<div class="g-row"><span class="r-chip ${e.verdict === "block" ? "rs-hit" : "rs-no"}">${esc(e.verdict || "?")}</span>
      <b>${esc(e.kind || "item")}</b><small class="r-src">${esc(e.source || "")}</small>
      ${(e.reasons || []).length ? `<small class="muted">${(e.reasons || []).map(esc).join(" · ")}</small>` : ""}</div>`).join("")}</div>
    ${env}</div>`;
}

function onTrust() {
  const pk = Object.entries(state.trust || {});
  const prov = pk.filter(([, v]) => v.provenance === true).length;
  term("dim", `trust › ${prov}/${pk.length} target release(s) with verified provenance (deps.dev)`);
  renderProof();
}

function provBadge(v) {
  return v === true ? '<span class="r-chip rs-no">verified</span>' : v === false ? '<span class="r-chip rs-hit">none</span>' : '<span class="r-chip rs-unk">unknown</span>';
}

function renderTrust() {
  const pk = Object.entries(state.trust || {});
  if (!pk.length) return "";
  return `<div class="card glass pf trust"><div class="pf-head"><span class="chip super">supply chain</span><b>Supply-chain trust</b>
    <span class="muted">old vs new release on deps.dev: provenance, OpenSSF Scorecard, new transitive deps</span></div>
    ${pk.map(([name, v]) => {
      const from = v.from?.version ?? v.from ?? "?", to = v.to?.version ?? v.to ?? "?";
      const sc = v.scorecard, scCls = sc == null ? "na" : sc >= 7 ? "ok" : sc >= 5 ? "na" : "bad";
      const checks = Object.entries(v.checks || {});
      const nd = v.new_deps;
      return `<div class="tr-pkg"><div class="tr-head"><b>${esc(name)}</b><span class="ver">${esc(from)}</span><span class="muted">→</span><span class="to">${esc(to)}</span>
        ${v.source_repo ? `<small class="muted tr-repo">${esc(v.source_repo)}</small>` : ""}</div>
        ${v.error ? `<p class="muted">deps.dev unavailable: ${esc(v.error)}</p>` : `<div class="tr-grid">
          <div><small>Provenance</small><span>${provBadge(v.had_provenance)} <span class="muted">→</span> ${provBadge(v.provenance)}</span></div>
          <div><small>OpenSSF Scorecard</small><b class="tr-sc ${scCls}">${sc == null ? "–" : (+sc).toFixed(1)}<i>/10</i></b></div>
          <div><small>New transitive deps</small><span>${nd == null ? '<span class="muted">unknown</span>' : nd.length ? nd.map((d) => `<code>${esc(d)}</code>`).join(" ") : '<span class="muted">none</span>'}</span></div>
        </div>
        ${checks.length ? `<div class="tr-checks">${checks.map(([c, s]) => `<span class="${s == null ? "" : s >= 7 ? "ok" : s < 4 ? "bad" : ""}">${esc(c)} <b>${s ?? "–"}</b></span>`).join("")}</div>` : ""}`}
      </div>`;
    }).join("")}</div>`;
}

function vexCounts(doc) {
  const n = { fixed: 0, affected: 0, not_affected: 0, under_investigation: 0 };
  (doc?.statements || []).forEach((s) => { n[s.status] = (n[s.status] || 0) + 1; });
  return n;
}

function onThreat(ev) {
  state.threat = ev;
  term(ev.kev ? "bad" : "dim", `threat › ${ev.kev} known-exploited (CISA KEV) · max EPSS ${((ev.max_epss || 0) * 100).toFixed(2)}% · oldest exposure ${ev.oldest_days ?? "?"} days`, ev.t);
  if (state.findings.length) renderAdvisories();
}

function onDrift(ev) {
  state.drift = ev;
  term(ev.breaks.length ? "super" : "dim", `drift › ${ev.breaks.length} API break(s) predicted before testing (${ev.probed} symbols probed)`, ev.t);
  ev.breaks.forEach((b) => term("dim", `   ✗ ${b.detail}  @ ${b.sites.join(", ")}`));
  $("#tab-drift").innerHTML = `<div class="card glass"><div class="pf-head"><span class="chip super">drift radar</span>
      <b>${ev.breaks.length} predicted break(s)</b><span class="muted">${ev.probed} library symbols your code uses, probed on old and new versions</span></div>
    ${ev.breaks.length ? ev.breaks.map((b) => `<div class="drift ${b.kind}"><span class="dk">${b.kind === "removed" ? "removed" : "signature"}</span>
      <div><b>${esc(b.detail)}</b><small>${b.sites.map(esc).join(" · ")}</small></div></div>`).join("")
      : '<p class="muted">No removed APIs or changed signatures. Remaining failures, if any, come from behaviour changes, which only the tests can catch.</p>'}
    <p class="hint">Predicted from the installed libraries' real APIs, before a single test ran. Behaviour changes (same API, different results) are left to the test suite.</p></div>`;
}

function onRedteam(ev) {
  if (ev.stage === "before") {
    state.redteam = { ...ev };
    const landed = Object.values(ev.variants).filter((v) => !v).length;
    term("bad", `redteam › ${landed}/${Object.keys(ev.variants).length} attack variants land on the vulnerable pins (${ev.source})`, ev.t);
  } else {
    Object.assign(state.redteam || (state.redteam = {}), ev);
    term(ev.open ? "bad" : "ok", `redteam › after fix: ${ev.rows.length - ev.open}/${ev.rows.length} blocked${ev.open ? `, ${ev.open} STILL OPEN` : ""}`, ev.t);
  }
  renderProof();
}

function onBehaviour(ev) {
  if (ev.stage === "before") {
    state.behaviour = { ...ev };
    term("sys", `lock › recorded ${Object.keys(ev.cases).length} behaviours of your code on the vulnerable pins${ev.unstable.length ? ` (${ev.unstable.length} unstable dropped)` : ""}`, ev.t);
  } else {
    Object.assign(state.behaviour || (state.behaviour = {}), ev);
    term(ev.changed ? "bad" : "ok", `lock › after fix: ${ev.preserved}/${ev.rows.length} behaviours identical${ev.changed ? `, ${ev.changed} CHANGED` : ""}`, ev.t);
  }
  renderBehaviour();
}

function renderBehaviour() {
  const b = state.behaviour;
  if (!b) return;
  const show = (v) => esc(JSON.stringify(v && "raises" in v ? { raises: v.raises } : v && v.value !== undefined ? v.value : v).slice(0, 160));
  const rows = b.rows || Object.entries(b.cases).map(([c, v]) => ({ case: c, status: "locked", before: v }));
  const cls = (s) => (s === "preserved" ? "ok" : s === "locked" ? "na" : "bad");
  $("#tab-behaviour").innerHTML = `<div class="card glass pf"><div class="pf-head"><span class="chip super">behaviour lock</span>
    <b>${b.rows ? `${b.preserved}/${rows.length} identical after the fix` : `${rows.length} behaviours recorded on the vulnerable pins`}</b></div>
    <p class="hint">Tests only check what someone thought to assert. Before the upgrade PatchPilot calls your own functions with realistic inputs and records what they return (twice, keeping only stable results). After the repair every call must return exactly the same thing; any change is sent back to the repair model, even when pytest is green.</p>
    <div class="rt">${rows.map((x) => `<div class="rt-row ${cls(x.status)}"><code>${esc(x.case)}</code><span>${x.status === "changed" ? `${show(x.before)} → ${show(x.after)}` : `${show(x.before)} · ${esc(x.status)}`}</span></div>`).join("")}</div>
    ${b.unstable && b.unstable.length ? `<p class="hint">Dropped as non-deterministic: ${b.unstable.map(esc).join(", ")}</p>` : ""}</div>`;
}

function renderRedteam() {
  const r = state.redteam;
  if (!r) return "";
  const rows = r.rows || Object.entries(r.variants).map(([variant, blocked]) => ({ variant, status: blocked ? "blocked on old pins" : "lands on old pins" }));
  const cls = (s) => (s === "still open" || s === "lands on old pins" ? "bad" : s === "closed by fix" ? "ok" : "na");
  return `<div class="card glass pf"><div class="pf-head"><span class="chip ultra">red team</span><b>Attack variants</b>
    <span class="muted">${r.rows ? `${rows.length - r.open}/${rows.length} blocked after the fix` : "running against old pins…"} · ${esc(r.source)}</span></div>
    <div class="rt">${rows.map((x) => `<div class="rt-row ${cls(x.status)}"><code>${esc(x.variant)}</code><span>${esc(x.status)}</span></div>`).join("")}</div></div>`;
}

function renderLedger() {
  const L = state.ledger;
  const icon = { verified: "✓", partial: "◐", unverified: "✗" };
  $("#tab-ledger").innerHTML = `<div class="cert card glass">
    <div class="cert-head"><div><small>PatchPilot proof certificate</small><b>${esc(L.certificate)}</b></div>
      <div class="cert-trust" data-css="--v:${L.trust}"><b>${L.trust}</b><small>trust</small></div></div>
    <div class="claims">${L.claims.map((c) => `<div class="claim ${c.status}"><span class="ci">${icon[c.status]}</span>
      <div><b>${esc(c.claim)}</b><small>${esc(c.evidence)}</small></div><span class="cs">${c.status}</span></div>`).join("")}</div>
    <div class="cert-foot"><code title="sha256 of claims + diff">sha256 ${esc(L.sha256.slice(0, 32))}…</code>
      <span class="cert-btns"><button class="btn ghost" id="dlVex" title="OpenVEX v0.2.0: machine-readable exploitability statements"><span aria-hidden="true">⇩</span> OpenVEX</button>
      <button class="btn ghost" id="dlCert"><span aria-hidden="true">⇩</span> Download certificate</button></span></div>
    ${state.vex ? (() => { const n = vexCounts(state.vex); return `<div class="vex-sum"><span class="chip nano">OpenVEX</span>
      <span class="vx ok"><b>${n.fixed}</b> fixed</span><span class="vx bad"><b>${n.affected}</b> affected</span><span class="vx na"><b>${n.not_affected}</b> not affected</span>
      <small class="muted">${(state.vex.statements || []).length} statement(s), static evidence only</small></div>`; })() : ""}</div>`;
  window.ppCss($("#tab-ledger"));
  $("#dlCert").onclick = () => download(`${L.certificate}.json`, JSON.stringify(L, null, 2));
  $("#dlVex").onclick = async () => {
    let doc = state.vex;
    if (!doc && state.runId) doc = await fetch(`/api/runs/${encodeURIComponent(state.runId)}/vex`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    if (!doc) return banner("No OpenVEX document was recorded for this run.", false);
    state.vex = doc; download(`${state.runId || "patchpilot"}.openvex.json`, JSON.stringify(doc, null, 2)); renderLedger();
  };
}

function renderReach() {
  const entries = Object.entries(state.reach || {});
  const adv = Object.entries(state.reachability || {});
  const cls = { reachable: "rs-hit", imported: "rs-imp", "not reachable": "rs-no", unknown: "rs-unk" };
  const chips = adv.length ? `<div class="r-adv">${adv.map(([id, r]) => `<div class="r-adv-row">
      <span class="r-chip ${cls[r.status] || "rs-unk"}">${esc(r.status)}</span><b>${esc(id)}</b>
      ${r.symbols && r.symbols.length ? `<code>${esc(r.symbols.join(", "))}</code>` : ""}
      ${r.source === "llm-inferred" ? '<small class="r-src">llm-inferred</small>' : ""}
      ${r.sites && r.sites.length ? `<small>${r.sites.map(esc).join(" · ")}</small>` : r.note ? `<small class="muted">${esc(r.note)}</small>` : ""}
    </div>`).join("")}</div>` : "";
  if (!entries.length && !chips) return;
  $("#tab-reach").innerHTML = chips + entries.map(([pkg, hits]) => {
    const files = {};
    hits.forEach((h) => { const m = /^(.+?):(\d+): (.*)$/.exec(h); if (m) (files[m[1]] ||= []).push([m[2], m[3]]); });
    const fk = Object.keys(files);
    return `<div class="reach"><div class="r-pkg"><span class="sev HIGH">vuln</span><b>${esc(pkg)}</b><small>${hits.length} call-site(s)</small></div>
      <div class="r-files">${fk.length ? fk.map((f) => `<div class="r-file"><div class="r-name"><span aria-hidden="true">📄</span> ${esc(f)}</div>
        ${files[f].map(([ln, code]) => `<div class="r-line"><span>${ln}</span><code>${esc(code)}</code></div>`).join("")}</div>`).join("")
        : '<div class="muted r-none">Not imported directly. Likely a transitive dependency.</div>'}</div></div>`;
  }).join("");
}

function renderDebate() {
  $("#tab-debate").innerHTML = `<div class="debate">${state.patches.map((p) => {
    const tier = TIERS.includes(p.tier) ? p.tier : "super";  // allow-list: tier lands in a class name and a CSS var
    return `<div class="db card glass" data-css="--c:var(--${tier})">
    <div class="db-head"><span class="chip ${tier}">${esc(tier)}</span><b>Attempt #${esc(String(p.attempt))}</b></div>
    <small>Diagnosis</small><p>${esc(p.diagnosis || "—")}</p><small>Fix</small><p>${esc(p.explanation)}</p>
    <div class="muted">${(p.files || []).map((f) => "<span aria-hidden=\"true\">✎</span> " + esc(f)).join("<br>")}</div></div>`;
  }).join("")}</div>`;
  window.ppCss($("#tab-debate"));
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
  const rt = state.redteam;
  if (rt?.rows) parts.push(`Red team: ${rt.rows.length - rt.open} of ${rt.rows.length} attack variants blocked${rt.open ? `, ${rt.open} still open` : ""}.`);
  if (state.ledger) parts.push(`Proof certificate trust score ${state.ledger.trust} percent.`);
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
  const T = state.threat;
  const clock = T ? `<div class="threat card glass">
      <div><small>CISA known exploited</small><b class="${T.kev ? "hot" : ""}">${T.kev}</b></div>
      <div><small>Highest EPSS (30-day exploit odds)</small><b>${T.max_epss != null ? (T.max_epss * 100).toFixed(2) + "%" : "–"}</b></div>
      <div><small>Exposed for</small><b>${T.oldest_days != null ? T.oldest_days.toLocaleString() + " days" : "–"}</b></div>
    </div>` : "";
  $("#tab-advisories").innerHTML = clock + state.findings.map((f) => {
    const up = state.plan?.upgrades.find((u) => u.package.toLowerCase() === f.package.toLowerCase());
    const vulns = [...f.vulns].sort((a, b) => (SEV_RANK[a.severity] ?? 4) - (SEV_RANK[b.severity] ?? 4));
    return `<div class="pkg"><div class="pkg-head"><b>${esc(f.package)}</b>${f.transitive ? '<span class="chip nano" title="Not in requirements.txt: installed as a dependency of a dependency">via dependency</span>' : ""}<span class="ver">${esc(f.current)}</span><span class="muted">→</span>
      <span class="to">${esc(up ? up.to : "…")}</span><span class="tag">${f.vulns.length} advisories</span>
      ${f.min_safe && f.min_safe !== f.latest ? `<span class="tag" title="Smallest release that clears every advisory">least-change: ${esc(f.min_safe)}</span>` : ""}
      ${up?.breaking ? '<span class="tag brk">⚠ breaking upgrade</span>' : ""}</div>
      ${vulns.map((v) => {
        const tr = state.triage[v.id] || state.triage[v.cve];
        const r = tr ? (tr.affected ?? tr.reachable ?? tr.exploitable) : null;
        const yes = r === true || r === "yes", no = r === false || r === "no";
        const th = T?.advisories[v.id];
        const badges = th ? `<div class="thb">${th.kev ? '<span class="kev">KEV · exploited in the wild</span>' : ""}${th.epss != null ? `<span title="EPSS percentile ${Math.round(th.percentile * 100)}">EPSS ${(th.epss * 100).toFixed(2)}%</span>` : ""}${th.days != null ? `<span>${th.days.toLocaleString()} days public</span>` : ""}</div>` : "";
        return `<div class="adv"><span class="sev ${v.severity || "NA"}">${v.severity || "N/A"}</span>
          <a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.cve || v.id)}</a>
          <div><div>${esc(v.summary)}</div>${badges}${tr ? `<div class="verdict"><span class="chip nano">nano</span> ${esc(tr.rationale || tr.reason || "")}</div>` : ""}</div>
          ${tr ? `<span class="tag ${yes ? "yes" : ""}">${yes ? "● reachable" : no ? "○ not reached" : esc(String(r ?? ""))}</span>` : "<span></span>"}</div>`;
      }).join("")}</div>`;
  }).join("");
}

function renderEvidence() {
  const quotes = state.evidence.map((e) => `<div class="ev-card"><span class="chip ${e.tier}">${e.tier} · patch #${e.attempt}</span>
    <blockquote>“${esc(e.quote)}”</blockquote><div class="src">${e.url ? `<a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.url)}</a>` : "migration notes"}</div></div>`).join("");
  const srcs = state.research.flatMap((r) => r.results.filter((x) => x.url).map((x) => `<li><span class="pk">${esc(r.package)}</span>${x.score != null ? `<span class="rr" title="Relevance 0-10 (Tavily score, or Nemotron Nano rerank when Tavily gives none)">${(+x.score).toFixed(1)}</span>` : ""}<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.title)}</a></li>`)).join("");
  $("#tab-evidence").innerHTML =
    (quotes ? `<div class="ev-section">Lines the agent relied on</div>${quotes}` : "") +
    (srcs ? `<div class="ev-section">Research via Tavily <span class="muted">(top 4 of 8 results by relevance score; listed in the PR report)</span></div><ul class="src-list">${srcs}</ul>` : "") ||
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
      <div class="bar"><i class="t-${t}" data-css="width:${(u.tok / max) * 100}%"></i></div></div>`;
  }).join("");
  window.ppCss($("#routing"));
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
  $("#tab-diff").innerHTML = `<div class="toolbar"><button class="btn ghost" id="dlPatch"><span aria-hidden="true">⇩</span> Download .patch</button></div><pre class="diff">${html}</pre>`;
  $("#dlPatch").onclick = () => download("patchpilot.patch", state.diff);
}

function renderReport() {
  const md = state.report.split("\n").map((l) => {
    let h = esc(l).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, url) => window.ppMdLink(label, url));
    if (l.startsWith("### ")) return `<h3>${h.slice(4)}</h3>`;
    if (l.startsWith("## ")) return `<h2>${h.slice(3)}</h2>`;
    if (l.startsWith("- ")) return `<li>${h.slice(2)}</li>`;
    if (l.startsWith("&gt; ")) return `<blockquote>${h.slice(5)}</blockquote>`;
    return h ? `<p>${h}</p>` : "";
  }).join("");
  $("#tab-report").innerHTML = `<div class="toolbar"><button class="btn ghost" id="copyMd"><span aria-hidden="true">⧉</span> Copy markdown</button></div><div class="report">${md}</div>`;
  $("#copyMd").onclick = () => navigator.clipboard?.writeText(state.report).then(() => banner("Copied PR description", true));
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
  const colors = ["#047857", "#10b981", "#0369a1", "#6d28d9", "#c2410c", "#f59e0b"];
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
