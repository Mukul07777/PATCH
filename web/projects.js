// Projects: list, add (GitHub URL or manifest), scan-only results, scan history, hand-off to the fix agent.
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = window.ppEsc;
  const SEV = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];
  const SEV_RANK = Object.fromEntries(SEV.map((s, i) => [s, i]));
  const MAX_BYTES = 200_000;
  let health = {}, current = null, sort = { key: "severity", dir: 1 }, findings = [], poll = null;

  const api = async (url, opts = {}) => {
    const r = await fetch(url, { ...opts, headers: { "Content-Type": "application/json", ...(opts.headers || {}) } });
    if (r.status === 204) return null;
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      const d = body.detail;
      throw new Error(Array.isArray(d) ? d.map((x) => (x.msg || "").replace(/^Value error, /, "")).join("; ") : d || `HTTP ${r.status}`);
    }
    return body;
  };
  const say = (msg, bad) => { const el = $("#status"); el.textContent = msg || ""; el.classList.toggle("bad", !!bad); };
  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
  const sevKey = (s) => { s = (s || "UNKNOWN").toUpperCase(); return s === "MEDIUM" ? "MODERATE" : SEV.includes(s) ? s : "UNKNOWN"; };
  const typeLabel = { git: "GitHub", upload: "Upload", path: "Local path", sample: "Sample" };

  function countChips(c) {
    if (!c) return "";
    const parts = SEV.filter((s) => c[s]).map((s) => `<span class="sev ${s === "UNKNOWN" ? "NA" : s}">${c[s]} ${s.toLowerCase()}</span>`);
    return parts.length ? parts.join(" ") : '<span class="status ok">no known vulns</span>';
  }
  function scanState(s) {
    if (!s) return '<span class="status na">not scanned</span>';
    if (s.status === "done") return countChips(s.counts);
    if (s.status === "error") return '<span class="status bad">scan failed</span>';
    return '<span class="status na">scanning…</span>';
  }

  // ---------- list ----------
  async function loadList() {
    const box = $("#projects");
    let list;
    try { list = await api("/api/projects"); } catch (e) {
      box.innerHTML = `<div class="empty span-all">Could not load projects: ${esc(e.message)}</div>`; return;
    }
    $("#samplesBtn").hidden = list.some((p) => p.source_type === "sample");
    if (!list.length) {
      box.innerHTML = `<div class="empty span-all">No projects yet. Add your own below, or <button type="button" class="btn ghost sm" id="emptySamples">add the sample projects</button> to try PatchPilot on bundled vulnerable code.</div>`;
      $("#emptySamples").onclick = addSamples;
      return;
    }
    box.innerHTML = list.map((p) => `<a class="pj-card card glass" href="/projects?id=${p.id}">
        <span class="pj-name">${esc(p.name)}</span>
        <span class="pj-meta"><span class="tag">${esc(typeLabel[p.source_type] || p.source_type)}</span> ${esc(p.source_type === "git" ? p.source.replace("https://github.com/", "") + (p.ref ? "@" + p.ref : "") : p.source)}</span>
        <span class="pj-sev">${scanState(p.last_scan)}</span>
        <span class="pj-when">Last scan: ${esc(when(p.last_scan_at))}</span></a>`).join("");
  }

  async function addSamples() {
    say("Adding sample projects…");
    try {
      const r = await api("/api/projects/samples", { method: "POST" });
      say(r.created.length ? `Added ${r.created.length} sample project${r.created.length === 1 ? "" : "s"}.` : "Sample projects are already added.");
      loadList();
    } catch (e) { say(`Could not add samples: ${e.message}`, true); }
  }
  $("#samplesBtn").onclick = addSamples;

  // ---------- new project form ----------
  const modeOf = () => document.querySelector("input[name=mode]:checked").value;
  document.querySelectorAll("input[name=mode]").forEach((r) => r.addEventListener("change", () => {
    $("#gitFields").hidden = modeOf() !== "git"; $("#uploadFields").hidden = modeOf() !== "upload";
  }));
  $("#file").addEventListener("change", async () => {
    const f = $("#file").files[0];
    if (!f) return;
    if (f.size > MAX_BYTES) { formErr(`${f.name} is larger than 200 KB.`); $("#file").value = ""; return; }
    $("#filename").value = f.name; $("#content").value = await f.text(); formErr("");
  });
  function formErr(msg) { const el = $("#formErr"); el.textContent = msg; el.hidden = !msg; }

  $("#newForm").addEventListener("submit", async (e) => {
    e.preventDefault(); formErr("");
    const body = { name: $("#pname").value.trim() };
    if (modeOf() === "git") {
      let url = $("#gitUrl").value.trim();
      if (!url) { formErr("Enter a GitHub repository URL."); $("#gitUrl").focus(); return; }
      if (!/^https?:\/\//i.test(url)) url = "https://" + url.replace(/^\/+/, "");
      Object.assign(body, { git_url: url.replace(/^http:/i, "https:"), ref: $("#gitRef").value.trim() });
    } else {
      const content = $("#content").value;
      if (!content.trim()) { formErr("Choose a manifest file or paste its contents."); $("#content").focus(); return; }
      if (new Blob([content]).size > MAX_BYTES) { formErr("The manifest is larger than 200 KB."); return; }
      Object.assign(body, { filename: $("#filename").value.trim() || "requirements.txt", content });
    }
    const btn = $("#createBtn"); btn.disabled = true; btn.textContent = "Adding…";
    try {
      const p = await api("/api/projects", { method: "POST", body: JSON.stringify(body) });
      $("#newForm").reset(); $("#gitFields").hidden = false; $("#uploadFields").hidden = true;
      history.pushState(null, "", `/projects?id=${p.id}`);
      await route();
      startScan();
    } catch (err) { formErr(err.message); }
    finally { btn.disabled = false; btn.textContent = "Add and scan"; }
  });

  // ---------- detail ----------
  async function showDetail(id) {
    $("#listView").hidden = true; $("#detailView").hidden = false;
    $("#findings").innerHTML = '<div class="empty">Loading…</div>';
    try { current = await api(`/api/projects/${id}`); } catch (e) {
      $("#pjTitle").textContent = "Project not found"; $("#pjSrc").textContent = e.message;
      $("#findings").innerHTML = '<div class="empty">This project does not exist or was deleted.</div>';
      ["#scanBtn", "#deleteBtn"].forEach((s) => ($(s).disabled = true)); fixState(false, "");
      return;
    }
    ["#scanBtn", "#deleteBtn"].forEach((s) => ($(s).disabled = false));
    document.title = `${current.name} · PatchPilot`;
    $("#pjTitle").textContent = current.name;
    const src = current.source_type === "git" ? current.source + (current.ref ? ` @ ${current.ref}` : "") : current.source;
    $("#pjSrc").textContent = `${typeLabel[current.source_type] || current.source_type} · ${src}`;
    setupFix();
    await loadHistory();
  }

  function fixState(on, why) {
    const a = $("#fixBtn");
    if (on) { a.href = `/console?project=${current.id}`; a.removeAttribute("aria-disabled"); a.classList.remove("is-disabled"); }
    else { a.removeAttribute("href"); a.setAttribute("aria-disabled", "true"); a.classList.add("is-disabled"); }
    $("#fixWhy").textContent = why;
  }
  function setupFix() {
    const t = current.source_type;
    if (!health.fix_mode) return fixState(false, "Fix mode is off: the server has no LLM API key. Scanning still works.");
    if (t === "upload") return fixState(false, "Uploaded manifests can be scanned but not fixed: the agent needs your code and tests. Add the project as a GitHub repository to fix it.");
    if (t === "path") return fixState(false, "Fix mode is not available for local path projects yet.");
    if (t === "git" && !health.remote_repos) return fixState(false, "This server does not run remote repositories (ALLOW_REMOTE_REPOS=0), so fixing is limited to sample projects.");
    fixState(true, "Opens the console and runs the agent: upgrade, repair until tests pass, verify, prepare a PR.");
  }

  async function loadHistory() {
    let scans;
    try { scans = await api(`/api/projects/${current.id}/scans`); } catch (e) {
      $("#history").innerHTML = `<div class="empty">Could not load scan history: ${esc(e.message)}</div>`; return;
    }
    $("#history").innerHTML = scans.length ? `<ol class="pj-hist">${scans.map((s) => `<li>
        <span class="tag">${s.kind === "fix" ? "fix run" : "scan"}</span>
        <span>${esc(when(s.started_at))}</span>
        <span>${s.kind === "fix" ? (s.status === "done" ? '<span class="status ok">secured</span>' : s.status === "error" ? '<span class="status bad">needs review</span>' : '<span class="status na">running</span>')
          : scanState(s)}</span>
        ${s.run_id ? `<a href="/console?replay=${encodeURIComponent(s.run_id)}">Replay run</a>` : s.status === "error" && s.summary?.error ? `<span class="muted">${esc(s.summary.error)}</span>` : ""}
      </li>`).join("")}</ol>` : '<div class="empty">No scans yet. Press <b>Scan now</b>.</div>';
    const lastScan = scans.find((s) => s.kind === "scan");
    if (!lastScan) { renderCounts(null); $("#findings").innerHTML = '<div class="empty">Not scanned yet. Press <b>Scan now</b> to check every pinned dependency against OSV.dev.</div>'; return; }
    if (lastScan.status === "queued" || lastScan.status === "running") return watch(lastScan.id);
    await loadScan(lastScan.id);
  }

  async function loadScan(id) {
    const s = await api(`/api/scans/${id}`);
    if (s.status === "error") {
      renderCounts(null);
      $("#findings").innerHTML = `<div class="empty">The last scan failed: ${esc(s.summary?.error || "unknown error")}</div>`;
      return s;
    }
    if (s.status !== "done") return s;
    findings = s.findings; renderCounts(s); renderFindings(s);
    return s;
  }

  function renderCounts(s) {
    const box = $("#pjCounts");
    if (!s) { box.innerHTML = ""; return; }
    const c = s.counts || {};
    box.innerHTML = [["Critical", c.CRITICAL, "c-bad"], ["High", c.HIGH, "c-warn"], ["Moderate", c.MODERATE, ""], ["Low / unrated", (c.LOW || 0) + (c.UNKNOWN || 0), ""]]
      .map(([k, n, cls]) => `<div class="kpi"><span>${k}</span><b class="${cls}">${n || 0}</b></div>`).join("");
  }

  function advLink(f) {
    const cve = f.aliases.find((a) => a.startsWith("CVE-"));
    const ghsa = [f.vuln_id, ...f.aliases].find((a) => a.startsWith("GHSA-"));
    const links = [`<a href="https://osv.dev/vulnerability/${encodeURIComponent(f.vuln_id)}" target="_blank" rel="noopener">${esc(f.vuln_id)}</a>`];
    if (cve) links.push(`<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener">${esc(cve)}</a>`);
    if (ghsa && ghsa !== f.vuln_id) links.push(`<a href="https://github.com/advisories/${encodeURIComponent(ghsa)}" target="_blank" rel="noopener">${esc(ghsa)}</a>`);
    return links.join("<br>");
  }

  const SORTS = {
    severity: (a, b) => SEV_RANK[sevKey(a.severity)] - SEV_RANK[sevKey(b.severity)] || (b.epss || 0) - (a.epss || 0),
    package: (a, b) => a.package.localeCompare(b.package),
    epss: (a, b) => (b.epss ?? -1) - (a.epss ?? -1),
  };
  function renderFindings(s) {
    const sum = s.summary || {};
    const notes = [];
    if (sum.pinned != null) notes.push(`${sum.pinned} pinned of ${sum.dependencies} dependencies in ${(sum.files || []).map(esc).join(", ")}`);
    if (sum.unpinned?.length) notes.push(`Not checked (no exact version): ${sum.unpinned.slice(0, 12).map(esc).join(", ")}${sum.unpinned.length > 12 ? "…" : ""}`);
    if (sum.errors?.length) notes.push(`Warnings: ${sum.errors.slice(0, 5).map(esc).join("; ")}`);
    const head = `<p class="hint">${notes.join("<br>")}<br>Scanned ${esc(when(s.finished_at))}.</p>`;
    if (!findings.length) { $("#findings").innerHTML = head + '<div class="empty">No known vulnerabilities in the pinned dependencies.</div>'; return; }
    const rows = [...findings].sort((a, b) => SORTS[sort.key](a, b) * sort.dir);
    const th = (key, label) => {
      const on = sort.key === key;
      return `<th scope="col" aria-sort="${on ? (sort.dir === 1 ? "ascending" : "descending") : "none"}"><button type="button" class="pj-sort" data-sort="${key}">${label}<span aria-hidden="true">${on ? (sort.dir === 1 ? " ▲" : " ▼") : ""}</span></button></th>`;
    };
    $("#findings").innerHTML = head + `<div class="pj-table" tabindex="0" role="region" aria-labelledby="findingsTitle"><table class="bench">
      <caption class="sr-only">${findings.length} findings, sorted by ${sort.key}</caption>
      <thead><tr>${th("severity", "Severity")}${th("package", "Package")}<th scope="col">Advisory</th>${th("epss", "EPSS")}<th scope="col">KEV</th><th scope="col">Fixed in</th><th scope="col">Summary</th></tr></thead>
      <tbody>${rows.map((f) => { const k = sevKey(f.severity); return `<tr>
        <td><span class="sev ${k === "UNKNOWN" ? "NA" : k}">${k === "UNKNOWN" ? "UNRATED" : k}</span></td>
        <td><code>${esc(f.package)}</code> <span class="muted">${esc(f.version || "")}</span></td>
        <td class="pj-adv">${advLink(f)}</td>
        <td class="num">${f.epss != null ? (f.epss * 100).toFixed(1) + "%" : '<span class="muted">–</span>'}</td>
        <td>${f.kev ? '<span class="status bad" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>' : '<span class="muted">–</span>'}</td>
        <td>${f.fixed_in ? `<code>${esc(f.fixed_in)}</code>` : '<span class="muted">no fix</span>'}</td>
        <td class="pj-sum">${esc(f.summary || "")}</td></tr>`; }).join("")}</tbody></table></div>`;
    document.querySelectorAll(".pj-sort").forEach((b) => b.addEventListener("click", () => {
      const k = b.dataset.sort; sort = { key: k, dir: sort.key === k ? -sort.dir : 1 };
      renderFindings(s); document.querySelector(`.pj-sort[data-sort="${k}"]`)?.focus();
    }));
  }

  // ---------- scanning ----------
  async function startScan() {
    if (!current) return;
    const btn = $("#scanBtn"); btn.disabled = true; btn.textContent = "Scanning…";
    say(`Scanning ${current.name}…`);
    try {
      const r = await api(`/api/projects/${current.id}/scan`, { method: "POST" });
      watch(r.id);
    } catch (e) { say(`Could not start the scan: ${e.message}`, true); btn.disabled = false; btn.textContent = "Scan now"; }
  }
  function watch(id) {
    clearTimeout(poll);
    const btn = $("#scanBtn"); btn.disabled = true; btn.textContent = "Scanning…";
    $("#findings").innerHTML = '<div class="empty">Scanning dependencies against OSV.dev…</div>';
    const pid = current.id;
    const tick = async () => {
      let s;
      try { s = await api(`/api/scans/${id}`); } catch (e) { say(`Lost track of the scan: ${e.message}`, true); return done(); }
      if (!current || current.id !== pid) return;
      if (s.status === "queued" || s.status === "running") { poll = setTimeout(tick, 1500); return; }
      if (s.status === "done") say(`Scan finished: ${s.findings.length} finding${s.findings.length === 1 ? "" : "s"}.`);
      else say(`Scan failed: ${s.summary?.error || "unknown error"}`, true);
      done(); loadHistory();
    };
    const done = () => { btn.disabled = false; btn.textContent = "Scan now"; };
    poll = setTimeout(tick, 600);
  }
  $("#scanBtn").onclick = startScan;
  $("#fixBtn").addEventListener("click", (e) => { if ($("#fixBtn").getAttribute("aria-disabled") === "true") e.preventDefault(); });
  $("#deleteBtn").onclick = async () => {
    if (!current || !confirm(`Delete ${current.name} and its scan history?`)) return;
    try {
      await api(`/api/projects/${current.id}`, { method: "DELETE" });
      say(`Deleted ${current.name}.`); history.pushState(null, "", "/projects"); route();
    } catch (e) { say(`Could not delete: ${e.message}`, true); }
  };

  // ---------- routing ----------
  async function route() {
    clearTimeout(poll);
    const id = new URLSearchParams(location.search).get("id");
    if (id && /^\d+$/.test(id)) return showDetail(id);
    current = null; document.title = "PatchPilot Projects";
    $("#listView").hidden = false; $("#detailView").hidden = true;
    const git = new URLSearchParams(location.search).get("git");
    if (git) { $("#gitUrl").value = git; $("#gitUrl").focus(); }
    await loadList();
  }
  addEventListener("popstate", route);
  $("#backLink").addEventListener("click", (e) => { e.preventDefault(); history.pushState(null, "", "/projects"); route(); });
  window.ppHealth.then((h) => { health = h || {}; route(); });
})();
