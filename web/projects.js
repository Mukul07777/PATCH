// Projects: list, add (GitHub URL or manifest), scan-only results, scan history, hand-off to the fix agent.
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = window.ppEsc;
  const SEV = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];
  const SEV_RANK = Object.fromEntries(SEV.map((s, i) => [s, i]));
  // upload limits match the server: lock files list every transitive package, so they get more room
  const LOCKS = /(^|\/)(poetry\.lock|uv\.lock|pipfile\.lock)$/i;
  const maxBytes = (name) => (LOCKS.test(name || "") ? 5_000_000 : 1_000_000);
  const mb = (n) => `${n / 1_000_000} MB`;
  let health = {}, current = null, sort = { key: "severity", dir: 1 }, findings = [], poll = null, lastScanId = null;

  const api = window.ppApi;
  let canEdit = false, isAdmin = false;  // anonymous public-demo visitors get a read-only view
  let channels = [];
  const say = (msg, bad) => { const el = $("#status"); el.textContent = msg || ""; el.classList.toggle("bad", !!bad); };
  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
  const sevKey = (s) => { s = (s || "UNKNOWN").toUpperCase(); return s === "MEDIUM" ? "MODERATE" : SEV.includes(s) ? s : "UNKNOWN"; };
  const typeLabel = { git: "GitHub", upload: "Upload", path: "Local path", sample: "Demo" };
  const typeTag = (t) => `<span class="tag${t === "sample" ? " demo" : ""}">${esc(typeLabel[t] || t)}</span>`;

  // How much of the dependency set a scan really checked. Older scans have no coverage block: derive it.
  function coverageOf(sum) {
    if (!sum) return null;
    if (sum.coverage) return sum.coverage;
    const total = sum.dependencies || 0, pinned = sum.pinned || 0;
    return { state: !pinned ? "unverified" : pinned >= total ? "verified" : "partial", total, pinned, checked: pinned, unpinned: (sum.unpinned || []).length };
  }
  function coverageBadge(cov) {
    if (!cov || cov.state === "verified") return "";
    if (cov.state === "unverified") return `<span class="status bad">NOT VERIFIED – ${cov.unpinned ? `${cov.unpinned} unpinned` : "nothing checked"}</span>`;
    return `<span class="status warn">Partially verified (${cov.checked} of ${cov.total} pinned)</span>`;
  }
  function countChips(c, cov) {
    if (!c) return "";
    const parts = SEV.filter((s) => c[s]).map((s) => `<span class="sev ${s === "UNKNOWN" ? "NA" : s}">${c[s]} ${s.toLowerCase()}</span>`);
    const badge = coverageBadge(cov);
    // a green all-clear only when every dependency was pinned and checked
    if (!parts.length) return badge || '<span class="status ok">no known vulns</span>';
    return parts.join(" ") + (badge ? " " + badge : "");
  }
  function scanState(s) {
    if (!s) return '<span class="status na">not scanned</span>';
    if (s.status === "done") return countChips(s.counts, coverageOf(s.summary));
    if (s.status === "error") return '<span class="status bad">scan failed</span>';
    if (s.status === "queued") return '<span class="status na">queued…</span>';
    return '<span class="status na">scanning…</span>';
  }

  // ---------- list ----------
  async function loadList() {
    const box = $("#projects");
    let list;
    try { list = await api("/api/projects"); } catch (e) {
      box.innerHTML = `<div class="empty span-all">Could not load projects: ${esc(e.message)}</div>`; return;
    }
    $("#samplesBtn").hidden = !canEdit || list.some((p) => p.source_type === "sample");
    $("#scanAllBtn").hidden = !isAdmin || !list.length;
    $("#newForm").hidden = !canEdit; $("#newTitle").hidden = !canEdit;
    if (!list.length) {
      box.innerHTML = `<div class="empty span-all">No projects yet. Add your own below, or <button type="button" class="btn ghost sm" id="emptySamples">add the sample projects</button> to try PatchPilot on bundled vulnerable code.</div>`;
      $("#emptySamples").onclick = addSamples;
      return;
    }
    box.innerHTML = list.map((p) => `<a class="pj-card card glass" href="/projects?id=${p.id}">
        <span class="pj-name">${esc(p.name)}</span>
        <span class="pj-meta">${typeTag(p.source_type)} ${esc(p.source_type === "git" ? p.source.replace("https://github.com/", "") + (p.ref ? "@" + p.ref : "") + (p.subdir ? "/" + p.subdir : "") : p.source)}</span>
        <span class="pj-sev">${scanState(p.last_scan)}</span>
        <span class="pj-when">Last scan: ${esc(when(p.last_scan_at))}</span></a>`).join("");
  }

  $("#scanAllBtn").addEventListener("click", async () => {
    const b = $("#scanAllBtn"); b.disabled = true;
    try {
      const r = await api("/api/projects/scan-all", { method: "POST" });
      say(r.queued ? `Queued ${r.queued} scan${r.queued === 1 ? "" : "s"}. Results appear as each one finishes.` : "Every project already has a scan queued or running.");
      setTimeout(loadList, 1500);
    } catch (e) { say(e.message, true); }
    finally { b.disabled = false; }
  });

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
    if (f.size > maxBytes(f.name)) { formErr(`${f.name} is larger than ${mb(maxBytes(f.name))}.`); $("#file").value = ""; return; }
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
      Object.assign(body, { git_url: url.replace(/^http:/i, "https:"), ref: $("#gitRef").value.trim(), subdir: $("#gitSub").value.trim() });
    } else {
      const content = $("#content").value, filename = $("#filename").value.trim() || "requirements.txt";
      if (!content.trim()) { formErr("Choose a manifest file or paste its contents."); $("#content").focus(); return; }
      if (new Blob([content]).size > maxBytes(filename)) { formErr(`${filename} is larger than ${mb(maxBytes(filename))}.`); return; }
      Object.assign(body, { filename, content });
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
    ["#scanBtn", "#deleteBtn"].forEach((s) => { $(s).disabled = false; $(s).hidden = !canEdit; });
    $("#policyForm").hidden = !canEdit;
    document.title = `${current.name} · PatchPilot`;
    $("#pjTitle").textContent = current.name;
    const src = current.source_type === "git" ? current.source + (current.ref ? ` @ ${current.ref}` : "") : current.source;
    $("#pjSrc").textContent = `${typeLabel[current.source_type] || current.source_type} · ${src}${current.subdir ? ` · folder ${current.subdir}` : ""}`;
    setupFix();
    await loadPolicy();
    await loadHistory();
  }

  // ---------- policy + ignore list ----------
  async function loadPolicy() {
    let policy;
    try { policy = await api(`/api/projects/${current.id}/policy`); } catch (e) { $("#ignores").innerHTML = ""; return; }
    $("#threshold").value = policy.severity_threshold; $("#autoFix").checked = policy.auto_fix;
    $("#schedule").value = policy.schedule || "off"; $("#scheduleHour").value = String(policy.schedule_hour ?? 3);
    $("#scheduleHour").disabled = $("#schedule").value === "off";
    $("#nextRun").textContent = policy.schedule !== "off" && policy.next_run_at
      ? `Next scheduled scan: ${new Date(policy.next_run_at * 1000).toLocaleString()} (${new Date(policy.next_run_at * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC).`
      : "No scheduled scans.";
    $("#chanBox").hidden = !canEdit || !channels.length;
    $("#chanList").innerHTML = channels.map((c) => `<label class="check"><input type="checkbox" data-chan="${c.id}"${policy.channels === null || policy.channels.includes(c.id) ? " checked" : ""}> ${esc(c.name)} <span class="muted">(${esc(c.type)}${c.enabled ? "" : ", disabled"})</span></label>`).join("");
    const ign = policy.ignores;
    $("#ignores").innerHTML = ign.length ? `<h3>Ignored advisories</h3><div class="tbl-wrap"><table class="bench"><caption class="sr-only">Ignored advisories</caption>
      <thead><tr><th scope="col">Advisory</th><th scope="col">Reason</th><th scope="col">Expires</th><th scope="col">By</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>${ign.map((i) => `<tr><td><code>${esc(i.vuln_id)}</code></td><td>${esc(i.reason)}</td>
        <td>${i.expires_at ? esc(new Date(i.expires_at * 1000).toLocaleDateString()) + (i.active ? "" : ' <span class="status na">expired</span>') : "never"}</td>
        <td>${esc(i.created_by || "")}</td>
        <td>${canEdit ? `<button type="button" class="btn ghost sm" data-unignore="${i.id}">Stop ignoring<span class="sr-only"> ${esc(i.vuln_id)}</span></button>` : ""}</td></tr>`).join("")}</tbody></table></div>`
      : '<p class="muted">No advisories ignored. Use <b>Ignore</b> on a finding to accept a risk with a reason.</p>';
    $("#ignores").querySelectorAll("[data-unignore]").forEach((b) => b.addEventListener("click", async () => {
      try { await api(`/api/projects/${current.id}/ignores/${b.dataset.unignore}`, { method: "DELETE" }); say("No longer ignored."); await loadPolicy(); refreshScan(); }
      catch (e) { say(e.message, true); }
    }));
  }
  $("#policyForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#policyErr"); err.hidden = true;
    try {
      const body = { severity_threshold: $("#threshold").value, auto_fix: $("#autoFix").checked,
        schedule: $("#schedule").value, schedule_hour: Number($("#scheduleHour").value) };
      if (channels.length) {
        const on = [...document.querySelectorAll("[data-chan]")].filter((c) => c.checked).map((c) => Number(c.dataset.chan));
        body.channels = on.length === channels.length ? null : on;  // all ticked = every channel, including future ones
      }
      await api(`/api/projects/${current.id}/policy`, { method: "PUT", body: JSON.stringify(body) });
      say("Policy saved."); await loadPolicy(); refreshScan();
    } catch (x) { err.textContent = x.message; err.hidden = false; }
  });
  const refreshScan = () => { if (lastScanId) loadScan(lastScanId); };
  $("#scheduleHour").innerHTML = Array.from({ length: 24 }, (_, h) => `<option value="${h}">${String(h).padStart(2, "0")}:00</option>`).join("");
  $("#schedule").addEventListener("change", () => { $("#scheduleHour").disabled = $("#schedule").value === "off"; });

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
    if (health.sandbox && !health.sandbox.ready) return fixState(false, "Fix runs are refused: the Docker sandbox is configured but Docker is not available on the server.");
    if (t === "git" && !health.remote_fix) return fixState(false, "This server does not run remote repositories' tests: an admin can enable the Docker sandbox (or allow remote repos) in Settings. Fixing is limited to sample projects.");
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
    lastScanId = id;
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
      .map(([k, n, cls]) => `<div class="kpi"><span>${k}</span><b class="${cls}">${n || 0}</b></div>`).join("")
      + (s.suppressed ? `<p class="muted span-all">${s.suppressed} suppressed by policy (not counted).</p>` : "");
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
    const cov = coverageOf(sum);
    const notes = [];
    if (sum.pinned != null) notes.push(`${sum.pinned} pinned of ${sum.dependencies} dependencies in ${(sum.files || []).map((f) => `<code>${esc(f)}</code>`).join(", ")}${sum.commit ? ` at <code>${esc(sum.commit.slice(0, 10))}</code>` : ""}`);
    if (sum.unpinned?.length) notes.push(`Not checked (no exact version): ${sum.unpinned.slice(0, 12).map(esc).join(", ")}${sum.unpinned.length > 12 ? `… (+${sum.unpinned.length - 12})` : ""}`);
    if (sum.diff) notes.push(`Since the previous scan: ${sum.diff.new} new, ${sum.diff.fixed} fixed`);
    const lockHint = "Add a lock file (poetry.lock, uv.lock, Pipfile.lock) or pin exact versions (<code>pip freeze</code> / <code>pip-compile</code>) so every package can be checked.";
    const banner = !cov || cov.state === "verified" ? ""
      : cov.state === "unverified"
        ? `<div class="pj-cov bad" role="note"><b>NOT VERIFIED${cov.unpinned ? ` – ${cov.unpinned} unpinned` : ""}.</b> No dependency could be checked against OSV.dev${cov.pinned ? " (the advisory lookup failed)" : ", because none has an exact version"}. A clean result here proves nothing. ${lockHint}</div>`
        : `<div class="pj-cov warn" role="note"><b>Partially verified (${cov.checked} of ${cov.total} pinned).</b> ${cov.total - cov.checked} dependenc${cov.total - cov.checked === 1 ? "y was" : "ies were"} not checked. ${lockHint}</div>`;
    const warns = [...(sum.errors || []), ...(sum.warnings || [])];
    const warnBox = warns.length ? `<details class="pj-warn"${sum.errors?.length ? " open" : ""}><summary>${warns.length} warning${warns.length === 1 ? "" : "s"}</summary><ul>${warns.slice(0, 50).map((w) => `<li>${esc(w)}</li>`).join("")}</ul></details>` : "";
    const dl = ["sarif", "cyclonedx", "json", "csv"].map((f) => `<a class="btn ghost sm no-underline" href="/api/scans/${s.id}/export?format=${f}" download>${{ sarif: "SARIF", cyclonedx: "CycloneDX SBOM", json: "JSON", csv: "CSV" }[f]}<span class="sr-only"> export of scan ${s.id}</span></a>`).join(" ");
    const head = `${banner}<p class="hint">${notes.join("<br>")}<br>Scanned ${esc(when(s.finished_at))}.</p>${warnBox}<p class="pj-export"><span class="muted">Export:</span> ${dl}</p>`;
    if (!findings.length) {
      $("#findings").innerHTML = head + `<div class="empty">${cov && cov.state !== "verified" ? `No known vulnerabilities in the ${cov.checked} checked dependenc${cov.checked === 1 ? "y" : "ies"}; the rest were not checked.` : "No known vulnerabilities in the pinned dependencies."}</div>`;
      return;
    }
    const rows = [...findings].sort((a, b) => SORTS[sort.key](a, b) * sort.dir);
    const th = (key, label) => {
      const on = sort.key === key;
      return `<th scope="col" aria-sort="${on ? (sort.dir === 1 ? "ascending" : "descending") : "none"}"><button type="button" class="pj-sort" data-sort="${key}">${label}<span aria-hidden="true">${on ? (sort.dir === 1 ? " ▲" : " ▼") : ""}</span></button></th>`;
    };
    $("#findings").innerHTML = head + `<div class="pj-table" tabindex="0" role="region" aria-labelledby="findingsTitle"><table class="bench">
      <caption class="sr-only">${findings.length} findings, sorted by ${sort.key}</caption>
      <thead><tr>${th("severity", "Severity")}${th("package", "Package")}<th scope="col">Advisory</th>${th("epss", "EPSS")}<th scope="col">KEV</th><th scope="col">Fixed in</th><th scope="col">Summary</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>${rows.map((f) => { const k = sevKey(f.severity); return `<tr class="${f.suppressed ? "suppressed" : ""}">
        <td><span class="sev ${k === "UNKNOWN" ? "NA" : k}">${k === "UNKNOWN" ? "UNRATED" : k}</span>${f.cvss_score != null ? ` <span class="muted" title="CVSS base score">${(+f.cvss_score).toFixed(1)}</span>` : ""}${f.new ? ' <span class="status ok">new</span>' : ""}${f.suppressed ? `<br><span class="status na" title="${esc(f.suppressed)}">suppressed</span><span class="sr-only"> (${esc(f.suppressed)})</span>` : ""}</td>
        <td><code>${esc(f.package)}</code> <span class="muted">${esc(f.version || "")}</span>${f.source_file ? `<br><span class="pj-file">${esc(f.source_file)}</span>` : ""}</td>
        <td class="pj-adv">${advLink(f)}</td>
        <td class="num">${f.epss != null ? (f.epss * 100).toFixed(1) + "%" : '<span class="muted">–</span>'}</td>
        <td>${f.kev ? '<span class="status bad" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>' : '<span class="muted">–</span>'}</td>
        <td>${f.fixed_in ? `<code>${esc(f.fixed_in)}</code>` : '<span class="muted">no fix</span>'}</td>
        <td class="pj-sum">${esc(f.summary || "")}</td>
        <td>${canEdit && !f.suppressed ? `<button type="button" class="btn ghost sm" data-ignore="${esc(f.vuln_id)}">Ignore<span class="sr-only"> ${esc(f.vuln_id)}</span></button>` : ""}</td></tr>`; }).join("")}</tbody></table></div>
      <form id="ignoreForm" class="fm pj-ign" hidden novalidate aria-labelledby="ignTitle">
        <h3 id="ignTitle">Ignore <code id="ignId"></code></h3>
        <div class="row2">
          <div><label for="ignReason">Reason <span class="muted">(required, kept in the audit log)</span></label><input id="ignReason" maxlength="300" autocomplete="off" placeholder="Not reachable: we never call the affected function"></div>
          <div><label for="ignExpires">Expires <span class="muted">(optional)</span></label><input id="ignExpires" type="date"></div>
        </div>
        <p class="pj-err" id="ignErr" role="alert" hidden></p>
        <div class="pj-actions"><button class="btn ghost" type="submit">Ignore advisory</button><button class="btn ghost" type="button" id="ignCancel">Cancel</button></div>
      </form>`;
    const form = $("#ignoreForm");
    document.querySelectorAll("[data-ignore]").forEach((b) => b.addEventListener("click", () => {
      form.dataset.vuln = b.dataset.ignore; $("#ignId").textContent = b.dataset.ignore; form.hidden = false; $("#ignReason").focus();
    }));
    $("#ignCancel").onclick = () => { form.hidden = true; };
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const reason = $("#ignReason").value.trim(), exp = $("#ignExpires").value, err = $("#ignErr");
      if (reason.length < 3) { err.textContent = "Give a reason (at least 3 characters)."; err.hidden = false; return; }
      const expires_at = exp ? new Date(exp + "T23:59:59").getTime() / 1000 : null;
      try {
        await api(`/api/projects/${current.id}/ignores`, { method: "POST", body: JSON.stringify({ vuln_id: form.dataset.vuln, reason, expires_at }) });
        say(`Ignoring ${form.dataset.vuln}.`); await loadPolicy(); refreshScan();
      } catch (x) { err.textContent = x.message; err.hidden = false; }
    });
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
      if (s.status === "queued" || s.status === "running") {
        $("#findings").innerHTML = `<div class="empty">${s.status === "queued" ? "Queued: waiting for a free scan worker…" : "Scanning dependencies against OSV.dev…"}</div>`;
        poll = setTimeout(tick, 1500); return;
      }
      const cov = coverageOf(s.summary);
      if (s.status === "done") say(`Scan finished: ${s.findings.length} finding${s.findings.length === 1 ? "" : "s"}${cov && cov.state !== "verified" ? ` (${cov.state === "unverified" ? "NOT verified" : `partially verified, ${cov.checked} of ${cov.total}`})` : ""}.`);
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
  Promise.all([window.ppHealth, window.ppReady]).then(async ([h, a]) => {
    health = h || {}; canEdit = !!(a && a.user); isAdmin = !!(a && a.user && a.user.role === "admin");
    if (canEdit) { try { channels = await api("/api/channels"); } catch { channels = []; } }
    route();
  });
})();
