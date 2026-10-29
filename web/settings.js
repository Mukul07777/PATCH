// Settings (admins only): provider keys + models, connection tests, users, API keys, audit log.
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = window.ppEsc, api = window.ppApi;
  const SECRETS = ["llm_api_key", "tavily_api_key", "github_token"];
  const PLAIN = ["llm_base_url", "model_nano", "model_super", "model_ultra", "model_guard", "max_fix_attempts", "sandbox", "sandbox_image", "public_url"];
  const SMTP = ["smtp_host", "smtp_port", "smtp_user", "smtp_from"];
  const EVENT_LABEL = { new_findings: "new findings", new_critical: "new critical", kev: "KEV", scan_failed: "scan failed", fix_completed: "fix finished", test: "test" };
  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
  const say = (msg, bad) => { const el = $("#status"); el.textContent = msg || ""; el.classList.toggle("bad", !!bad); };
  const err = (id, msg) => { const el = $(id); el.textContent = msg || ""; el.hidden = !msg; };
  let me = null, auditPage = 1;

  // ---------- providers ----------
  function secretState(k, v) {
    $("#" + k).value = "";
    $("#" + k).placeholder = v.set ? "•••• stored, type to replace" : "not set";
    $(`#${k}_st`).textContent = v.set ? `Set${v.last4 ? `, ends in ${v.last4}` : ""} (from ${v.source === "settings" ? "these settings" : "the server environment"})` : "Not set";
  }
  async function sandboxNote() {
    const h = await (window.ppHealth || Promise.resolve({}));
    const sb = h.sandbox || {};
    $("#sandboxSt").textContent = sb.mode === "docker"
      ? (sb.ready ? `Docker sandbox active (${sb.image}): installs run with network, tests with --network none, 2 GB memory, 2 CPUs, read-only root, non-root user. Remote repositories may be fixed.`
        : "Docker sandbox selected but Docker is not available on this server: fix runs are refused until it is.")
      : "Local virtualenv: fix-run tests run on this server as the PatchPilot user. Choose Docker to isolate them (and to allow remote repositories without the switch above).";
  }
  function fill(s) {
    PLAIN.forEach((k) => { $("#" + k).value = s[k].value ?? (k === "sandbox" ? "local" : ""); });
    SMTP.forEach((k) => { $("#" + k).value = s[k].value ?? ""; });
    $("#smtp_starttls").checked = s.smtp_starttls.value !== "0";
    secretState("smtp_password", s.smtp_password);
    sandboxNote();
    $("#allow_remote_repos").checked = !!s.allow_remote_repos.value;
    SECRETS.forEach((k) => {
      const v = s[k];
      $("#" + k).value = "";
      $("#" + k).placeholder = v.set ? "•••• stored, type to replace" : "not set";
      $(`#${k}_st`).textContent = v.set ? `Set${v.last4 ? `, ends in ${v.last4}` : ""} (from ${v.source === "settings" ? "these settings" : "the server environment"})` : "Not set";
    });
  }
  $("#setForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#setErr", "");
    const body = {};
    PLAIN.forEach((k) => { body[k] = $("#" + k).value.trim(); });
    body.allow_remote_repos = $("#allow_remote_repos").checked;
    SECRETS.forEach((k) => {
      const v = $("#" + k).value.trim();
      if (v) body[k] = v; else if ($("#clearSecrets").checked) body[k] = "";
    });
    const btn = $("#saveBtn"); btn.disabled = true;
    try {
      fill(await api("/api/settings", { method: "PUT", body: JSON.stringify(body) }));
      $("#clearSecrets").checked = false;
      say("Settings saved. They apply to the next scan or run.");
      window.ppHealth = fetch("/api/health").then((r) => r.json()).catch(() => ({}));
      sandboxNote();
    } catch (x) { err("#setErr", x.message); }
    finally { btn.disabled = false; }
  });
  document.querySelectorAll("[data-test]").forEach((b) => b.addEventListener("click", async () => {
    const out = $("#testOut"), name = b.textContent.replace(/^Test /, "");
    out.textContent = `Testing ${name}…`; b.disabled = true;
    try {
      const r = await api(`/api/settings/test/${b.dataset.test}`, { method: "POST" });
      out.innerHTML = r.ok ? `<span class="status ok">${esc(name)} ok</span>` : `<span class="status bad">${esc(name)} failed</span> ${esc(r.error || "")}`;
    } catch (x) { out.textContent = `${name}: ${x.message}`; }
    finally { b.disabled = false; }
  }));

  // ---------- email (SMTP) ----------
  $("#smtpForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#smtpErr", "");
    const body = {};
    SMTP.forEach((k) => { body[k] = $("#" + k).value.trim(); });
    body.smtp_starttls = $("#smtp_starttls").checked;
    const pw = $("#smtp_password").value;
    if (pw) body.smtp_password = pw;
    try { fill(await api("/api/settings", { method: "PUT", body: JSON.stringify(body) })); say("Email settings saved."); loadAudit(); }
    catch (x) { err("#smtpErr", x.message); }
  });

  // ---------- notification channels ----------
  let chans = [], editing = null;
  function showType() {
    const t = $("#c_type").value;
    document.querySelectorAll("#chanForm [data-for]").forEach((d) => { d.hidden = !d.dataset.for.split(" ").includes(t); });
    $("#c_url").placeholder = t === "slack" ? "https://hooks.slack.com/services/…" : "https://example.com/hooks/patchpilot";
  }
  $("#c_type").addEventListener("change", showType);
  function resetChan() {
    editing = null; $("#chanForm").reset(); showType();
    $("#chanTitle").textContent = "Add a channel"; $("#chanSave").textContent = "Add channel"; $("#chanCancel").hidden = true;
    $("#c_type").disabled = false;
  }
  $("#chanCancel").onclick = resetChan;
  async function loadChannels() {
    chans = await api("/api/channels");
    const cfg = (c) => c.type === "email" ? (c.config.to || []).join(", ") : (c.config.url || "") + (c.type === "webhook" && c.config.secret_last4 ? ` (secret …${c.config.secret_last4})` : "");
    $("#channels").innerHTML = chans.length ? `<table class="bench"><caption class="sr-only">Notification channels</caption>
      <thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Target</th><th scope="col">Events</th><th scope="col">Min severity</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>${chans.map((c) => `<tr><td>${esc(c.name)}${c.enabled ? "" : ' <span class="status na">disabled</span>'}${c.readable ? "" : ' <span class="status bad">unreadable</span>'}</td><td><span class="tag">${esc(c.type)}</span></td>
        <td class="pj-sum"><code>${esc(cfg(c))}</code></td><td>${c.events.map((e) => esc(EVENT_LABEL[e] || e)).join(", ")}</td><td>${esc(c.min_severity)}</td>
        <td><button type="button" class="btn ghost sm" data-ctest="${c.id}">Send test<span class="sr-only"> to ${esc(c.name)}</span></button>
          <button type="button" class="btn ghost sm" data-cedit="${c.id}">Edit<span class="sr-only"> ${esc(c.name)}</span></button>
          <button type="button" class="btn ghost sm" data-cdel="${c.id}">Delete<span class="sr-only"> ${esc(c.name)}</span></button></td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">No channels yet.</div>';
    $("#channels").querySelectorAll("[data-ctest]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true; say("Sending a test message…");
      try {
        const r = await api(`/api/channels/${b.dataset.ctest}/test`, { method: "POST" });
        const d = r.delivery || {};
        say(r.ok ? `Test delivered${d.response_code ? ` (HTTP ${d.response_code})` : ""}.` : `Test failed: ${d.error || r.status}`, !r.ok);
        loadDeliveries(); loadAudit();
      } catch (x) { say(x.message, true); }
      finally { b.disabled = false; }
    }));
    $("#channels").querySelectorAll("[data-cedit]").forEach((b) => b.addEventListener("click", () => {
      const c = chans.find((x) => x.id === Number(b.dataset.cedit));
      editing = c.id; $("#c_type").value = c.type; $("#c_type").disabled = true; showType();
      $("#c_name").value = c.name; $("#c_sev").value = c.min_severity; $("#c_enabled").checked = c.enabled;
      $("#c_url").value = c.type === "webhook" ? c.config.url || "" : ""; $("#c_url").placeholder = c.type === "slack" ? "stored, type to replace" : $("#c_url").placeholder;
      $("#c_to").value = (c.config.to || []).join(", "); $("#c_secret").value = "";
      document.querySelectorAll("#chanForm [name=ev]").forEach((x) => { x.checked = c.events.includes(x.value); });
      $("#chanTitle").textContent = `Edit ${c.name}`; $("#chanSave").textContent = "Save channel"; $("#chanCancel").hidden = false;
      $("#c_name").focus();
    }));
    $("#channels").querySelectorAll("[data-cdel]").forEach((b) => b.addEventListener("click", async () => {
      if (!confirm("Delete this channel and its delivery log?")) return;
      try { await api(`/api/channels/${b.dataset.cdel}`, { method: "DELETE" }); say("Channel deleted."); if (editing === Number(b.dataset.cdel)) resetChan(); loadChannels(); loadDeliveries(); loadAudit(); }
      catch (x) { say(x.message, true); }
    }));
  }
  $("#chanForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#chanErr", "");
    const type = $("#c_type").value;
    const config = type === "email" ? { to: $("#c_to").value } : { url: $("#c_url").value.trim() };
    if (type === "webhook" && $("#c_secret").value.trim()) config.secret = $("#c_secret").value.trim();
    const body = { type, name: $("#c_name").value.trim(), config, min_severity: $("#c_sev").value, enabled: $("#c_enabled").checked,
      events: [...document.querySelectorAll("#chanForm [name=ev]")].filter((x) => x.checked).map((x) => x.value) };
    if (!body.name) return err("#chanErr", "Give the channel a name.");
    if (!body.events.length) return err("#chanErr", "Pick at least one event.");
    try {
      const r = await api(editing ? `/api/channels/${editing}` : "/api/channels", { method: editing ? "PUT" : "POST", body: JSON.stringify(body) });
      const box = $("#chanSecret");
      if (r.secret) { box.hidden = false; box.innerHTML = `<p><b>Signing secret</b> (verify <code>X-PatchPilot-Signature</code> with it; shown once):</p><div class="st-newkey">${esc(r.secret)}</div>`; }
      else box.hidden = true;
      say(editing ? "Channel saved." : `Added ${body.name}.`); resetChan(); loadChannels(); loadAudit();
    } catch (x) { err("#chanErr", x.message); }
  });
  async function loadDeliveries() {
    const rows = await api("/api/deliveries?limit=25");
    $("#deliveries").innerHTML = rows.length ? `<table class="bench"><caption class="sr-only">Recent notification deliveries</caption>
      <thead><tr><th scope="col">When</th><th scope="col">Channel</th><th scope="col">Event</th><th scope="col">Status</th><th scope="col">Response</th><th scope="col">Attempts</th></tr></thead>
      <tbody>${rows.map((d) => `<tr><td>${esc(when(d.created_at))}</td><td>${esc(d.channel || "(deleted)")}</td><td>${esc(EVENT_LABEL[d.event] || d.event)}</td>
        <td><span class="status ${d.status === "ok" ? "ok" : d.status === "failed" ? "bad" : "na"}">${esc(d.status)}</span></td>
        <td>${esc(d.response_code ?? "")} ${d.error ? `<span class="muted">${esc(d.error)}</span>` : ""}</td><td>${esc(d.attempts)}</td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">Nothing delivered yet.</div>';
  }

  // ---------- users ----------
  async function loadUsers() {
    const users = await api("/api/users");
    $("#users").innerHTML = `<table class="bench"><caption class="sr-only">Users</caption>
      <thead><tr><th scope="col">Email</th><th scope="col">Name</th><th scope="col">Role</th><th scope="col">Created</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>${users.map((u) => `<tr><td>${esc(u.email)}${u.id === me.id ? ' <span class="muted">(you)</span>' : ""}</td><td>${esc(u.name || "")}</td>
        <td><span class="tag">${esc(u.role)}</span></td><td>${esc(when(u.created_at))}</td>
        <td>${u.id === me.id ? "" : `<button type="button" class="btn ghost sm" data-role="${u.id}" data-to="${u.role === "admin" ? "member" : "admin"}">Make ${u.role === "admin" ? "member" : "admin"}<span class="sr-only"> ${esc(u.email)}</span></button>
          <button type="button" class="btn ghost sm" data-reset="${u.id}" data-email="${esc(u.email)}">Reset password<span class="sr-only"> for ${esc(u.email)}</span></button>
          <button type="button" class="btn ghost sm" data-deluser="${u.id}" data-email="${esc(u.email)}">Remove<span class="sr-only"> ${esc(u.email)}</span></button>`}</td></tr>`).join("")}</tbody></table>`;
    $("#users").querySelectorAll("[data-role]").forEach((b) => b.addEventListener("click", async () => {
      try { await api(`/api/users/${b.dataset.role}/role`, { method: "PUT", body: JSON.stringify({ role: b.dataset.to }) }); say("Role updated."); loadUsers(); loadAudit(); }
      catch (x) { say(x.message, true); }
    }));
    $("#users").querySelectorAll("[data-reset]").forEach((b) => b.addEventListener("click", () => {
      const f = $("#resetForm"); f.dataset.uid = b.dataset.reset; $("#resetWho").textContent = b.dataset.email;
      f.hidden = false; err("#resetErr", ""); $("#r_pw").focus();
    }));
    $("#users").querySelectorAll("[data-deluser]").forEach((b) => b.addEventListener("click", async () => {
      if (!confirm(`Remove ${b.dataset.email}? Their sessions and API keys stop working.`)) return;
      try { await api(`/api/users/${b.dataset.deluser}`, { method: "DELETE" }); say("User removed."); loadUsers(); loadKeys(); loadAudit(); }
      catch (x) { say(x.message, true); }
    }));
  }
  $("#userForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#userErr", "");
    const body = { email: $("#u_email").value.trim(), name: $("#u_name").value.trim(), password: $("#u_pw").value, role: $("#u_role").value };
    if (!body.email || body.password.length < 10) return err("#userErr", "Enter an email and a password of at least 10 characters.");
    try { await api("/api/users", { method: "POST", body: JSON.stringify(body) }); $("#userForm").reset(); say(`Added ${body.email}.`); loadUsers(); loadAudit(); }
    catch (x) { err("#userErr", x.message); }
  });

  $("#resetCancel").onclick = () => { $("#resetForm").hidden = true; $("#resetForm").reset(); };
  $("#resetForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#resetErr", "");
    const f = $("#resetForm"), password = $("#r_pw").value;
    if (password.length < 10) return err("#resetErr", "The new password needs at least 10 characters.");
    try {
      const r = await api(`/api/users/${f.dataset.uid}/password`, { method: "POST", body: JSON.stringify({ password }) });
      say(`Password reset for ${$("#resetWho").textContent}; ${r.sessions_ended} session${r.sessions_ended === 1 ? "" : "s"} signed out.`);
      f.reset(); f.hidden = true; loadAudit();
    } catch (x) { err("#resetErr", x.message); }
  });

  // ---------- your account ----------
  $("#pwForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#pwErr", "");
    const body = { current_password: $("#pw_cur").value, new_password: $("#pw_new").value };
    if (!body.current_password) return err("#pwErr", "Enter your current password.");
    if (body.new_password.length < 10) return err("#pwErr", "The new password needs at least 10 characters.");
    try {
      const r = await api("/api/auth/password", { method: "POST", body: JSON.stringify(body), noRedirect: true });
      $("#pwForm").reset();
      say(`Password changed.${r.other_sessions_ended ? ` ${r.other_sessions_ended} other session${r.other_sessions_ended === 1 ? "" : "s"} signed out.` : ""}`);
    } catch (x) { err("#pwErr", x.message); }
  });
  $("#logoutAll").onclick = async () => {
    if (!confirm("Sign out of PatchPilot everywhere, including this browser?")) return;
    try { await api("/api/auth/logout-all", { method: "POST" }); } catch {}
    location.href = "/login";
  };

  // ---------- API keys ----------
  async function loadKeys() {
    const keys = await api("/api/keys");
    $("#keys").innerHTML = keys.length ? `<table class="bench"><caption class="sr-only">API keys</caption>
      <thead><tr><th scope="col">Name</th><th scope="col">Key</th><th scope="col">Role</th><th scope="col">Owner</th><th scope="col">Created</th><th scope="col">Last used</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>${keys.map((k) => `<tr><td>${esc(k.name)}</td><td><code>${esc(k.prefix)}…</code></td><td><span class="tag">${esc(k.role)}</span></td><td>${esc(k.owner)}</td>
        <td>${esc(when(k.created_at))}</td><td>${esc(when(k.last_used))}</td>
        <td><button type="button" class="btn ghost sm" data-delkey="${k.id}">Revoke<span class="sr-only"> ${esc(k.name)}</span></button></td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">No API keys yet.</div>';
    $("#keys").querySelectorAll("[data-delkey]").forEach((b) => b.addEventListener("click", async () => {
      if (!confirm("Revoke this key? Anything using it stops working.")) return;
      try { await api(`/api/keys/${b.dataset.delkey}`, { method: "DELETE" }); say("Key revoked."); loadKeys(); loadAudit(); }
      catch (x) { say(x.message, true); }
    }));
  }
  $("#keyForm").addEventListener("submit", async (e) => {
    e.preventDefault(); err("#keyErr", "");
    const body = { name: $("#k_name").value.trim(), role: $("#k_role").value };
    if (!body.name) return err("#keyErr", "Give the key a name.");
    try {
      const k = await api("/api/keys", { method: "POST", body: JSON.stringify(body) });
      $("#keyForm").reset();
      const box = $("#newKey"); box.hidden = false;
      box.innerHTML = `<p><b>Copy this key now.</b> It will not be shown again.</p><div class="st-newkey">${esc(k.key)}</div>`;
      loadKeys(); loadAudit();
    } catch (x) { err("#keyErr", x.message); }
  });

  // ---------- audit ----------
  async function loadAudit() {
    const r = await api(`/api/audit?page=${auditPage}&per_page=25`);
    const pages = Math.max(1, Math.ceil(r.total / r.per_page));
    const detail = (d) => d && typeof d === "object" ? Object.entries(d).filter(([k]) => k !== "ip").map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ") : (d || "");
    $("#audit").innerHTML = r.entries.length ? `<table class="bench"><caption class="sr-only">Audit log, page ${auditPage} of ${pages}</caption>
      <thead><tr><th scope="col">When</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Detail</th></tr></thead>
      <tbody>${r.entries.map((e) => `<tr><td>${esc(when(e.ts))}</td><td>${esc(e.actor || "")}</td><td><code>${esc(e.action)}</code></td><td class="pj-sum">${esc(detail(e.detail))}</td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">Nothing logged yet.</div>';
    $("#auditPage").textContent = `Page ${auditPage} of ${pages}`;
    $("#auditPrev").disabled = auditPage <= 1; $("#auditNext").disabled = auditPage >= pages;
  }
  $("#auditPrev").onclick = () => { auditPage = Math.max(1, auditPage - 1); loadAudit(); };
  $("#auditNext").onclick = () => { auditPage += 1; loadAudit(); };

  window.ppReady.then(async (a) => {
    me = a.user;
    if (!me) return;
    if (me.via === "session") { $("#secAccount").hidden = false; $("#acctWho").textContent = `Signed in as ${me.email} (${me.role}).`; }
    if (me.role !== "admin") { $("#denied").hidden = false; return; }
    ["#secProviders", "#secNotify", "#secUsers", "#secKeys", "#secAudit"].forEach((s) => ($(s).hidden = false));
    showType();
    try {
      fill(await api("/api/settings"));
      await Promise.all([loadChannels(), loadDeliveries(), loadUsers(), loadKeys(), loadAudit()]);
    } catch (x) { say(`Could not load settings: ${x.message}`, true); }
  });
})();
