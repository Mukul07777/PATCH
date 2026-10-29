// Runs page: recorded runs, per-tier usage and benchmarks.
(() => {
  const esc = window.ppEsc;
  const when = (id) => { const m = /^(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)/.exec(id); return m ? new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}`).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : id; };
  const fmt = (s) => { s = Math.round(s); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`; };
  let runs = [], filter = "all";

  function render() {
    const list = runs.filter((r) => filter === "all" || (filter === "ok" ? r.ok === true : r.ok !== true));
    document.getElementById("runs").innerHTML = list.length ? list.map((r, i) => {
      const st = r.ok === true ? ["ok", "secured"] : r.ok === false ? ["bad", "review"] : ["na", "incomplete"];
      return `<a class="run spot rv" data-css="--d:${Math.min(i, 8) * .04}s" href="/console?replay=${encodeURIComponent(r.id)}">
        <div class="top"><span class="status ${st[0]}">${st[1]}</span><span class="go">Replay <span aria-hidden="true">▶</span></span></div>
        <code>${esc(r.repo)}</code><span class="id">${esc(when(r.id))} · ${esc(r.id.slice(-4))}</span></a>`;
    }).join("") : runs.length ? '<div class="empty span-all">No runs match this filter.</div>'
      : '<div class="empty span-all">No runs yet. <a href="/console">Launch the agent</a> to record one.</div>';
    window.ppReveal();
  }
  document.querySelectorAll(".chipbtn").forEach((b) => b.addEventListener("click", () => {
    filter = b.dataset.f;
    document.querySelectorAll(".chipbtn").forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-pressed", String(x === b)); });
    render();
  }));

  fetch("/api/runs").then((r) => r.json()).catch(() => []).then((r) => {
    r = Array.isArray(r) ? r : [];
    runs = r;
    const ok = r.filter((x) => x.ok === true).length, bad = r.filter((x) => x.ok === false).length;
    document.getElementById("s-total").textContent = r.length;
    document.getElementById("s-ok").textContent = ok;
    document.getElementById("s-bad").textContent = bad;
    document.getElementById("s-rate").textContent = ok + bad ? Math.round((ok / (ok + bad)) * 100) + "%" : "–";
    render();
  });

  // per-tier calls / tokens / seconds summed over the newest recorded runs (done.usage.tiers)
  const TIERS = ["nano", "super", "ultra"];
  async function doneOf(id) {
    const txt = await fetch(`/api/runs/${encodeURIComponent(id)}/events`).then((r) => r.text()).catch(() => "");
    const lines = txt.split(/\r?\n/).filter((l) => l.startsWith("data: "));
    for (let i = lines.length - 1; i >= 0; i--) { try { const e = JSON.parse(lines[i].slice(6)); if (e.type === "done") return e; } catch {} }
    return null;
  }
  function bars(title, unit, vals, fmtv) {
    const max = Math.max(1, ...vals), W = 300, rowH = 30, x0 = 50, bw = 175;
    const rows = TIERS.map((t, i) => {
      const w = Math.max(vals[i] ? 2 : 0, (vals[i] / max) * bw), y = i * rowH;
      return `<g><text x="0" y="${y + 17}">${t}</text><rect class="track" x="${x0}" y="${y + 5}" width="${bw}" height="16" rx="4"/>
        <rect x="${x0}" y="${y + 5}" width="${w.toFixed(1)}" height="16" rx="4" data-css="fill:var(--${t})"/>
        <text class="v" x="${W}" y="${y + 17}" text-anchor="end">${fmtv(vals[i])}</text></g>`;
    }).join("");
    const label = `${title}: ` + TIERS.map((t, i) => `${t} ${fmtv(vals[i])}${unit}`).join(", ");
    return `<figure><figcaption>${title}</figcaption><svg viewBox="0 0 ${W} ${rowH * 3}" role="img" aria-label="${esc(label)}"><title>${esc(label)}</title>${rows}</svg></figure>`;
  }
  fetch("/api/runs").then((r) => r.json()).catch(() => []).then(async (list) => {
    list = Array.isArray(list) ? list : [];
    const el = document.getElementById("tiers");
    const recent = list.slice(0, 8), dones = (await Promise.all(recent.map((r) => doneOf(r.id)))).filter((d) => d?.usage?.tiers);
    if (!dones.length) { el.innerHTML = '<div class="empty">No recorded usage yet.</div>'; return; }
    const tot = Object.fromEntries(TIERS.map((t) => [t, { calls: 0, in: 0, out: 0, seconds: 0 }]));
    dones.forEach((d) => TIERS.forEach((t) => { const u = d.usage.tiers[t] || {}; ["calls", "in", "out", "seconds"].forEach((k) => (tot[t][k] += +u[k] || 0)); }));
    const k = (n) => n >= 10000 ? Math.round(n / 1000) + "k" : n.toLocaleString();
    const allTok = TIERS.reduce((n, t) => n + tot[t].in + tot[t].out, 0), ultraTok = tot.ultra.in + tot.ultra.out;
    el.innerHTML = `<div class="tierchart">
        ${bars("Model calls", "", TIERS.map((t) => tot[t].calls), (v) => v.toLocaleString())}
        ${bars("Tokens (in + out)", " tokens", TIERS.map((t) => tot[t].in + tot[t].out), k)}
        ${bars("Latency (seconds)", "s", TIERS.map((t) => tot[t].seconds), (v) => v.toFixed(1))}
      </div>
      <p class="muted mt-14">Why three tiers: Nano does the cheap work, Ultra only when needed.
        Across the newest ${dones.length} run(s), <b class="c-text">${allTok ? Math.round((1 - ultraTok / allTok) * 100) : 0}%</b> of tokens ran below Ultra.</p>`;
  });

  fetch("/api/bench").then((r) => r.json()).catch(() => []).then((rows) => {
    if (!Array.isArray(rows) || !rows.length) return;
    const sum = (r, k) => Object.values(r.usage?.tiers || {}).reduce((n, t) => n + (t[k] || 0), 0);
    const ok = rows.filter((r) => r.ok).length, proven = rows.filter((r) => r.exploit === "proven closed").length;
    const rt = rows.filter((r) => r.redteam), blocked = rt.reduce((n, r) => n + r.redteam.blocked, 0), variants = rt.reduce((n, r) => n + r.redteam.total, 0);
    const trusts = rows.filter((r) => r.trust != null), adv = rows.reduce((n, r) => n + (r.advisories || 0), 0);
    const stat = (v, l) => `<div class="kpi"><span>${l}</span><b>${v}</b></div>`;
    document.getElementById("bench").innerHTML = `<div class="summary">
        ${stat(`${ok}/${rows.length}`, "Repos secured, tests green")}
        ${stat(adv || "–", "Real advisories handled")}
        ${stat(`${proven}/${rows.length}`, "Exploits proven closed")}
        ${stat(trusts.length ? Math.round(trusts.reduce((n, r) => n + r.trust, 0) / trusts.length) : "–", "Avg certificate trust")}
      </div>
      ${variants ? `<p class="muted mb-14">Red team: <b class="c-text">${blocked}/${variants}</b> attack variants blocked after the fix.</p>` : ""}
      <table class="bench"><thead><tr><th>Case</th><th>Result</th><th>Advisories</th><th>Attempts</th><th>Exploit</th><th>Trust</th><th>Time</th><th>Tokens</th><th></th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td><code>${esc(r.repo)}</code></td><td>${r.ok ? '<span class="status ok">green</span>' : '<span class="status bad">review</span>'}</td>
      <td class="num">${r.advisories ?? "–"}</td><td class="num">${r.attempts ?? "–"}</td>
      <td>${r.exploit ? `<span class="status ${r.exploit === "proven closed" ? "ok" : "na"}">${esc(r.exploit)}</span>` : '<span class="muted">–</span>'}</td>
      <td class="num">${r.trust ?? "–"}</td><td class="num">${r.seconds ? fmt(r.seconds) : "–"}</td>
      <td class="num">${(sum(r, "in") + sum(r, "out")).toLocaleString()}</td>
      <td><a class="btn ghost" href="/console?replay=${encodeURIComponent(r.run)}" class="no-underline">Replay</a></td></tr>`).join("")}</tbody></table>`;
  });
})();
