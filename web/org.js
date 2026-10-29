// Org scan page: heat map of every public Python repo of a GitHub owner.
(() => {
  const esc = window.ppEsc;
  const $ = (s) => document.querySelector(s);
  const msg = (html) => ($("#heat").innerHTML = `<div class="empty span-all">${html}</div>`);
  const q = new URLSearchParams(location.search).get("owner");
  if (q) { $("#owner").value = q; scan(q); }
  $("#f").addEventListener("submit", (e) => {
    e.preventDefault();
    const o = $("#owner").value.trim();
    if (!o) return;
    history.replaceState(null, "", "?owner=" + encodeURIComponent(o));
    scan(o);
  });

  async function scan(owner) {
    msg("Scanning repos against OSV.dev…");
    $("#heat").setAttribute("aria-busy", "true");
    let r, data;
    try {
      r = await fetch("/api/org/" + encodeURIComponent(owner));
      data = await r.json().catch(() => ({}));
    } catch {
      $("#heat").removeAttribute("aria-busy");
      return msg("Could not reach the server. Check your connection and try again.");
    }
    $("#heat").removeAttribute("aria-busy");
    if (!r.ok) return msg(esc(data.detail || `Scan failed (HTTP ${r.status})`));
    const repos = Array.isArray(data.repos) ? data.repos : [];
    const rows = repos.filter((x) => x.has_reqs);
    const total = (x) => (x.critical || 0) + (x.high || 0) + (x.other || 0);
    $("#sum").hidden = false;
    $("#s-repos").textContent = data.scanned ?? repos.length;
    $("#s-vuln").textContent = rows.filter((x) => total(x)).length;
    $("#s-ch").textContent = rows.reduce((n, x) => n + (x.critical || 0) + (x.high || 0), 0);
    $("#s-all").textContent = rows.reduce((n, x) => n + total(x), 0);
    if (!rows.length) return msg("No repos with a requirements.txt found.");
    $("#heat").innerHTML = rows.map((x, i) => {
      const t = total(x), c = x.critical ? "var(--bad)" : x.high ? "var(--warn)" : t ? "var(--info)" : "var(--ok)";
      const pk = (x.packages || []).slice(0, 3).map((p) => `${esc(p.package)}==${esc(p.version)}`).join(" · ") || "clean";
      return `<div class="hc spot rv" style="--d:${Math.min(i, 10) * .03}s;--hc:${c};--heat:radial-gradient(circle at 100% 0%, ${c}, transparent 70%)">
        <div class="top"><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.name)}</a><span class="muted"><span aria-hidden="true">★</span><span class="sr-only">stars:</span> ${+x.stars || 0}</span></div>
        <div class="n">${t}</div>
        <div class="muted fs-12">${+x.critical || 0} critical · ${+x.high || 0} high · ${+x.other || 0} other · ${+x.pins || 0} pins</div>
        <div class="pk">${pk}</div>
        ${t ? `<a class="btn ghost fix" href="/console?repo=${encodeURIComponent(x.url)}">Fix with agent <span aria-hidden="true">→</span></a>` : ""}</div>`;
    }).join("") + (data.osv_capped ? '<div class="empty span-all">Large owner: the advisory lookup limit was reached, so some pins were not checked.</div>' : "");
    window.ppReveal();
  }
})();
