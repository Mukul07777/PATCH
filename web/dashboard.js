// Dashboard: aggregates from /api/dashboard (stored scans only). Charts are plain HTML/SVG bars with text equivalents.
(() => {
  const esc = window.ppEsc;
  const box = document.getElementById("dash");
  const SEV = [["CRITICAL", "Critical", "c-crit"], ["HIGH", "High", "c-high"], ["MODERATE", "Moderate", "c-mod"], ["LOW", "Low", "c-low"], ["UNKNOWN", "Unrated", "c-unk"]];
  const pct = (n, max) => (max ? Math.max(n ? 2 : 0, (n / max) * 100) : 0).toFixed(1) + "%";
  const dur = (s) => {
    if (s == null) return "–";
    if (s < 3600) return Math.max(1, Math.round(s / 60)) + " min";
    if (s < 86400 * 2) return (s / 3600).toFixed(1) + " h";
    return (s / 86400).toFixed(1) + " days";
  };
  const kpi = (label, value, cls = "", sub = "") => `<div class="kpi"><span>${label}</span><b class="${cls}">${value}</b>${sub ? `<small class="muted">${sub}</small>` : ""}</div>`;

  // One horizontal bar per row; a stacked bar when `parts` is given. The numbers are always printed as text too.
  function bars(rows, max) {
    return `<ul class="db-bars">${rows.map((r) => `<li>
      <span class="lbl">${r.href ? `<a href="${r.href}">${esc(r.label)}</a>` : esc(r.label)}</span>
      <span class="db-track" aria-hidden="true">${(r.parts || [[r.value, r.cls || ""]]).map(([n, cls]) => `<i class="${cls}" data-css="--w:${pct(n, max)}"></i>`).join("")}</span>
      <span class="db-num">${r.value}</span>${r.note ? `<span class="sr-only">${esc(r.note)}</span>` : ""}</li>`).join("")}</ul>`;
  }

  function trendChart(trend) {
    if (!trend.length) return '<div class="empty">No finished scans yet.</div>';
    const W = 600, H = 150, pad = 18, n = trend.length, max = Math.max(1, ...trend.map((t) => t.open));
    const step = W / n, bw = Math.min(step * 0.7, 36);
    const rects = trend.map((t, i) => {
      const h = t.open ? Math.max(2, (t.open / max) * (H - pad - 4)) : 2;
      return `<rect class="${t.open ? "" : "zero"}" x="${(i * step + (step - bw) / 2).toFixed(1)}" y="${(H - pad - h).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2"><title>${esc(t.day)}: ${t.open} open</title></rect>`;
    }).join("");
    const label = `Open findings per day from ${trend[0].day} to ${trend[n - 1].day}: ${trend[n - 1].open} today, peak ${max}.`;
    return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label)}">${rects}
        <text class="axis" x="0" y="${H - 3}">${esc(trend[0].day)}</text><text class="axis" x="${W}" y="${H - 3}" text-anchor="end">${esc(trend[n - 1].day)}</text>
        <text class="axis" x="0" y="10">max ${max}</text></svg>
      <details><summary>Show as table</summary><div class="tbl-wrap"><table class="bench"><caption class="sr-only">Open findings per day (UTC)</caption>
        <thead><tr><th scope="col">Day (UTC)</th><th scope="col">Open findings</th></tr></thead>
        <tbody>${trend.map((t) => `<tr><td>${esc(t.day)}</td><td class="num">${t.open}</td></tr>`).join("")}</tbody></table></div></details>`;
  }

  function render(d) {
    if (!d.projects) {
      box.innerHTML = `<div class="card glass empty">No projects yet. <a href="/projects">Add a project</a> (or the bundled sample projects) and scan it: this dashboard fills in from real scan results.</div>`;
      return;
    }
    if (!d.scanned) {
      box.innerHTML = `<div class="card glass empty">${d.projects} project${d.projects === 1 ? "" : "s"}, none scanned yet. Open <a href="/projects">Projects</a> and press <b>Scan now</b>.</div>`;
      return;
    }
    const c = d.by_severity;
    const sevMax = Math.max(...SEV.map(([k]) => c[k]));
    const riskMax = Math.max(1, ...d.at_risk.map((p) => p.total));
    const pkgMax = Math.max(1, ...d.top_packages.map((p) => p.findings));
    box.innerHTML = `
      <div class="summary">
        ${kpi("Open findings", d.open, d.open ? "c-warn" : "", d.suppressed ? `${d.suppressed} suppressed by policy` : `${d.scanned} of ${d.projects} projects scanned`)}
        ${kpi("Critical + high", c.CRITICAL + c.HIGH, c.CRITICAL + c.HIGH ? "c-bad" : "")}
        ${kpi("Known exploited (KEV)", d.kev, d.kev ? "c-bad" : "", "CISA KEV catalog")}
        ${kpi("Mean time to remediate", dur(d.mttr_seconds), "", d.fixed_total ? `${d.fixed_total} fixed · ${d.fixed_7d} this week` : "nothing fixed yet")}
      </div>
      <p class="muted mb-14">Last 7 days: <b class="c-text">${d.new_7d}</b> new, <b class="c-text">${d.fixed_7d}</b> fixed (a finding counts as fixed when a later scan of its project no longer reports it).</p>
      <div class="db-grid">
        <section class="card glass" aria-labelledby="sevTitle"><h2 id="sevTitle">Open findings by severity</h2>
          ${bars(SEV.map(([k, label, cls]) => ({ label, value: c[k], cls })), sevMax)}</section>
        <section class="card glass" aria-labelledby="riskTitle"><h2 id="riskTitle">Projects at risk</h2>
          ${d.at_risk.length ? bars(d.at_risk.map((p) => ({
            label: p.name, href: `/projects?id=${p.id}`, value: p.total,
            note: `: ${SEV.filter(([k]) => p.counts[k]).map(([k, l]) => `${p.counts[k]} ${l.toLowerCase()}`).join(", ")}${p.kev ? `, ${p.kev} known exploited` : ""}`,
            parts: SEV.map(([k, , cls]) => [p.counts[k], cls]) })), riskMax)
            + `<div class="db-legend" aria-hidden="true">${SEV.map(([, l, cls]) => `<span class="${cls}"><i></i>${l}</span>`).join("")}</div>`
            : '<div class="empty">No project has open findings.</div>'}</section>
        <section class="card glass" aria-labelledby="pkgTitle"><h2 id="pkgTitle">Top vulnerable packages</h2>
          ${d.top_packages.length ? bars(d.top_packages.map((p) => ({ label: p.package, value: p.findings,
            cls: SEV.find(([k]) => k === p.worst)[2],
            note: `: worst ${p.worst.toLowerCase()}, in ${p.projects} project${p.projects === 1 ? "" : "s"}${p.kev ? `, ${p.kev} known exploited` : ""}` })), pkgMax)
            : '<div class="empty">No vulnerable packages.</div>'}</section>
        <section class="card glass db-trend" aria-labelledby="trendTitle"><h2 id="trendTitle">Open findings over time</h2>${trendChart(d.trend)}</section>
      </div>`;
    window.ppCss(box);
  }

  window.ppReady.then(() => window.ppApi("/api/dashboard")).then(render).catch((e) => {
    box.innerHTML = `<div class="card glass empty">Could not load the dashboard: ${esc(e.message)}</div>`;
  });
})();
