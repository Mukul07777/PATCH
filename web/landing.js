// Landing page: measured results from this server's database, real model names, try-it form.
(() => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---------- measured results: recorded benchmark (/api/bench) plus live counts (/api/stats) ----------
  const cell = (n, label) => `<div><b>${n}</b><span>${label}</span></div>`;
  Promise.all([
    fetch("/api/bench").then((r) => (r.ok ? r.json() : [])).catch(() => []),
    fetch("/api/auth/state").then((r) => (r.ok ? r.json() : null)).catch(() => null)
      .then((st) => (st && (st.user || st.public_demo) ? fetch("/api/stats").then((r) => (r.ok ? r.json() : null)) : null)).catch(() => null),
  ]).then(([bench, s]) => {
    const cells = [];
    if (Array.isArray(bench) && bench.length) {
      const fixed = bench.filter((r) => r.ok).length, proven = bench.filter((r) => r.proven).length;
      cells.push(cell(`${fixed}/${bench.length}`, "recorded cases fixed with tests green"), cell(`${proven}/${bench.length}`, "with the exploit proven closed"));
    }
    if (s && s.projects) cells.push(cell(s.projects, "project" + (s.projects === 1 ? "" : "s") + " on this server"));
    if (!cells.length) return;
    const el = document.getElementById("stats");
    el.innerHTML = cells.join("") + '<div class="stats-note">Counted from the recorded benchmark runs and the server database, not hardcoded.</div>';
    el.style.setProperty("--n", cells.length); el.hidden = false;
  });

  // ---------- tier cards: the model each tier is configured with ----------
  window.ppHealth.then((h) => {
    const models = (h && h.models) || {};
    document.querySelectorAll(".ed-model[data-tier]").forEach((p) => {
      const id = models[p.dataset.tier];
      p.textContent = id || "picked from the catalog at run time";
    });
  });

  // ---------- "Try it" form: hand the repo URL to the projects page ----------
  const tryForm = document.getElementById("tryForm");
  if (tryForm) tryForm.addEventListener("submit", (e) => {
    e.preventDefault();
    let v = document.getElementById("tryRepo").value.trim();
    if (v && !/^https?:\/\//i.test(v)) v = "https://" + v.replace(/^\/+/, "");
    location.href = "/projects" + (v ? "?git=" + encodeURIComponent(v) : "");
  });
})();
