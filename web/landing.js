// Landing page: parallax, live counts from this server's database, real model names, try-it form.
(() => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---------- parallax: letters drift on scroll ----------
  const word = document.getElementById("word");
  if (!reduced) addEventListener("scroll", () => {
    const y = scrollY; if (y > innerHeight) return;
    word.style.transform = `translateY(calc(-46% + ${y * .35}px)) scale(${1 + y / 4000})`;
  }, { passive: true });

  // ---------- live stats: projects, scans and open findings stored on this server ----------
  fetch("/api/stats").then((r) => (r.ok ? r.json() : null)).catch(() => null).then((s) => {
    if (!s) return;
    const el = document.getElementById("stats");
    if (!s.projects) {
      el.innerHTML = '<div class="stats-note">No projects on this server yet, so there is nothing to count. <a href="/projects">Add the first one</a>.</div>';
    } else {
      const stats = [[s.projects, "project" + (s.projects === 1 ? "" : "s")], [s.scans, "completed scan" + (s.scans === 1 ? "" : "s")],
        [s.open_findings, "open finding" + (s.open_findings === 1 ? "" : "s")]];
      el.innerHTML = stats.map(([n, label]) => `<div><b>${n}</b><span>${label}</span></div>`).join("") +
        '<div class="stats-note">Counted live from this server\'s database. Open findings come from each project\'s latest scan.</div>';
      el.style.setProperty("--n", stats.length);
    }
    el.hidden = false;
  });

  // ---------- tier cards: the model each tier is configured with ----------
  window.ppHealth.then((h) => {
    const models = (h && h.models) || {};
    document.querySelectorAll(".ed-model[data-tier]").forEach((p) => {
      const id = models[p.dataset.tier];
      p.textContent = id ? `Model: ${id}` : "Model: picked from the provider's catalog at run time";
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
