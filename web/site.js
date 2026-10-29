// Shared chrome for every page: nav, theme toggle, live service pills, scroll reveal, card spotlight.
(() => {
  const PAGES = [["/", "Home"], ["/console", "Console"], ["/runs", "Runs"], ["/org", "Org scan"], ["/how", "How it works"]];
  const path = location.pathname.replace(/\/$/, "") || "/";
  const here = path === "/app" ? "/console" : path;

  const bar = document.querySelector(".topbar");
  if (bar) {
    bar.innerHTML = `
      <a class="brand" href="/">
        <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)"/><path d="m11 16 3.5 3.5L21.5 12" stroke="var(--bg)" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <div><b>Patch<span class="g">Pilot</span></b><small>autonomous security upgrades</small></div>
      </a>
      <nav class="nav" id="nav">${PAGES.map(([h, t]) => `<a href="${h}" class="${h === here ? "on" : ""}">${t}</a>`).join("")}</nav>
      <div class="pills" id="pills"></div>
      <button class="icon-btn menu-btn" id="menu" aria-label="Menu">☰</button>
      <button class="icon-btn" id="theme" title="Toggle theme" aria-label="Toggle theme">◐</button>`;
    document.getElementById("menu").onclick = () => document.getElementById("nav").classList.toggle("open");
  }

  try { const t = localStorage.getItem("pp-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
  const themeBtn = document.getElementById("theme");
  if (themeBtn) themeBtn.onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    const next = cur === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("pp-theme", next); } catch {}
  };

  window.ppHealth = fetch("/api/health").then((r) => r.json()).catch(() => ({}));
  window.ppHealth.then((h) => {
    const el = document.getElementById("pills");
    if (el) el.innerHTML = [[h.provider || "LLM", h.nebius], ["Tavily", h.tavily], ["GitHub PRs", h.github]]
      .map(([n, on]) => `<span class="pill ${on ? "on" : ""}"><i></i>${n}</span>`).join("");
  });

  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: .15 });
  const watch = () => document.querySelectorAll(".rv:not(.in), .tcard:not(.in)").forEach((el) => io.observe(el));
  watch(); window.ppReveal = watch;

  document.addEventListener("pointermove", (e) => {
    const c = e.target.closest?.(".spot");
    if (!c) return;
    const r = c.getBoundingClientRect();
    c.style.setProperty("--mx", e.clientX - r.left + "px"); c.style.setProperty("--my", e.clientY - r.top + "px");
  });
})();
