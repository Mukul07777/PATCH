// Shared chrome for every page: nav, footer, theme toggle, live service pills, scroll reveal, card spotlight.
const ppEsc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
window.ppEsc = ppEsc;
// Markdown link -> <a> only for http(s) URLs; anything else (javascript:, data:, relative) stays plain text.
// `label` and `url` must already be HTML-escaped.
window.ppMdLink = (label, url) => /^https?:\/\//i.test(url) ? `<a href="${url}" target="_blank" rel="noopener">${label}</a>` : `${label} (${url})`;

// The CSP has no style-src 'unsafe-inline', so markup carries per-element custom properties as
// data-css="--k:v;..." and they are applied here through the CSSOM (allowed under CSP), including for HTML injected later.
(() => {
  const apply = (el) => {
    el.getAttribute("data-css").split(";").forEach((d) => {
      const i = d.indexOf(":");
      if (i > 0) el.style.setProperty(d.slice(0, i).trim(), d.slice(i + 1).trim());
    });
    el.removeAttribute("data-css");
  };
  const scan = (n) => {
    if (n.nodeType !== 1) return;
    if (n.hasAttribute("data-css")) apply(n);
    n.querySelectorAll("[data-css]").forEach(apply);
  };
  scan(document.documentElement);
  new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach(scan))).observe(document.documentElement, { childList: true, subtree: true });
})();

(() => {
  const PAGES = [["/", "Home"], ["/console", "Console"], ["/runs", "Runs"], ["/org", "Org scan"], ["/how", "How it works"]];
  const path = location.pathname.replace(/\/$/, "") || "/";
  const here = path === "/app" ? "/console" : path;

  const main = document.getElementById("main");
  if (main) {
    const skip = document.createElement("a");
    skip.className = "skip-link"; skip.href = "#main"; skip.textContent = "Skip to content";
    document.body.prepend(skip);
    if (!main.hasAttribute("tabindex")) main.setAttribute("tabindex", "-1");
  }

  const bar = document.querySelector(".topbar");
  if (bar) {
    bar.innerHTML = `
      <a class="brand" href="/">
        <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)"/><path d="m11 16 3.5 3.5L21.5 12" stroke="var(--bg)" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <div><b>Patch<span class="g">Pilot</span></b><small>autonomous security upgrades</small></div>
      </a>
      <nav class="nav" id="nav" aria-label="Main">${PAGES.map(([h, t]) => `<a href="${h}" class="${h === here ? "on" : ""}"${h === here ? ' aria-current="page"' : ""}>${t}</a>`).join("")}</nav>
      <div class="pills" id="pills"></div>
      <button class="icon-btn menu-btn" id="menu" type="button" aria-label="Menu" aria-controls="nav" aria-expanded="false"><span aria-hidden="true">☰</span></button>
      <button class="icon-btn" id="theme" type="button" title="Toggle theme" aria-label="Toggle theme"><span aria-hidden="true">◐</span></button>`;
    const menu = document.getElementById("menu"), nav = document.getElementById("nav");
    const setMenu = (open) => { nav.classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); };
    menu.addEventListener("click", () => setMenu(!nav.classList.contains("open")));
    nav.addEventListener("click", (e) => { if (e.target.closest("a")) setMenu(false); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && nav.classList.contains("open")) { setMenu(false); menu.focus(); }
    });
  }

  // One shared footer: any <footer data-site-foot> (or element with that attribute) gets the same links.
  document.querySelectorAll("[data-site-foot]").forEach((f) => {
    f.innerHTML = `<span>PatchPilot · NVIDIA Nemotron · OSV.dev · Tavily · MIT licensed</span>
      <nav aria-label="Footer"><span>${PAGES.map(([h, t]) => `<a href="${h}">${t}</a>`).join("")}</span></nav>`;
  });

  try { const t = localStorage.getItem("pp-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
  const themeBtn = document.getElementById("theme");
  if (themeBtn) themeBtn.addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme || "dark";
    const next = cur === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("pp-theme", next); } catch {}
  });

  window.ppHealth = fetch("/api/health").then((r) => r.json()).catch(() => ({}));
  window.ppHealth.then((h) => {
    const el = document.getElementById("pills");
    if (el) el.innerHTML = [[h.provider || "LLM", h.nebius], ["Tavily", h.tavily], ["GitHub PRs", h.github]]
      .map(([n, on]) => `<span class="pill ${on ? "on" : ""}"><i aria-hidden="true"></i>${ppEsc(n)}<span class="sr-only">${on ? " connected" : " not configured"}</span></span>`).join("");
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
