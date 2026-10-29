// Shared chrome for every page: nav, footer, theme toggle, live service pills, scroll reveal, card spotlight.
const ppEsc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
window.ppEsc = ppEsc;
// Markdown link -> <a> only for http(s) URLs; anything else (javascript:, data:, relative) stays plain text.
// `label` and `url` must already be HTML-escaped.
window.ppMdLink = (label, url) => /^https?:\/\//i.test(url) ? `<a href="${url}" target="_blank" rel="noopener">${label}</a>` : `${label} (${url})`;

// Every API call goes through ppApi: JSON in/out, the session cookie, and the X-Requested-With header the server
// requires on cookie-authenticated writes (CSRF). Throws Error(detail) on failure; a 401 sends you to sign in.
window.ppLoginUrl = () => "/login?next=" + encodeURIComponent(location.pathname + location.search);
window.ppApi = async (url, opts = {}) => {
  const r = await fetch(url, { ...opts, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Requested-With": "patchpilot", ...(opts.headers || {}) } });
  if (r.status === 204) return null;
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && !opts.noRedirect) location.href = window.ppLoginUrl();
    const d = body.detail;
    const err = new Error(Array.isArray(d) ? d.map((x) => (x.msg || "").replace(/^Value error, /, "")).join("; ") : d || `HTTP ${r.status}`);
    err.status = r.status;
    throw err;
  }
  return body;
};
// Signed-in state: {setup_needed, public_demo, user: {id, email, name, role, via} | null}
window.ppAuth = fetch("/api/auth/state", { credentials: "same-origin" }).then((r) => r.json()).catch(() => ({}));
// Pages anyone may open; everything else needs a session (or PATCHPILOT_PUBLIC_DEMO=1 for read-only browsing).
// ppReady resolves with the auth state once this page may load its data, and never while a redirect is under way.
window.ppReady = window.ppAuth.then((a) => {
  const path = location.pathname.replace(/\/$/, "") || "/";
  const to = a.setup_needed && path !== "/setup" ? "/setup"
    : !a.setup_needed && !a.user && !a.public_demo && !["/", "/how", "/login", "/setup"].includes(path) ? window.ppLoginUrl() : null;
  if (!to) return a;
  location.replace(to);
  return new Promise(() => {});
});

// The CSP has no style-src 'unsafe-inline', so markup carries per-element custom properties as
// data-css="--k:v;..." and they are applied here through the CSSOM (allowed under CSP), including for HTML injected later.
(() => {
  const apply = (el) => {
    // Declarations split on ';' outside parentheses, so values like url(a;b) survive; a value
    // itself can't contain a bare ';' (none of ours do).
    el.getAttribute("data-css").split(/;(?![^(]*\))/).forEach((d) => {
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
  // Call right after an innerHTML assignment so styles apply before paint (the observer is the safety net).
  window.ppCss = (root) => scan(root || document.documentElement);
  new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach(scan))).observe(document.documentElement, { childList: true, subtree: true });
})();

(() => {
  const PAGES = [["/dashboard", "Dashboard"], ["/projects", "Projects"], ["/console", "Console"], ["/runs", "Runs"], ["/org", "Org scan"], ["/how", "How it works"]];
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
    window.ppAuth.then((a) => {
      const u = a.user;
      const link = (h, t) => `<a href="${h}" class="${h === here ? "on" : ""}"${h === here ? ' aria-current="page"' : ""}>${t}</a>`;
      if (u && u.via === "session") {
        nav.insertAdjacentHTML("beforeend", link("/settings", u.role === "admin" ? "Settings" : "Account")
          + `<button type="button" class="nav-btn" id="signOut" title="Signed in as ${ppEsc(u.email)}">Sign out<span class="sr-only"> ${ppEsc(u.email)}</span></button>`);
        document.getElementById("signOut").addEventListener("click", async () => {
          try { await window.ppApi("/api/auth/logout", { method: "POST" }); } catch {}
          location.href = "/login";
        });
      } else if (!u && !a.setup_needed && !["/login", "/setup"].includes(path)) {
        nav.insertAdjacentHTML("beforeend", link(window.ppLoginUrl(), "Sign in"));
      }
    });
    const setMenu = (open) => { nav.classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); };
    menu.addEventListener("click", () => setMenu(!nav.classList.contains("open")));
    nav.addEventListener("click", (e) => { if (e.target.closest("a")) setMenu(false); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && nav.classList.contains("open")) { setMenu(false); menu.focus(); }
    });
  }

  // One shared footer: any <footer data-site-foot> (or element with that attribute) gets the same links.
  document.querySelectorAll("[data-site-foot]").forEach((f) => {
    f.innerHTML = `<span>PatchPilot · <span data-mode-text>Scan mode</span> · OSV.dev · EPSS · CISA KEV · MIT licensed</span>
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
    // any [data-model-tier] element shows the model id configured for that tier (Settings, else MODEL_*)
    document.querySelectorAll("[data-model-tier]").forEach((el) => { const m = (h.models || {})[el.dataset.modelTier]; if (m) el.textContent = m; });
    // Say plainly which mode this server is in: without an LLM key it scans only, it does not fix
    const mode = h.fix_mode ? "Scan + auto-fix" : "Scan mode";
    document.querySelectorAll("[data-mode-text]").forEach((m) => { m.textContent = h.fix_mode ? `${mode} (${h.provider || "LLM"})` : `${mode} (fix mode off: no LLM key)`; });
    const el = document.getElementById("pills");
    if (el) el.innerHTML = `<span class="pill on" title="${h.fix_mode ? "Scanning and LLM fix runs are available" : "Scanning works; fix runs need an LLM API key in Settings"}"><i aria-hidden="true"></i>${mode}</span>`
      + [[h.provider || "LLM", h.nebius], ["Tavily", h.tavily], ["GitHub", h.github]].filter(([, on], i) => on || i === 0)
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
