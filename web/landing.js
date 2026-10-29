// Landing page: parallax, live proof stats, scripted terminal, try-it form.
(() => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---------- parallax: letters drift on scroll ----------
  const word = document.getElementById("word");
  if (!reduced) addEventListener("scroll", () => {
    const y = scrollY; if (y > innerHeight) return;
    word.style.transform = `translateY(calc(-46% + ${y * .35}px)) scale(${1 + y / 4000})`;
  }, { passive: true });

  // ---------- proof stats: computed from real recorded runs only ----------
  (async () => {
    const get = (u) => fetch(u).then((r) => (r.ok ? r.json() : [])).catch(() => []);
    const [bench, runs] = await Promise.all([get("/api/bench"), get("/api/runs")]);
    const latest = new Map();
    (Array.isArray(runs) ? runs : []).forEach((r) => { if (r.ok === true && !latest.has(r.repo)) latest.set(r.repo, r.id); });
    (Array.isArray(bench) ? bench : []).forEach((r) => { if (r.ok && r.run && !latest.has(r.repo)) latest.set(r.repo, r.run); });
    const evs = await Promise.all([...latest.values()].map((id) => fetch(`/api/runs/${encodeURIComponent(id)}/events`).then((r) => (r.ok ? r.text() : "")).catch(() => "")
      .then((t) => t.split(/\r?\n/).filter((l) => l.startsWith("data: ")).map((l) => { try { return JSON.parse(l.slice(6)); } catch { return null; } }).filter(Boolean))));
    let closed = 0, blocked = 0, total = 0, sawRt = false; const trusts = [];
    evs.forEach((list) => list.forEach((e) => {
      if (e.type === "exploit" && e.stage === "after" && e.closed) closed++;
      if (e.type === "redteam" && e.stage === "after" && Array.isArray(e.rows)) { sawRt = true; total += e.rows.length; blocked += e.rows.length - (e.open || 0); }
      if (e.type === "ledger" && typeof e.trust === "number") trusts.push(e.trust);
    }));
    const stats = [];
    if (latest.size) stats.push([latest.size, "", "repos secured, tests green"]);
    if (closed) stats.push([closed, "", "exploits proven closed"]);
    if (sawRt && total) stats.push([blocked, `/${total}`, "attack variants blocked"]);
    if (trusts.length) stats.push([Math.round(trusts.reduce((a, b) => a + b, 0) / trusts.length), "/100", "avg certificate trust"]);
    if (!stats.length) return;
    const el = document.getElementById("stats");
    el.innerHTML = stats.map(([n, suf, label]) => `<div><b>${n}<small>${suf}</small></b><span>${label}</span></div>`).join("") +
      `<div class="stats-note">Computed live from ${latest.size} recorded run${latest.size === 1 ? "" : "s"} on this server (latest successful run per target).</div>`;
    el.style.setProperty("--n", stats.length);
    el.hidden = false;
  })();

  // ---------- scripted terminal demo (illustrative, not live data) ----------
  const L = [
    ['<span class="d">$</span> <span class="k">patchpilot</span> run case:authsvc', 0],
    ['<span class="d">▸</span> scan · OSV.dev', 500],
    ['  <span class="b">HIGH</span>     CVE-2022-29217  PyJWT 1.7.1', 250],
    ['  <span class="b">MODERATE</span> CVE-2023-32681  requests 2.25.1', 200],
    ['<span class="b">threat clock</span> › CVE-2022-29217 public for 4+ years, exploit published', 500],
    ['<span class="n">nano</span>  › triage advisories … <span class="g">✓</span>', 600],
    ['<span class="t">tavily</span> › "PyJWT 2.0 migration guide"', 500],
    ['<span class="s">super</span> › plan PyJWT 1.7.1 → 2.x <span class="t">[breaking]</span>', 600],
    ['<span class="s">drift radar</span> › predicts 2 call-sites break: jwt.decode(), token.decode()', 600],
    ['<span class="b">exploit</span> › key-confusion attack WORKS on old pins', 500],
    ['<span class="d">pytest</span> › upgrade: <span class="b">FAIL</span>', 700],
    ['<span class="s">super</span> › patch #1: add algorithms=[…] to decode()', 600],
    ['<span class="d">pytest</span> › attempt 1: <span class="b">FAIL</span>', 700],
    ['<span class="u">ultra</span> › escalate: bytes/str token handling', 600],
    ['<span class="d">pytest</span> › attempt 2: <span class="g">PASS</span>', 700],
    ['<span class="u">red team</span> › after fix: <span class="g">7/8 variants blocked</span>', 600],
    ['<span class="g">exploit</span> › proven closed', 400],
    ['<span class="g">certificate</span> › trust 93 · sha256 9f2c…e41a', 500],
    ['<span class="g">✔ secured</span> · PR ready', 400],
  ];
  const pre = document.getElementById("typed");
  let started = false;
  new IntersectionObserver(([e]) => { if (e.isIntersecting && !started) { started = true; play(); } }, { threshold: .3 }).observe(pre);
  async function play() {
    for (;;) {
      pre.innerHTML = "";
      for (const [html, wait] of L) { await new Promise((r) => setTimeout(r, reduced ? 0 : wait)); pre.insertAdjacentHTML("beforeend", html + "\n"); }
      pre.insertAdjacentHTML("beforeend", '<span class="caret" aria-hidden="true"></span>');
      if (reduced) return;
      await new Promise((r) => setTimeout(r, 4500));
    }
  }

  // ---------- "Try it" form: hand the repo URL to the console ----------
  const tryForm = document.getElementById("tryForm");
  if (tryForm) tryForm.addEventListener("submit", (e) => {
    e.preventDefault();
    let v = document.getElementById("tryRepo").value.trim();
    if (v && !/^https?:\/\//i.test(v)) v = "https://" + v.replace(/^\/+/, "");
    location.href = "/console" + (v ? "?repo=" + encodeURIComponent(v) : "");
  });
})();
