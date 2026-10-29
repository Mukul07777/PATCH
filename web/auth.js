// Sign-in and first-run setup (both pages share this form handler).
(() => {
  const form = document.getElementById("authForm"), err = document.getElementById("authErr"), btn = document.getElementById("authBtn");
  const setup = form.dataset.mode === "setup";
  const next = () => { const n = new URLSearchParams(location.search).get("next") || "/dashboard"; return /^\/(?!\/)/.test(n) ? n : "/dashboard"; };
  const fail = (m) => { err.textContent = m; err.hidden = !m; };
  window.ppAuth.then((a) => {
    if (setup && !a.setup_needed) location.replace("/login");
    else if (a.user && a.user.via === "session") location.replace(next());
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault(); fail("");
    const v = (id) => (document.getElementById(id)?.value || "").trim();
    const body = { email: v("email"), password: document.getElementById("password").value };
    if (!body.email || !body.password) return fail("Enter your email and password.");
    if (setup) {
      if (body.password.length < 10) return fail("Use a password of at least 10 characters.");
      body.name = v("name");
    }
    const label = btn.textContent; btn.disabled = true; btn.textContent = setup ? "Creating…" : "Signing in…";
    try {
      await window.ppApi(setup ? "/api/auth/setup" : "/api/auth/login", { method: "POST", body: JSON.stringify(body), noRedirect: true });
      location.href = setup ? "/settings" : next();
    } catch (x) { fail(x.message); btn.disabled = false; btn.textContent = label; }
  });
})();
