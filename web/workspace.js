// Workspace: one page, four sections (overview, projects, run history, org scan) switched by tab and URL hash.
(() => {
  const btns = [...document.querySelectorAll("[data-ws]")];
  const show = (key, focus) => {
    if (!btns.some((b) => b.dataset.ws === key)) key = "overview";
    btns.forEach((b) => {
      const on = b.dataset.ws === key;
      b.classList.toggle("active", on); b.setAttribute("aria-selected", on); b.tabIndex = on ? 0 : -1;
      document.getElementById(`ws-${b.dataset.ws}`).hidden = !on;
      if (on && focus) b.focus();
    });
  };
  btns.forEach((b, i) => {
    b.addEventListener("click", () => { history.replaceState(null, "", `${location.pathname}${location.search}#${b.dataset.ws}`); show(b.dataset.ws); });
    b.addEventListener("keydown", (e) => {
      const n = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: btns.length - 1 }[e.key];
      if (n === undefined) return;
      e.preventDefault(); btns[(n + btns.length) % btns.length].click(); btns[(n + btns.length) % btns.length].focus();
    });
  });
  const q = new URLSearchParams(location.search);
  // a project link (?id= / ?git=) always opens the Projects section
  show(q.has("id") || q.has("git") ? "projects" : location.hash.slice(1));
  window.addEventListener("hashchange", () => show(location.hash.slice(1)));
})();
