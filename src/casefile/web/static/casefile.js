// Every handler is delegated, so panels htmx swaps in later are covered without rebinding.
document.addEventListener("input", (event) => {
  const input = event.target.closest(".filter");
  if (!input) return;
  const list = document.getElementById(input.dataset.filters);
  if (!list) return;
  const needle = input.value.trim().toLowerCase();
  let shown = 0;
  for (const item of list.children) {
    item.hidden = needle !== "" && !item.textContent.toLowerCase().includes(needle);
    if (!item.hidden) shown++;
  }
  let status = input.parentElement.querySelector(".filter-status");
  if (!status) {
    status = document.createElement("span");
    status.className = "filter-status muted";
    status.setAttribute("role", "status");
    input.insertAdjacentElement("afterend", status);
  }
  status.textContent = needle === "" ? "" : shown ? `${shown} of ${list.children.length}` : "nothing matches";
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
  const tag = (event.target.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select" || event.target.isContentEditable) return;
  const box = document.getElementById("target");
  if (!box) return;
  event.preventDefault();
  box.focus();
  box.select();
});

document.addEventListener("click", (event) => {
  const button = event.target.closest(".copy");
  if (!button || !navigator.clipboard) return;
  navigator.clipboard.writeText(button.dataset.copy || "").then(() => {
    const original = button.textContent;
    button.textContent = "copied";
    setTimeout(() => { button.textContent = original; }, 1200);
  });
});

// htmx swaps nothing when a request never completes, so a blocked panel just sits there looking idle.
function panelFailed(event, reason) {
  const panel = event.detail.elt.closest(".panel");
  if (!panel) return;
  panel.dataset.state = "error";
  const state = panel.querySelector(".panel-state");
  if (state) {
    state.textContent = "failed";
    state.className = "panel-state state-error";
  }
  if (!panel.querySelector(".panel-detail")) {
    const note = document.createElement("p");
    note.className = "panel-detail";
    note.textContent = reason;
    panel.appendChild(note);
  }
}

document.addEventListener("htmx:sendError", (event) =>
  panelFailed(
    event,
    "this request never reached casefile. If the server is still running, a content blocker or " +
      "browser extension is the usual cause: allow 127.0.0.1, or check its request log to see what it matched.",
  ),
);
document.addEventListener("htmx:timeout", (event) => panelFailed(event, "this request timed out."));

document.addEventListener("htmx:afterSwap", (event) => {
  // With outerHTML the swapped-out target is detached, so focusing it does nothing; look the id back up.
  const id = event.detail.target?.id;
  if (!id) return;
  const panel = document.getElementById(id);
  if (panel && panel.classList.contains("panel")) panel.focus({ preventScroll: true });
});



// A rail link can target a heading inside a folded <details>, so open its ancestors before scrolling.
function revealHashTarget() {
  const id = decodeURIComponent(location.hash.slice(1));
  if (!id) return;
  const target = document.getElementById(id);
  if (!target) return;
  for (let el = target; el; el = el.parentElement) {
    if (el.tagName === "DETAILS") el.open = true;
  }
  target.scrollIntoView();
}
window.addEventListener("hashchange", revealHashTarget);
document.addEventListener("DOMContentLoaded", revealHashTarget);
