// All of casefile's JavaScript: the link filter, the / shortcut and the copy buttons.
// Every handler is delegated, so panels htmx swaps in later are covered without rebinding.
document.addEventListener("input", (event) => {
  const input = event.target.closest(".filter");
  if (!input) return;
  const list = document.getElementById(input.dataset.filters);
  if (!list) return;
  const needle = input.value.trim().toLowerCase();
  for (const item of list.children) {
    item.hidden = needle !== "" && !item.textContent.toLowerCase().includes(needle);
  }
});

// "/" focuses the search box, unless you are already typing in a field.
document.addEventListener("keydown", (event) => {
  if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
  const tag = (event.target.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea" || event.target.isContentEditable) return;
  const box = document.getElementById("target");
  if (!box) return;
  event.preventDefault();
  box.focus();
  box.select();
});

// Copy a finding's value. Delegated, so it also works on panels htmx swaps in later.
document.addEventListener("click", (event) => {
  const button = event.target.closest(".copy");
  if (!button || !navigator.clipboard) return;
  navigator.clipboard.writeText(button.dataset.copy || "").then(() => {
    const original = button.textContent;
    button.textContent = "copied";
    setTimeout(() => { button.textContent = original; }, 1200);
  });
});
