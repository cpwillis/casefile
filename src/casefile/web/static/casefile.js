// The only JavaScript in casefile. Filtering links; nothing else needs it.
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
