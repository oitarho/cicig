document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const label = button.querySelector("[data-copy-label]");
    const original = label?.textContent ?? button.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      if (label) label.textContent = button.dataset.copied;
      else button.textContent = button.dataset.copied;
    } catch {
      const input = document.createElement("textarea");
      input.value = button.dataset.copy;
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.append(input);
      input.select();
      document.execCommand("copy");
      input.remove();
      if (label) label.textContent = button.dataset.copied;
      else button.textContent = button.dataset.copied;
    }
    window.setTimeout(() => {
      if (label) label.textContent = original;
      else button.textContent = original;
    }, 1800);
  });
});
