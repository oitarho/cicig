document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      button.textContent = button.dataset.copied;
    } catch {
      const input = document.createElement("textarea");
      input.value = button.dataset.copy;
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.append(input);
      input.select();
      document.execCommand("copy");
      input.remove();
      button.textContent = button.dataset.copied;
    }
    window.setTimeout(() => { button.textContent = original; }, 1800);
  });
});
