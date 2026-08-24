document.querySelectorAll("[data-open-dialog]").forEach((button) => {
  button.addEventListener("click", () => {
    document.getElementById(button.dataset.openDialog)?.showModal();
  });
});

document.querySelectorAll("[data-close-dialog]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog")?.close());
});

document.querySelectorAll("[data-dismiss]").forEach((button) => {
  button.addEventListener("click", () => button.parentElement?.remove());
});

document.querySelectorAll("[data-autosubmit]").forEach((field) => {
  field.addEventListener("change", () => field.form?.requestSubmit());
});

document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});
