// Report form submissions — field NAMES only, never values.
document.addEventListener("submit", (e) => {
  try {
    const form = e.target;
    if (!form || form.tagName !== "FORM") return;
    const fields = Array.from(form.elements)
      .filter(el => el.name)
      .map(el => el.name)
      .slice(0, 50);
    chrome.runtime.sendMessage({
      type: "form_submit",
      url: location.href,
      action: form.action || "",
      fields: fields
    });
  } catch (err) {}
}, true);
