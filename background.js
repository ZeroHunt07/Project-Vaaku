const ALLOWED_SCHEMES = ["http://", "https://", "chrome://", "edge://", "about:", "file://"];

function isAllowedUrl(url) {
  if (!url) return false;
  return ALLOWED_SCHEMES.some(scheme => url.startsWith(scheme));
}

function resolveTitle(url, title) {
  if (title && title.trim()) return title.trim();
  if (url.includes("://history")) return "Browser History";
  if (url.includes("://downloads")) return "Browser Downloads";
  if (url.includes("://settings")) return "Browser Settings";
  if (url.includes("://extensions")) return "Browser Extensions";
  return url;
}

async function sendVisit(tab) {
  if (!tab || !tab.url || !isAllowedUrl(tab.url)) return;
  const title = resolveTitle(tab.url, tab.title);
  try {
    await fetch("http://127.0.0.1:8765/visit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "visit",
        url: tab.url,
        title: title,
        browser: "chrome"
      })
    });
  } catch (e) {}
}

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    sendVisit(tab);
  } catch (e) {}
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active) {
    sendVisit(tab);
  }
});

// Receive form-submit events from content scripts
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === "form_submit") {
    fetch("http://127.0.0.1:8765/visit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "form_submit",
        url: (sender.tab && sender.tab.url) || msg.url,
        title: (sender.tab && sender.tab.title) || "",
        browser: "chrome",
        form_action: msg.action || "",
        field_names: msg.fields || []
      })
    }).catch(() => {});
  }
});

// Download audit logging
if (chrome.downloads) {
  chrome.downloads.onCreated.addListener(async (item) => {
    try {
      await fetch("http://127.0.0.1:8765/visit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind: "download",
          url: item.url || item.finalUrl || "",
          filename: item.filename || "",
          fileSize: item.fileSize || 0,
          mime: item.mime || "",
          state: item.state || "in_progress",
          browser: "chrome"
        })
      });
    } catch (e) {}
  });

  chrome.downloads.onChanged.addListener(async (delta) => {
    if (delta.state && (delta.state.current === "complete" || delta.state.current === "interrupted")) {
      try {
        const items = await chrome.downloads.search({ id: delta.id });
        if (items && items.length > 0) {
          const item = items[0];
          await fetch("http://127.0.0.1:8765/visit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              kind: "download",
              url: item.url || item.finalUrl || "",
              filename: item.filename || "",
              fileSize: item.fileSize || 0,
              mime: item.mime || "",
              state: delta.state.current,
              browser: "chrome"
            })
          });
        }
      } catch (e) {}
    }
  });
}

