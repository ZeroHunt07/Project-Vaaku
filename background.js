async function sendVisit(tab) {
  if (!tab || !tab.url || !tab.url.startsWith("http")) return;
  try {
    await fetch("http://127.0.0.1:8765/visit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "visit",
        url: tab.url,
        title: tab.title,
        browser: "chrome"
      })
    });
  } catch (e) {}
}

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  sendVisit(tab);
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
