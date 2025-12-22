// background.js — passes the blob data to the viewer tab instead of creating URL

console.log("[Sandbox Worker] Service worker started ✅");

const sandboxFiles = new Map();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.feature === "fileViewer" && msg.cmd === "open") {
    console.log("[Sandbox Worker] Received fileViewer open:", msg.fileName, msg.mime);
    try {
      const id = crypto.randomUUID();
      // store raw data instead of blobURL
      sandboxFiles.set(id, {
        base64: msg.base64,
        mime: msg.mime || "",
        name: msg.fileName || "file"
 });

      chrome.tabs.create({
        url: chrome.runtime.getURL(`file_viewer.html?id=${id}`)
      });
      sendResponse({ ok: true, id });
    } catch (err) {
      console.error("[Sandbox Worker] open failed ❌", err);
      sendResponse({ ok: false, error: err.message });
    }
    return true;
  }

  if (msg && msg.feature === "fileViewer" && msg.cmd === "getBlob" && msg.id) {
    const entry = sandboxFiles.get(msg.id);
    if (!entry) {
      sendResponse({ ok: false, error: "Blob not found" });
      return true;
    }
    sendResponse({ ok: true, ...entry });
    return true;
  }

  if (msg && msg.feature === "fileViewer" && msg.cmd === "revoke" && msg.id) {
    sandboxFiles.delete(msg.id);
    sendResponse({ ok: true });
    return true;
  }
});
