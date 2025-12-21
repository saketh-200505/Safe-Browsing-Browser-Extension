// ============================================
// Sandbox File Viewer — External Script Version
// Works with Flask API at http://192.168.1.114:8080
// ============================================

console.log("📡 Sandbox viewer starting...");

const qs = new URLSearchParams(location.search);
const server = qs.get("server");
const path = atob(qs.get("path"));

const status = document.getElementById("status");
const meta = document.getElementById("meta");
const frame = document.getElementById("frame");
const downloadBtn = document.getElementById("downloadBtn");
const closeBtn = document.getElementById("closeBtn");

let currentURL = null;
let currentName = "download";

(async () => {
  try {
    if (!server || !path) throw new Error("Missing server or file path parameter.");

    console.log("📤 Requesting file from:", server, "path:", path);
    const resp = await fetch(`${server}/view_file`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });

    const data = await resp.json();
    console.log("📥 Server response:", data);

    if (!resp.ok || !data.ok) throw new Error(data.error || "Failed to load file.");

    const type = data.type;
    const mime = data.mime || "";
    currentName = path.split("/").pop() || "download";
    meta.textContent = `Name: ${currentName} • Type: ${mime || "unknown"}`;

    if (type === "text") {
      frame.srcdoc = `<pre style="white-space:pre-wrap;padding:1em;font-family:monospace;">${escapeHtml(
        data.content || ""
      )}</pre>`;
      status.textContent = "📄 Text file loaded ✅";
      currentURL = URL.createObjectURL(new Blob([data.content || ""], { type: mime }));
    } else if (type === "html") {
      frame.srcdoc = data.content || "<em>No content</em>";
      status.textContent = "🌐 HTML loaded ✅";
      currentURL = URL.createObjectURL(new Blob([data.content || ""], { type: "text/html" }));
    } else if (type === "pdf") {
      currentURL = `data:${mime};base64,${data.content}`;
      frame.srcdoc = `<embed src="${currentURL}" width="100%" height="100%">`;
      status.textContent = "📄 PDF loaded ✅";
    } else if (type === "image") {
      currentURL = `data:${mime};base64,${data.content}`;
      frame.srcdoc = `<img src="${currentURL}" style="max-width:100%;display:block;margin:auto;">`;
      status.textContent = "🖼️ Image loaded ✅";
    } else if (type === "audio") {
      currentURL = `data:${mime};base64,${data.content}`;
      frame.srcdoc = `<audio controls src="${currentURL}" style="width:100%;margin-top:1rem;"></audio>`;
      status.textContent = "🎵 Audio loaded ✅";
    } else if (type === "video") {
      currentURL = `data:${mime};base64,${data.content}`;
      frame.srcdoc = `<video controls src="${currentURL}" style="width:100%;height:100%;"></video>`;
      status.textContent = "🎬 Video loaded ✅";
    } else if (type === "office") {
      // Office files — Google Docs viewer fallback
      const gviewUrl = `https://docs.google.com/gview?url=${encodeURIComponent(
        `${server}/uploads/${path.split("/").slice(-2).join("/")}`
      )}&embedded=true`;
      frame.src = gviewUrl;
      status.textContent = "📘 Office file preview (Google Docs) ✅";
    } else {
      frame.srcdoc = `<p style="text-align:center;margin-top:2em;">⚙️ ${
        escapeHtml(data.message || "Unsupported file type")
      }</p>`;
      status.textContent = "Unsupported file type ⚙️";
      currentURL = URL.createObjectURL(new Blob([data.message || ""], { type: "text/plain" }));
    }

    // Download button
    downloadBtn.onclick = () => {
      if (!currentURL) return;
      const a = document.createElement("a");
      a.href = currentURL;
      a.download = currentName;
      a.click();
    };

    // Close button
    closeBtn.onclick = () => {
      if (currentURL) URL.revokeObjectURL(currentURL);
      window.close();
    };

    window.addEventListener("beforeunload", () => {
      if (currentURL) URL.revokeObjectURL(currentURL);
    });

  } catch (err) {
    console.error("❌ Viewer error:", err);
    status.textContent = "❌ " + err.message;
    frame.srcdoc = `<p style="text-align:center;margin-top:2em;color:red;">${escapeHtml(
      err.message
    )}</p>`;
  }
})();

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[m]));
}
