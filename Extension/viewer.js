// viewer.js — Enhanced Disposable Link Opener (Integrated with Sandbox API)

const SERVER = "http://192.168.1.118:8080"; // your sandbox backend
const urlField = document.getElementById("dloUrl");
const btnAnalyze = document.getElementById("dloAnalyze");
const btnOpen = document.getElementById("dloOpen");
const result = document.getElementById("dloResult");
const dloIframe = document.getElementById("dloIframe");
const dloFrame = document.getElementById("dloFrame");

function show(msg, color = "#333") {
  result.innerHTML = msg;
  result.style.color = color;
}

// Helper: check if sandbox API is reachable
async function sandboxAvailable() {
  try {
    const res = await fetch(`${SERVER}/cleanup`, { method: "POST" });
    return res.ok;
  } catch {
    return false;
  }
}

// -----------------------------
// Analyze Button
// -----------------------------
btnAnalyze.addEventListener("click", async () => {
  const url = urlField.value.trim();
  if (!url) return show("⚠️ Enter a URL", "#e11d48");

  try {
    const res = await window.LocalAnalyzer.analyzeUrl(url);
    const summary = `Score ${res.score}/100 — ${res.summary}`;
    const reasons = res.reasons.join("<br/>");
    show(`${summary}<br/><small>${reasons}</small>`, "#2563eb");
  } catch (err) {
    console.error(err);
    show("❌ Error analyzing URL", "#e11d48");
  }
});

// -----------------------------
// Open Button
// -----------------------------
btnOpen.addEventListener("click", async () => {
  const url = urlField.value.trim();
  if (!url) return show("⚠️ Enter a URL", "#e11d48");

  show("🔄 Connecting to sandbox...", "#666");

  const apiOk = await sandboxAvailable();

  // ✅ Use Flask backend if available
  if (apiOk) {
    try {
      show("🧠 Rendering via secure sandbox API...");
      const res = await fetch(`${SERVER}/render`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();

      if (!data.ok) throw new Error(data.error);

      // Display sanitized HTML
      dloFrame.srcdoc = data.html;
      dloIframe.style.display = "block";
      show("✅ Rendered in sandbox environment (scripts removed)", "#16a34a");

      // Optional: add screenshot thumbnail
      if (data.screenshot) {
        const img = document.createElement("img");
        img.src = `data:image/png;base64,${data.screenshot}`;
        img.style.maxWidth = "200px";
        img.style.border = "1px solid #ccc";
        img.style.marginTop = "10px";
        result.appendChild(img);
      }
    } catch (err) {
      console.error("Backend sandbox error:", err);
      show("⚠️ Sandbox API error. Falling back to browser fetch...", "#d97706");
      fallbackLocal(url);
    }
  } else {
    // 🚫 Backend offline → fallback mode
    show("🌐 Sandbox API unavailable. Using local fetch...", "#d97706");
    fallbackLocal(url);
  }
});

// -----------------------------
// Fallback: Browser fetch + sanitize
// -----------------------------
async function fallbackLocal(url) {
  try {
    const resp = await fetch(url, { mode: "cors" });
    const html = await resp.text();

    const cleaned = LocalAnalyzer.stripScriptsAndHandlers(html);

    dloFrame.srcdoc = cleaned;
    dloIframe.style.display = "block";
    show("✅ Opened in strict sandbox (client sanitized)", "#16a34a");
  } catch (err) {
    console.error(err);
    show("❌ Blocked by CORS — opening plain tab...", "#e11d48");
    window.open(url, "_blank");
  }
}
