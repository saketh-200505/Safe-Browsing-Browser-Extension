// sandbox.js
(() => {
  // -------------------------------------------------
  // Block any unhandled promise rejections permanently
  // -------------------------------------------------
  window.addEventListener("unhandledrejection", e => {
    console.warn("🔇 Suppressed async rejection:", e.reason);
    e.preventDefault();
  });

  // -------------------------------------------------
  // Click handler
  // -------------------------------------------------
  document.getElementById("startBtn").addEventListener("click", async () => {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) {
      alert("⚠️ Please enter a valid URL.");
      return;
    }

    const SANDBOX_CANDIDATES = [
      "http://127.0.0.1:8080",
      "http://192.168.1.118:8080"
    ];

    const startBtn = document.getElementById("startBtn");
    startBtn.disabled = true;
    startBtn.textContent = "Loading…";

    try {
      // Try all sandbox servers in parallel
      const attempts = SANDBOX_CANDIDATES.map(async base => {
        try {
          const res = await fetch(`${base}/render`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            cache: "no-store"
          });
          if (res.ok) return { base, res };
        } catch (err) {
          console.warn(`❌ ${base} failed: ${err.message}`);
        }
        return null;
      });

      // Wait for first actual success
      const settled = await Promise.allSettled(attempts);
      const success = settled.find(r => r.status === "fulfilled" && r.value);

      if (!success) {
        alert("⚠️ Unable to reach any sandbox server. Check if it’s running.");
        return;
      }

      const { base, res } = success.value;
      console.log(`✅ Connected to sandbox at ${base}`);

      const result = await res.json().catch(() => ({}));

      if (result.ok && result.html) {
        document.getElementById("viewer").srcdoc = result.html;
        showStatus(`Connected to ${base} ✅`, "#16a34a");
      } else {
        alert("⚠️ Sandbox returned unexpected data.");
      }
    } catch (err) {
      // If anything outside of fetch fails, just log it
      console.error("Sandbox viewer error:", err);
      // do not alert here – we already loaded successfully
    } finally {
      startBtn.disabled = false;
      startBtn.textContent = "Start";
    }
  });

  // -------------------------------------------------
  // Simple bottom status bar
  // -------------------------------------------------
  function showStatus(msg, color = "#333") {
    let bar = document.getElementById("sandboxStatusBar");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "sandboxStatusBar";
      Object.assign(bar.style, {
        position: "fixed",
        bottom: "0",
        left: "0",
        width: "100%",
        padding: "6px",
        fontSize: "13px",
        textAlign: "center",
        color: "#fff",
        zIndex: "9999"
      });
      document.body.appendChild(bar);
    }
    bar.style.background = color;
    bar.textContent = msg;
  }
})();
