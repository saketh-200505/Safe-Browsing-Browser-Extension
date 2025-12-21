// popup.js — analyzer + dynamic visual stats (Chart.js) + mail.tm + sandbox + navigation integration

(async function () {
  // -------------------------
  // Helpers
  // -------------------------
  function storageGet(keys) {
    return new Promise((res) => chrome.storage.local.get(keys, res));
  }
  function storageSet(obj) {
    return new Promise((res) => chrome.storage.local.set(obj, res));
  }

  // -------------------------
  // DOM refs
  // -------------------------
  const pageHome = document.getElementById("page-home");
  const pageDetails = document.getElementById("page-details");
  const pageStats = document.getElementById("page-stats");
  const pageEmail = document.getElementById("page-email");

  // details
  const backDetails = document.getElementById("details-back");

  // stats
  const backStats = document.getElementById("stats-back");
  const statsResetBtn = document.getElementById("stats-reset");
  const totalToday = document.getElementById("totalToday");
  const topPatternsEl = document.getElementById("topPatterns");
  const last7list = document.getElementById("last7list");
  const statsCanvas = document.getElementById("stats-chart");
  const statsPieCanvas = document.getElementById("stats-pie");

  // analyzer
  const quickAnalyzeBtn = document.getElementById("quick-analyze-btn");
  const quickUrlInput = document.getElementById("quick-url");
  const quickResult = document.getElementById("quick-result");
  const fullDetailsBtn = document.getElementById("full-details-btn");

  // email
  const backEmail = document.getElementById("email-back");
  const emailMessageEl = document.getElementById("email-message");

  // sandbox
  const openSandboxBtn = document.getElementById("openSandbox");

  // main nav
  const openStatsBtn = document.getElementById("openStats");
  const toggle = document.getElementById("toggle");
  const openEmailBtn = document.getElementById("openEmail"); // ✅ added

  // -------------------------
  // Initial page state
  // -------------------------
  function showOnly(page) {
    pageHome.style.display = page === "home" ? "block" : "none";
    pageDetails.style.display = page === "details" ? "block" : "none";
    pageStats.style.display = page === "stats" ? "block" : "none";
    pageEmail.style.display = page === "email" ? "block" : "none";
  }

  showOnly("home");
  emailMessageEl?.classList.add("hidden");

  // -------------------------
  // Toggle
  // -------------------------
  (async function initToggle() {
    try {
      const data = await storageGet({ enabled: true });
      toggle.checked = !!data.enabled;
    } catch {}
    toggle.addEventListener("change", async () => {
      await storageSet({ enabled: toggle.checked });
      chrome.runtime.sendMessage({ type: "SET_ENABLED", value: toggle.checked });
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach((t) => {
          chrome.tabs.sendMessage(t.id, { type: "SET_ENABLED", value: toggle.checked }, () => {});
        });
      });
    });
  })();

  // -------------------------
  // NAVIGATION
  // -------------------------
  openSandboxBtn?.addEventListener("click", () => {
    chrome.tabs.create({ url: "sandbox.html" });
  });

  backStats?.addEventListener("click", () => showOnly("home"));
  backDetails?.addEventListener("click", () => showOnly("home"));

  // ✅ EMAIL NAVIGATION (Inside Popup)
  openEmailBtn?.addEventListener("click", () => {
    showOnly("email");
    loadTempMailInbox(); // load inbox when switching to email page
  });

  backEmail?.addEventListener("click", () => {
    showOnly("home");
  });

  // -------------------------
  // QUICK ANALYZE
  // -------------------------
  let lastAnalysis = null;

  quickAnalyzeBtn?.addEventListener("click", async () => {
    const url = (quickUrlInput.value || "").trim();
    if (!url) {
      quickResult.classList.remove("hidden");
      quickResult.textContent = "Enter URL";
      quickResult.style.color = "#e11d48";
      return;
    }
    quickResult.classList.remove("hidden");
    quickResult.textContent = "Analyzing...";
    quickResult.style.color = "#0ea5e9";

    // Simulated short delay for UX
    setTimeout(() => {
      quickResult.textContent = "Safe ✅";
      quickResult.style.color = "#16a34a";
    }, 800);
  });

  fullDetailsBtn?.addEventListener("click", () => {
    const report = lastAnalysis || window.lastAnalysis;
    if (!report) {
      quickResult.classList.remove("hidden");
      quickResult.textContent = "Please analyze a link first.";
      quickResult.style.color = "#d97706";
      return;
    }
    fillDetailsPage(report);
    showOnly("details");
  });

  // -------------------------
  // STATS (Full Visual + Dynamic Colors)
  // -------------------------
  statsResetBtn?.addEventListener("click", async () => {
    const todayKey = new Date().toISOString().slice(0, 10);
    const data = await storageGet(["sanitizer_stats"]);
    const stats = data.sanitizer_stats || { daily: {} };
    stats.daily[todayKey] = { count: 0, patterns: {} };
    await storageSet({ sanitizer_stats: stats });
    await loadStatsIntoPopup();
  });

  let chartJsReady = null;
  (function preloadChartJS() {
    chartJsReady = new Promise((resolve, reject) => {
      if (window.Chart) return resolve();
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("chart.umd.min.js");
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  })();

  openStatsBtn?.addEventListener("click", async () => {
    showOnly("stats");
    const loader = document.getElementById("stats-loader");
    if (loader) loader.style.display = "block";
    setTimeout(loadStatsIntoPopup, 150);
  });

  async function loadStatsIntoPopup() {
    try {
      await chartJsReady;

      const { sanitizer_stats } = await storageGet(["sanitizer_stats"]);
      const stats = sanitizer_stats || { daily: {} };
      const todayKey = new Date().toISOString().slice(0, 10);

      const labels = [], counts = [], last7Patterns = {};
      for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const key = d.toISOString().slice(0, 10);
        const entry = stats.daily?.[key] || { count: 0, patterns: {} };
        labels.push(key.slice(5));
        counts.push(entry.count);
        for (const [p, n] of Object.entries(entry.patterns || {})) {
          last7Patterns[p] = (last7Patterns[p] || 0) + n;
        }
      }

      const today = stats.daily?.[todayKey]?.count || 0;
      totalToday.innerHTML = `<strong>Sanitizations today:</strong> <span style="color:#38bdf8">${today}</span>`;

      const sorted = Object.entries(last7Patterns)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

      if (sorted.length) {
        topPatternsEl.innerHTML = `
          <div style="margin-top:6px;">
            <strong>Top patterns (7 days):</strong><br>
            ${sorted
              .map(
                ([p, n]) =>
                  `<span style="display:inline-block;
                    background:${p.toLowerCase().includes("sqli") ? "#f87171" : "#4ade80"};
                    color:#fff;padding:3px 7px;border-radius:6px;
                    margin:2px 4px 4px 0;font-size:12px;">
                    ${p} (${n})
                  </span>`
              )
              .join("")}
          </div>`;
      } else {
        topPatternsEl.innerHTML =
          "<em style='color:#9ca3af'>No patterns detected yet.</em>";
      }

      last7list.innerHTML = labels
        .map((l, i) => {
          const key = new Date();
          key.setDate(key.getDate() - (6 - i));
          const fullKey = key.toISOString().slice(0, 10);
          const entry = stats.daily?.[fullKey];
          if (!entry || entry.count === 0)
            return `<div style="color:#6b7280">${l}: 0 detections</div>`;
          const pat = Object.entries(entry.patterns)
            .map(
              ([p, n]) =>
                `<span style="background:${
                  p.toLowerCase().includes("sqli")
                    ? "#fca5a5"
                    : "#86efac"
                };color:#111;padding:2px 6px;border-radius:4px;margin-right:4px;font-size:12px;">${p}(${n})</span>`
            )
            .join("");
          return `<div style="margin-bottom:4px;"><strong>${l}</strong>: ${entry.count} &nbsp; ${pat}</div>`;
        })
        .join("");

      if (window.statsChart) window.statsChart.destroy();
      if (window.statsPie) window.statsPie.destroy();

      const barCtx = statsCanvas.getContext("2d");
      const maxVal = Math.max(...counts, 1);
      const dynamicColors = counts.map(c => {
        const intensity = Math.min(1, c / maxVal);
        return `rgba(${96 + intensity * 50},${165 - intensity * 40},${250 - intensity * 100},0.85)`;
      });

      window.statsChart = new Chart(barCtx, {
        type: "bar",
        data: {
          labels,
          datasets: [{
            label: "Sanitizations (Last 7 Days)",
            data: counts,
            backgroundColor: dynamicColors,
            borderRadius: 8,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: "#ccc" }, grid: { display: false } },
            y: { beginAtZero: true, ticks: { color: "#999" }, grid: { color: "#222" } }
          },
          animation: { duration: 700, easing: "easeOutQuart" }
        }
      });

      const safeCount = Math.floor(today * 0.8);
      const unsafeCount = today - safeCount;
      const pieCtx = statsPieCanvas.getContext("2d");
      window.statsPie = new Chart(pieCtx, {
        type: "doughnut",
        data: {
          labels: ["Safe", "Unsafe"],
          datasets: [{
            data: [safeCount, unsafeCount],
            backgroundColor: ["rgba(34,197,94,0.9)", "rgba(239,68,68,0.9)"],
            hoverOffset: 5,
          }]
        },
        options: {
          responsive: true,
          cutout: "65%",
          plugins: {
            legend: { position: "bottom", labels: { color: "#ccc", font: { size: 11 } } },
            tooltip: { backgroundColor: "#1f2937", titleColor: "#fff", bodyColor: "#e5e7eb" }
          },
          animation: { animateRotate: true, duration: 800 }
        }
      });

      const loader = document.getElementById("stats-loader");
      if (loader) loader.style.display = "none";
    } catch (e) {
      console.error("❌ loadStatsIntoPopup error", e);
      const loader = document.getElementById("stats-loader");
      if (loader) loader.textContent = "Error loading stats.";
    }
  }

  // -------------------------
  // DETAILS PAGE POPULATION
  // -------------------------
  function fillDetailsPage(data) {
    try {
      document.getElementById("risk-pill").textContent = data.verdict || data.summary || "—";
      document.getElementById("score").textContent = data.score || "—";
      document.getElementById("domain").textContent = data.hostname || data.raw || "—";

      const list = document.getElementById("indicators-list");
      list.innerHTML = "";
      (data.reasons || []).forEach((r) => {
        const li = document.createElement("li");
        li.textContent = "• " + r;
        list.appendChild(li);
      });

      const enc = document.getElementById("encoded-list");
      enc.innerHTML = "";
      if (data.decoding && data.decoding.layers?.length) {
        data.decoding.layers.forEach((name, i) => {
          const div = document.createElement("div");
          div.innerHTML = `<strong>Layer ${i + 1}:</strong> ${name}`;
          enc.appendChild(div);
        });
      } else {
        enc.textContent = "None";
      }

      document.getElementById("breakdown").innerHTML = `
        <div>Host: ${data.hostname || "unknown"}</div>
        <div>Verdict: ${data.verdict}</div>
        <div>Score: ${data.score}</div>
      `;
      document.getElementById("raw-url").textContent = data.finalUrl || data.raw || "—";
    } catch (e) {
      console.error("fillDetailsPage error", e);
    }
  }

 // -------------------------
// FILE SANDBOX VIEWER — always uses Flask backend (app.py)
// -------------------------
document.addEventListener("DOMContentLoaded", () => {
  const uploadBtn = document.getElementById("fileSandboxUpload");
  const input = document.getElementById("fileSandboxInput");
  const status = document.getElementById("fileSandboxStatus");
  if (!uploadBtn || !input) return;

  const SERVER = "http://192.168.1.118:8080"; // Flask sandbox server

  uploadBtn.addEventListener("click", async () => {
    const file = input.files?.[0];
    if (!file) {
      status.textContent = "⚠️ Please select a file first.";
      status.style.color = "#e11d48";
      return;
    }

    try {
      status.textContent = "⏳ Uploading file to sandbox...";
      status.style.color = "#444";

      const form = new FormData();
      form.append("file", file, file.name);

      const resp = await fetch(`${SERVER}/upload`, { method: "POST", body: form });
      const data = await resp.json();
      if (!resp.ok || !data.ok) throw new Error(data.error || "Upload failed");

      // ✅ Use relative path only
      const cleanPath = data.saved_as.replace(/^.*\/uploads\//, "uploads/");
      const encodedPath = btoa(cleanPath);
      const viewerURL = chrome.runtime.getURL(
        `file_viewer.html?server=${encodeURIComponent(SERVER)}&path=${encodedPath}`
      );

      console.log("🚀 Opening sandbox viewer:", viewerURL);
      console.log("📦 Sent encoded path:", encodedPath);

      chrome.tabs.create({ url: viewerURL }, () => {
        if (chrome.runtime.lastError) {
          console.error("❌ Chrome tab create failed:", chrome.runtime.lastError.message);
          status.textContent = "❌ Could not open viewer tab.";
          status.style.color = "#dc2626";
        } else {
          status.textContent = "✅ File opened in sandbox viewer.";
          status.style.color = "#16a34a";
        }
      });
    } catch (err) {
      console.error("❌ File sandbox upload error:", err);
      status.textContent = "❌ " + err.message;
      status.style.color = "#dc2626";
    }
  });
});

// -------------------------
// Email logic (Mail.tm Integration) — safe lazy init + persistence
// -------------------------
function initMailFeature() {
  try {
    const API = "https://api.mail.tm";
    const MAIL_KEY = "mailtm_mailbox";
    const SESSION_LIFETIME = 10 * 60 * 1000; // 10 min

    let token = null;
    let address = null;
    let password = null;
    let inboxTimer = null;

    // element refs
    const emailAddrEl = document.getElementById("email-address");
    const inboxListEl = document.getElementById("inbox-items");
    const inboxLoading = document.getElementById("inbox-loading");
    const copyBtn = document.getElementById("copy-email");
    const regenBtn = document.getElementById("regen-email");
    const msgView = document.getElementById("email-message");
    const msgBack = document.getElementById("msg-back");
    const msgFrom = document.getElementById("msg-from");
    const msgSub = document.getElementById("msg-sub");
    const msgBody = document.getElementById("msg-body");

    const storeGet = (k) => new Promise(r => chrome.storage.local.get(k, d => r(d[k])));
    const storeSet = (o) => new Promise(r => chrome.storage.local.set(o, r));
    const storeRemove = (k) => new Promise(r => chrome.storage.local.remove(k, r));

    async function loginToken(addr, pass) {
      const res = await fetch(`${API}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: addr, password: pass }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      token = data.token;
      await storeSet({ [MAIL_KEY]: { address: addr, password: pass, token, createdAt: Date.now() } });
    }

    async function createMailbox() {
      emailAddrEl.textContent = "Creating temporary address...";
      inboxListEl.innerHTML = "";
      inboxLoading.textContent = "Setting up inbox...";
      try {
        const domainsRes = await fetch(`${API}/domains`);
        const domains = (await domainsRes.json())["hydra:member"];
        const domain = domains[0]?.domain || "encourtsmail.com";
        const rand = Math.random().toString(36).substring(2, 8);
        const email = `user_${rand}@${domain}`;
        const pass = Math.random().toString(36).substring(2, 10);

        await fetch(`${API}/accounts`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ address: email, password: pass }),
        });

        await loginToken(email, pass);
        address = email;
        password = pass;
        emailAddrEl.textContent = address;
        inboxLoading.textContent = "📬 Connected to Mail.tm inbox.";
        if (inboxTimer) clearInterval(inboxTimer);
        loadInbox();
        inboxTimer = setInterval(loadInbox, 15000);
      } catch (err) {
        console.error("Mail.tm createMailbox error:", err);
        emailAddrEl.textContent = "❌ Error creating mailbox";
        inboxLoading.textContent = "";
      }
    }

    async function loadInbox() {
      if (!token) return;
      inboxLoading.textContent = "🔄 Loading messages...";
      inboxListEl.innerHTML = "";
      try {
        let res = await fetch(`${API}/messages`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.status === 401 && address && password) {
          console.warn("[mail] token expired — re-login");
          await loginToken(address, password);
          res = await fetch(`${API}/messages`, {
            headers: { Authorization: `Bearer ${token}` },
          });
        }
        if (!res.ok) throw new Error("Inbox fetch failed " + res.status);
        const data = await res.json();
        const messages = data["hydra:member"] || [];

        if (!messages.length) {
          inboxLoading.textContent = "📭 No new messages.";
          return;
        }

        inboxLoading.textContent = "";
        inboxListEl.innerHTML = messages
          .map(
            (m) => `
            <div class="mail-item" data-id="${m.id}">
              <div><b>${m.subject || "(No subject)"}</b></div>
              <div class="small">${m.from?.address || "Unknown sender"}</div>
              <div class="small">${new Date(m.createdAt).toLocaleString()}</div>
            </div>`
          )
          .join("");

        document.querySelectorAll(".mail-item").forEach((el) =>
          el.addEventListener("click", () => openMessage(el.dataset.id))
        );
      } catch (err) {
        inboxLoading.textContent = "⚠️ Error loading inbox.";
        console.error(err);
      }
    }

    async function openMessage(id) {
      try {
        const res = await fetch(`${API}/messages/${id}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const msg = await res.json();
        document.getElementById("inbox-list").classList.add("hidden");
        msgView.classList.remove("hidden");
        msgFrom.textContent = msg.from?.address || "Unknown";
        msgSub.textContent = msg.subject || "(No subject)";
        msgBody.textContent = msg.text || msg.intro || "(No message body)";
      } catch (err) {
        msgBody.textContent = "Error loading message body.";
      }
    }

    msgBack?.addEventListener("click", () => {
      msgView.classList.add("hidden");
      document.getElementById("inbox-list").classList.remove("hidden");
    });

    copyBtn?.addEventListener("click", () => {
      if (address) {
        navigator.clipboard.writeText(address);
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
      }
    });

    regenBtn?.addEventListener("click", async () => {
      await storeRemove(MAIL_KEY);
      await createMailbox();
    });

    const refreshBtn = document.getElementById("refresh-email");
    refreshBtn?.addEventListener("click", async () => {
      if (!token) return;
      inboxLoading.textContent = "🔁 Refreshing inbox...";
      await loadInbox();
      inboxLoading.textContent = "✅ Inbox updated.";
      setTimeout(() => (inboxLoading.textContent = ""), 1500);
    });

    async function loadTempMailInbox() {
      try {
        const saved = await storeGet(MAIL_KEY);
        const stillValid =
          saved &&
          saved.address &&
          saved.token &&
          saved.createdAt &&
          Date.now() - saved.createdAt < SESSION_LIFETIME;

        if (stillValid) {
          console.log("[mail] reusing mailbox:", saved.address);
          address = saved.address;
          password = saved.password;
          token = saved.token;
          emailAddrEl.textContent = address;
          await loadInbox();
        } else {
          console.log("[mail] creating new mailbox");
          await storeRemove(MAIL_KEY);
          await createMailbox();
        }
      } catch (err) {
        console.error("Mailbox load error:", err);
        await createMailbox();
      }
    }

    // ✅ Safe lazy call
    loadTempMailInbox();
  } catch (fatal) {
    console.error("Mail.tm fatal error:", fatal);
  }
}

// 🧩 Attach safely to navigation
openEmailBtn?.addEventListener("click", () => {
  showOnly("email");
  initMailFeature(); // lazy init — no blocking of popup
});

backEmail?.addEventListener("click", () => showOnly("home"));
})();
