// analyzer.js — Link Analyzer (final optimized version)

// ============= SERVER DETECTION ==================
const SERVER_CANDIDATES = [
  "http://192.168.1.118:8080", // ✅ Your actual backend IP
  "http://127.0.0.1:8080",
  "http://localhost:8080"
];

let API_BASE = SERVER_CANDIDATES[0];

// Quick reachability detection (runs once)
async function detectServer() {
  for (const base of SERVER_CANDIDATES) {
    try {
      const res = await fetch(`${base}/ping`, { method: "GET" });
      if (res.ok) {
        API_BASE = base;
        console.log("✅ Analyzer backend:", base);
        return;
      }
    } catch {}
  }
  console.warn("⚠️ No analyzer backend reachable, defaulting to", API_BASE);
}
detectServer();

// ============= UTILS ==================
async function safeFetch(url, options, timeoutMs = 5000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

// ============= MAIN ==================
document.addEventListener("DOMContentLoaded", () => {
  // DOM refs
  const elUrl = document.getElementById("quick-url");
  const btnAnalyze = document.getElementById("quick-analyze-btn");
  const elQuickRes = document.getElementById("quick-result");
  const btnDetails = document.getElementById("full-details-btn");

  const pageHome = document.getElementById("page-home");
  const pageDetails = document.getElementById("page-details");
  const btnBack = document.getElementById("details-back");

  const elPill = document.getElementById("risk-pill");
  const elScore = document.getElementById("score");
  const elRec = document.getElementById("recommendation");
  const elDomain = document.getElementById("domain");
  const elInd = document.getElementById("indicators-list");
  const elEnc = document.getElementById("encoded-list");
  const elBreak = document.getElementById("breakdown");
  const elRaw = document.getElementById("raw-url");
  const btnOpenSandbox = document.getElementById("open-sandbox");
  const btnCopyReport = document.getElementById("copy-report");

  function setQuick(text, type = "info") {
    elQuickRes.classList.remove("hidden");
    elQuickRes.dataset.type = type;
    elQuickRes.textContent = text;
  }

  function classify(score, fatal) {
    if (fatal) return { verdict: "Unsafe", pill: "danger" };
    if (score >= 8) return { verdict: "Unsafe", pill: "danger" };
    if (score >= 4) return { verdict: "Caution", pill: "warn" };
    return { verdict: "Safe", pill: "safe" };
  }

  function multiDecode(raw) {
    const layers = [], outputs = [];
    let curr = raw;
    for (let i = 0; i < 3; i++) {
      let changed = false;
      try {
        const d = decodeURIComponent(curr);
        if (d !== curr) { layers.push("percent"); curr = d; outputs.push(curr); changed = true; }
      } catch {}
      const htmlDecoded = curr.replace(/&#(\d{1,7});/g, (_, n) => String.fromCharCode(Number(n)))
        .replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
        .replace(/&quot;/g, "\"").replace(/&apos;/g, "'");
      if (htmlDecoded !== curr) { layers.push("html"); curr = htmlDecoded; outputs.push(curr); changed = true; }

      const b64re = /(?:^|[?&=])(aHR0|https?:\/\/)?([A-Za-z0-9+/]{12,}={0,2})(?:$|[&#])/;
      const m = curr.match(b64re);
      if (m) {
        try {
          const bytes = atob(m[2]);
          if (/https?:\/\//.test(bytes) || /[A-Za-z0-9\-_.?&=/%]/.test(bytes)) {
            layers.push("base64");
            curr = curr.replace(m[2], bytes);
            outputs.push(curr);
            changed = true;
          }
        } catch {}
      }
      if (!changed || curr.length > raw.length * 4) break;
    }
    return { final: curr, layers, outputs };
  }

  function localHeuristics(u) {
    let score = 0, fatal = false;
    const reasons = [];
    let url;
    try { url = new URL(u); } catch { return { score: 8, fatal: true, reasons: ["Invalid URL"] }; }

    const h = url.hostname;
    const full = url.href;
    if (url.protocol === "http:") { score += 2; reasons.push("Uses HTTP"); }
    if (!/^https?:$/.test(url.protocol)) { score += 8; fatal = true; reasons.push(`Non-web scheme: ${url.protocol}`); }
    if (full.split("://")[1]?.includes("@")) { score += 8; fatal = true; reasons.push("Has userinfo (@) before host"); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { score += 3; reasons.push("Raw IP as hostname"); }
    if (h.startsWith("xn--")) { score += 3; reasons.push("Punycode (IDN) domain"); }
    if (/\.(zip|mov|gq|tk|ml|cf|ga|top|xyz|click)$/i.test(h)) { score += 2; reasons.push("High-abuse TLD"); }
    if (/\.(exe|scr|bat|cmd|js|jar|vbs|ps1|apk|msi|hta)([?#].*)?$/i.test(url.pathname)) { score += 8; fatal = true; reasons.push("Direct executable"); }
    if (/([?&](url|dest|redirect|next|to)=https?:)/i.test(url.search)) { score += 2; reasons.push("Open-redirect parameter"); }
    if (full.length > 200) { score += 2; reasons.push("Very long URL"); }

    return { score, fatal, reasons, hostname: h };
  }

  function buildReport(base, decoded, serverData) {
    const fatal = base.fatal || serverData?.fatal;
    const score = (base.score || 0) + (serverData?.score || 0);
    const cls = classify(score, fatal);

    return {
      verdict: cls.verdict,
      score,
      reasons: [...(base.reasons || []), ...((serverData && serverData.reasons) || [])],
      finalUrl: serverData?.finalUrl || decoded.final || elUrl.value.trim(),
      hostname: serverData?.hostname || base.hostname,
      decoding: decoded,
      chain: serverData?.chain || [],
      dns: serverData?.dns || null,
      whois: serverData?.whois || null,
      tls: serverData?.tls || null
    };
  }

  function renderDetails(report) {
    const { verdict, score, reasons, finalUrl, hostname, decoding, chain, dns, whois, tls } = report;

    elPill.textContent = verdict;
    elPill.className = "risk-pill";
    elPill.classList.add(verdict === "Unsafe" ? "danger" : verdict === "Caution" ? "warn" : "safe");
    elScore.textContent = String(score);
    elDomain.textContent = hostname || "—";
    elRec.textContent = verdict === "Safe"
      ? "No blocking indicators found."
      : verdict === "Caution"
      ? "Be careful; review the indicators below before proceeding."
      : "Do not open this link.";

    elInd.innerHTML = "";
    (reasons || []).forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      elInd.appendChild(li);
    });

    const enc = decoding || { layers: [], outputs: [] };
    elEnc.innerHTML = enc.layers.length
      ? enc.layers.map((name, i) =>
          `<div class="kv"><span class="k">Layer ${i + 1}</span><span class="v">${name}</span></div>
          <pre class="raw">${(enc.outputs[i] || "").slice(0, 1200)}</pre>`).join("")
      : "<div class='small' style='color:var(--text-sub)'>No extra encoding found</div>";

    const chainHtml = (chain || []).map((hop, i) =>
      `<div class="kv"><span class="k">Hop ${i + 1}</span><span class="v">${hop.status || "—"} → ${hop.host || hop.url}</span></div>`).join("");
    const dnsHtml = dns ? `<div class="kv"><span class="k">A/AAAA</span><span class="v">${[...(dns.a || []), ...(dns.aaaa || [])].join(", ") || "—"}</span></div>` : "";
    const whoisHtml = whois ? `<div class="kv"><span class="k">Registrar</span><span class="v">${whois.registrar || "—"}</span></div>
      <div class="kv"><span class="k">Created</span><span class="v">${whois.created || "—"}</span></div>` : "";
    const tlsHtml = tls ? `<div class="kv"><span class="k">Protocol</span><span class="v">${tls.protocol || "—"}</span></div>
      <div class="kv"><span class="k">Hostname Match</span><span class="v">${tls.hostname_match ? "Yes" : "No"}</span></div>` : "";

    elBreak.innerHTML = `<div class="kv"><span class="k">Redirects</span><span class="v">${(chain && chain.length) ? chain.length : 0}</span></div>${chainHtml}<hr/>${dnsHtml}${whoisHtml}${tlsHtml}`;
    elRaw.textContent = finalUrl || "—";
  }

  // ============= EVENT HANDLERS ==================

  btnAnalyze?.addEventListener("click", async () => {
    const raw = elUrl.value.trim();
    if (!raw) { setQuick("Enter a URL to analyze.", "warn"); return; }

    const dec = multiDecode(raw);
    const locals = localHeuristics(dec.final);

    setQuick("Analyzing…");

    let server = null;
    try {
      const resp = await safeFetch(`${API_BASE}/api/analyzer/v1/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: dec.final }),
      }, 5000);
      const json = await resp.json();
      if (json?.ok) server = json.data;
      else if (json?.error) locals.reasons.push(`Server: ${json.error}`);
    } catch {
      locals.reasons.push("Backend enrichment unavailable");
    }

    const report = buildReport(locals, dec, server);
    const icon = report.verdict === "Safe" ? "✅" : report.verdict === "Caution" ? "⚠️" : "🛑";
    setQuick(`${icon} ${report.verdict} (score ${report.score})`,
             report.verdict === "Safe" ? "success" : report.verdict === "Caution" ? "warn" : "error");

    window.lastAnalysis = report;
    try { await chrome.storage.session.set({ lastAnalysis: report }); } catch {}
  });

  btnDetails?.addEventListener("click", () => {
    const current = elUrl.value.trim();
    const report = window.lastAnalysis;
    if (!report || !report.finalUrl || report.finalUrl !== current) {
      setQuick("Please analyze a link first.", "warn");
      return;
    }
    renderDetails(report);
    pageHome.style.display = "none";
    pageDetails.style.display = "block";
  });

  btnBack?.addEventListener("click", () => {
    pageDetails.style.display = "none";
    pageHome.style.display = "block";
  });

  btnCopyReport?.addEventListener("click", async () => {
    const { lastAnalysis } = await chrome.storage.session.get("lastAnalysis");
    await navigator.clipboard.writeText(JSON.stringify(lastAnalysis, null, 2));
    setQuick("Copied full report to clipboard.", "success");
  });

  btnOpenSandbox?.addEventListener("click", async () => {
    const { lastAnalysis } = await chrome.storage.session.get("lastAnalysis");
    const url = lastAnalysis?.finalUrl || elUrl.value.trim();
    if (!url) return;
    const target = chrome.runtime.getURL(`sandbox.html?url=${encodeURIComponent(url)}`);
    chrome.tabs.create({ url: target });
  });
});
