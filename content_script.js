// content_script.js — FINAL (Option C + robust decoding + strong detection, low false positives)
(async function () {
  'use strict';

  // initial enabled flag from storage
  const data = await chrome.storage.local.get({ enabled: true });
  let enabled = !!data.enabled;

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "SET_ENABLED") enabled = !!msg.value;
  });

  // -------------------------
  // Helper: search box detection
  // -------------------------
  function isSearchBox(el) {
    if (!el) return false;
    const tag = el.tagName?.toLowerCase();
    if (tag !== "input" && tag !== "textarea") return false;

    const id = (el.id || "").toLowerCase();
    const cls = (el.className || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    const hostname = location.hostname.toLowerCase();

    if (hostname.includes("google.") && name === "q") return true;
    if (id.includes("search") || cls.includes("search") || name.includes("search")) return true;
    if (placeholder.includes("search")) return true;

    return false;
  }

  // -------------------------
  // Plain-English guard (tightened)
  // -------------------------
  function isPlainEnglish(text) {
    return /^[a-zA-Z0-9\s.,!?'"()-]{4,}$/.test(text) &&
           !/[<>{}$;=`]|--|\/\*/.test(text);
  }

  // -------------------------
  // Multi-decode helpers
  // -------------------------
  function safeDecodeURIComponent(s) { try { return decodeURIComponent(String(s)); } catch { return s; } }
  function decodePercentU(s) { try { return String(s).replace(/%u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))); } catch { return s; } }
  function decodeUnicodeEscapes(s) {
    try {
      let t = String(s);
      t = t.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      t = t.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      return t;
    } catch { return s; }
  }
  function decodeHtmlEntities(s) {
    try {
      const ta = document.createElement('textarea');
      ta.innerHTML = s;
      return ta.value;
    } catch { return s; }
  }
  function tryBase64Decode(s) {
    try {
      const t = String(s).replace(/\s+/g, '');
      if (t.length > 12 && /^[A-Za-z0-9+/=]+$/.test(t) && t.length % 4 === 0) {
        try { return atob(t); } catch {}
      }
    } catch {}
    return s;
  }
  function tryRawHexDecode(s) {
    try {
      const t = String(s).replace(/\s+/g, '');
      if (t.length >= 8 && t.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(t)) {
        let out = '';
        for (let i = 0; i < t.length; i += 2)
          out += String.fromCharCode(parseInt(t.substr(i, 2), 16));
        return out;
      }
    } catch {}
    return s;
  }

  function multiDecodeSafe(s) {
    let cur = String(s);
    for (let i = 0; i < 10; i++) {
      const prev = cur;
      cur = safeDecodeURIComponent(cur);
      cur = decodePercentU(cur);
      cur = decodeUnicodeEscapes(cur);
      cur = decodeHtmlEntities(cur);
      cur = tryBase64Decode(cur);
      cur = tryRawHexDecode(cur);
      if (cur === prev) break;
    }
    return cur;
  }

  // -------------------------
  // Detection rules
  // -------------------------
  const XSS_RULES = [
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /on\w+\s*=/i,
    /\bjavascript:/i
  ];

  const SQL_RULES = [
    /\b(or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+/i,
    /\bunion\s+select\b/i,
    /(select|insert|update|delete|drop)\b[\s\S]{0,40}(--|#|\/\*)/i,
    /['"`]\s*(or|and|union|select|delete|update|drop)\b/i
  ];

  function hasSqlSymbols(s) {
    return /['"`=();]|--|\/\*/.test(s);
  }

  function looksStructuredSQL(s) {
    return /\b(select|delete|update|insert)\b\s+\w+\s+(from|set|where)\b/i.test(s) ||
           /\bselect\b\s+\*/i.test(s);
  }

  // -------------------------
  // Sanitizers (Option C)
  // -------------------------
  function sanitizeXSSReadable(v) {
    return String(v)
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/on\w+\s*=\s*(['"])[\s\S]*?\1/gi, '')
      .replace(/\b(javascript|data):[^\s'">]*/gi, '')
      .replace(/[<>]/g, '')
      .replace(/\s{2,}/g, ' ')
      .trim();
  }

  function sanitizeSQLReadable(v) {
    return String(v)
      .replace(/\b(delete|update)\b\s+\w+\s+(from|set)\b/gi, ' ')
      .replace(/\bunion\s+select\b/gi, ' ')
      .replace(/\bwhere\b[\s\S]{0,60}/gi, ' ')
      .replace(/--.*?(\r?\n|$)/g, ' ')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/['"`;]/g, ' ')
      .replace(/\s{2,}/g, ' ')
      .trim();
  }

  // -------------------------
  // Analyzer
  // -------------------------
  function analyzeAndSanitize(original) {
    const orig = String(original);
    const decoded = multiDecodeSafe(orig);

    // Plain English check AFTER decode
    if (isPlainEnglish(orig) && isPlainEnglish(decoded)) {
      return { acted: false, cleaned: orig, hits: [] };
    }

    function pipeline(text) {
      let tmp = String(text);
      const hits = [];
      const before = tmp;

      if (XSS_RULES.some(r => r.test(tmp))) {
        tmp = sanitizeXSSReadable(tmp);
        hits.push('xss');
      }

      if (SQL_RULES.some(r => r.test(tmp)) &&
          (hasSqlSymbols(tmp) || looksStructuredSQL(tmp))) {
        tmp = sanitizeSQLReadable(tmp);
        hits.push('sqli');
      }

      return { cleaned: tmp, hits, changed: tmp !== before };
    }

    const decRes = pipeline(decoded);
    const origRes = pipeline(orig);

    if (!decRes.hits.length && !origRes.hits.length)
      return { acted: false, cleaned: orig, hits: [] };

    return { acted: true, cleaned: decRes.changed ? decRes.cleaned : origRes.cleaned, hits: [...new Set([...decRes.hits, ...origRes.hits])] };
  }

  // -------------------------
  // Handlers
  // -------------------------
  function onInput(e) {
    if (!enabled) return;
    const el = e.target;
    if (!el || isSearchBox(el) || el.type === 'password') return;

    const res = analyzeAndSanitize(el.value || '');
    if (res.acted) {
      el.value = res.cleaned;
      showToast('Suspicious input sanitized.');
    }
  }

  function onPaste(e) {
    if (!enabled) return;
    const el = e.target;
    if (!el || isSearchBox(el) || el.type === 'password') return;

    const raw = e.clipboardData?.getData('text/plain') || '';
    const res = analyzeAndSanitize(raw);
    if (res.acted) {
      e.preventDefault();
      el.value = res.cleaned;
      showToast('Suspicious paste sanitized.');
    }
  }

  // -------------------------
  // Toast
  // -------------------------
  function showToast(msg) {
    let box = document.getElementById('inputshield-toast');
    if (!box) {
      box = document.createElement('div');
      box.id = 'inputshield-toast';
      box.style.cssText =
        'position:fixed;top:18px;right:18px;padding:12px 16px;background:#202A44;color:#fff;' +
        'border-radius:10px;box-shadow:0 6px 22px rgba(0,0,0,.35);z-index:2147483647;';
      document.body.appendChild(box);
    }
    box.textContent = msg;
    box.style.opacity = '1';
    clearTimeout(box._t);
    box._t = setTimeout(() => box.style.opacity = '0', 2400);
  }

  document.addEventListener('input', onInput, true);
  document.addEventListener('paste', onPaste, true);

  console.log('[InputShield] Final hardened version loaded.');
})();
