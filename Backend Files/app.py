from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import os, time, uuid, base64, threading, shutil, sqlite3, mimetypes, requests, ssl, json
import re, socket, ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

APP_DIR = "/home/saketh/sandbox-api"
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
DB = os.path.join(APP_DIR, "sessions.db")

app = Flask(__name__)

# ================================
# DB Setup
# ================================
def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, created INT, ttl INT)")
    conn.commit()
    conn.close()
init_db()

def create_session(ttl=300):
    sid = str(uuid.uuid4())
    path = os.path.join(UPLOAD_DIR, sid)
    os.makedirs(path, exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.execute("INSERT INTO sessions(id, created, ttl) VALUES(?,?,?)", (sid, int(time.time()), ttl))
    conn.commit()
    conn.close()
    return sid, path

def validate_path(path):
    return os.path.realpath(path).startswith(os.path.realpath(UPLOAD_DIR))

# ================================
# HTML Sanitizer
# ================================
def sanitize_html(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "iframe", "object", "embed"]):
        tag.decompose()
    for el in soup.find_all(True):
        for attr in list(el.attrs):
            if attr.lower().startswith("on"):
                del el.attrs[attr]
            if attr.lower() in ("href", "src"):
                val = el.attrs.get(attr, "")
                if isinstance(val, str) and val.strip().lower().startswith("javascript:"):
                    el.attrs[attr] = "#"
    for m in soup.find_all("meta"):
        if m.attrs.get("http-equiv", "").lower() in ("content-security-policy", "x-frame-options"):
            m.decompose()
    return str(soup)

# ================================
# LINK ANALYZER HELPERS
# ================================
_CACHE = {}
def cache_get(k):
    v = _CACHE.get(k)
    if not v: return None
    exp, val = v
    if time.time() > exp:
        _CACHE.pop(k, None)
        return None
    return val

def cache_set(k, val, ttl_sec=3600):
    _CACHE[k] = (time.time() + ttl_sec, val)

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_private_host(host):
    try:
        if not host:
            return True
        hl = host.lower()
        if hl in ("localhost",) or hl.endswith(".local"):
            return True
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            ip_obj = ipaddress.ip_address(ip)
            if any(ip_obj in net for net in PRIVATE_NETS):
                return True
    except Exception:
        pass
    return False

def expand_redirects(start_url, max_hops=5, per_hop_timeout=1.0):
    chain = []
    final = start_url
    try:
        resp = requests.head(start_url, allow_redirects=False, timeout=per_hop_timeout)
        hops = 0
        while resp.is_redirect and hops < max_hops:
            loc = resp.headers.get("Location")
            if not loc:
                break
            nxt = urljoin(final, loc)
            u = urlparse(nxt)
            chain.append({"status": resp.status_code, "url": nxt, "host": u.hostname, "scheme": u.scheme})
            final = nxt
            resp = requests.head(final, allow_redirects=False, timeout=per_hop_timeout)
            hops += 1
    except Exception:
        # ⚙️ fallback to GET (some sites like Cloudflare block HEAD)
        try:
            resp = requests.get(start_url, allow_redirects=False, timeout=per_hop_timeout)
            if resp.is_redirect:
                loc = resp.headers.get("Location")
                if loc:
                    nxt = urljoin(start_url, loc)
                    chain.append({"status": resp.status_code, "url": nxt})
                    final = nxt
        except Exception:
            pass
    return final, chain


def dns_snapshot(host):
    if not host:
        return {"host": None, "a": [], "aaaa": [], "ns": [], "dnssec": None}
    ck = f"dns:{host}"
    cached = cache_get(ck)
    if cached:
        return cached
    data = {"host": host, "a": [], "aaaa": [], "ns": [], "dnssec": None}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        data["a"] = sorted({ip for fam,_,_,_,(ip, *_) in infos if ":" not in ip})
        data["aaaa"] = sorted({ip for fam,_,_,_,(ip, *_) in infos if ":" in ip})
    except Exception:
        pass
    cache_set(ck, data, ttl_sec=3600)
    return data

def guess_etld1(host):
    if not host: return None
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host

def rdap_whois(etld1):
    if not etld1:
        return None
    ck = f"rdap:{etld1}"
    cached = cache_get(ck)
    if cached is not None:
        return cached
    whois = None
    try:
        r = requests.get(f"https://rdap.org/domain/{etld1}", timeout=1.2)
        if r.ok:
            j = r.json()
            created = None
            if isinstance(j.get("events"), list):
                for ev in j["events"]:
                    if ev.get("eventAction") in ("registration", "registered", "creation"):
                        created = ev.get("eventDate")
                        break
            registrar = None
            ents = j.get("entities") or []
            for e in ents:
                v = (e.get("vcardArray") or [None, []])[1]
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, list) and len(item) >= 3 and item[0] == "fn":
                            registrar = item[3]
                            break
                if registrar:
                    break
            whois = {"domain": etld1, "created": created, "registrar": registrar, "rdap_provider": "rdap.org"}
    except Exception:
        whois = None
    cache_set(ck, whois, ttl_sec=86400)
    return whois

def tls_probe(url, timeout=1.0):
    info = None
    score = 0
    reasons = []
    fatal = False
    try:
        u = urlparse(url)
        if u.scheme == "https":
            _ = requests.get(url, timeout=timeout, allow_redirects=False)
            info = {"host": u.hostname, "issuer": None, "valid_to": None, "hostname_match": True, "protocol": "HTTPS"}
        elif u.scheme == "http":
            score += 2
            reasons.append("Final URL uses HTTP (no TLS)")
            info = {"host": u.hostname, "issuer": None, "valid_to": None, "hostname_match": None, "protocol": "HTTP"}
        else:
            reasons.append(f"Non-web scheme: {u.scheme}")
            score += 8
            fatal = True
    except requests.exceptions.SSLError:
        reasons.append("TLS certificate error")
        fatal = True
    except Exception:
        pass
    return info, score, reasons, fatal

def url_heuristics(u):
    reasons, score, fatal = [], 0, False
    try:
        x = urlparse(u)
    except Exception:
        return {"score": 8, "fatal": True, "reasons": ["Invalid URL"], "hostname": None}
    h = x.hostname or ""
    full = u

    if x.scheme == "http":
        score += 2; reasons.append("Uses HTTP")
    if x.scheme not in ("http", "https"):
        score += 8; fatal = True; reasons.append(f"Non-web scheme: {x.scheme}")
    if full.split("://")[1].find("@") != -1:
        score += 8; fatal = True; reasons.append("Contains userinfo (@) before host")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
        score += 3; reasons.append("Raw IP hostname")
    if h.startswith("xn--"):
        score += 3; reasons.append("Punycode (IDN) domain")
    if re.search(r"\.(zip|mov|gq|tk|ml|cf|ga|top|xyz|click)$", h, re.I):
        score += 2; reasons.append("High-abuse TLD")
    if re.search(r"\.(exe|scr|bat|cmd|js|jar|vbs|ps1|apk|msi|hta)([?#].*)?$", x.path, re.I):
        score += 8; fatal = True; reasons.append("Direct executable link")
    if re.search(r"([?&](url|dest|redirect|next|to)=https?:)", x.query, re.I):
        score += 2; reasons.append("Open-redirect style parameter")
    if len(full) > 200:
        score += 2; reasons.append("Very long URL")

    return {"score": score, "fatal": fatal, "reasons": reasons, "hostname": h}

# ================================
# CORS
# ================================
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp

# ================================
# API ENDPOINTS
# ================================
@app.route("/ping")
def ping():
    return jsonify(ok=True)

# ✅ NEW — Web Sandbox Viewer route
@app.route("/render", methods=["POST"])
def render():
    data = request.get_json(force=True) or {}
    target = data.get("url", "").strip()

    if not target:
        return jsonify(ok=False, error="Missing URL"), 400

    # Block local/private URLs
    if is_private_host(urlparse(target).hostname):
        return jsonify(ok=False, error="Private or local address blocked"), 403

    try:
        with sync_playwright() as p:
            browser = p.firefox.launch(headless=True)
            page = browser.new_page()
            page.goto(target, timeout=5000)
            html = page.content()
            browser.close()

        safe_html = sanitize_html(html)
        return jsonify(ok=True, html=safe_html)
    except Exception as e:
        return jsonify(ok=False, error=str(e))

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify(ok=False, error="No file"), 400
    f = request.files["file"]
    name = secure_filename(f.filename)
    sid, path = create_session(ttl=300)
    fp = os.path.join(path, name)
    f.save(fp)
    return jsonify(ok=True, session=sid, saved_as=fp)

@app.route("/view_file", methods=["POST"])
def view_file():
    data = request.get_json(force=True) or {}
    path = data.get("path")

    if not path or not os.path.exists(path):
        return jsonify(ok=False, error="File not found"), 404
    if not validate_path(path):
        return jsonify(ok=False, error="Invalid path"), 403

    mime_type, _ = mimetypes.guess_type(path)
    mime_type = mime_type or "application/octet-stream"

    if mime_type.startswith("text/") or path.lower().endswith((".html", ".js", ".css", ".json", ".txt", ".log")):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "html" in mime_type:
            safe_html = sanitize_html(content)
            return jsonify(ok=True, type="html", mime=mime_type, content=safe_html)
        else:
            return jsonify(ok=True, type="text", mime=mime_type, content=content)

    elif mime_type == "application/pdf" or path.lower().endswith(".pdf"):
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        return jsonify(ok=True, type="pdf", mime=mime_type, content=b64)

    elif mime_type.startswith("image/") or path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")):
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        return jsonify(ok=True, type="image", mime=mime_type, content=b64)

    elif mime_type.startswith("audio/") or mime_type.startswith("video/"):
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        ftype = "video" if mime_type.startswith("video/") else "audio"
        return jsonify(ok=True, type=ftype, mime=mime_type, content=b64)

    else:
        size = os.path.getsize(path)
        return jsonify(ok=True, type="binary", mime=mime_type,
                       message=f"Binary file ({size//1024} KB)")

# ✅ direct file streaming for PDF inline rendering
@app.route("/get_file")
def get_file():
    path = request.args.get("path", "")
    if not path or not os.path.exists(path) or not validate_path(path):
        return "Invalid path", 404

    mime, _ = mimetypes.guess_type(path)
    mime = mime or "application/octet-stream"
    as_attachment = (request.args.get("download") == "1")

    resp = send_file(
        path,
        mimetype=mime,
        as_attachment=as_attachment,
        download_name=os.path.basename(path),
        conditional=True
    )
    if not as_attachment:
        resp.headers["Content-Disposition"] = f'inline; filename="{os.path.basename(path)}"'
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

# ================================
# LINK ANALYZER (for extension)
# ================================
@app.route("/api/analyzer/v1/analyze", methods=["POST"])
def analyzer_v1():
    data = request.get_json(force=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify(ok=False, error="Missing URL"), 400

    try:
        base = url_heuristics(url)
        final, chain = expand_redirects(url)
        host = urlparse(final).hostname
        dns_info = dns_snapshot(host)
        etld1 = guess_etld1(host)
        whois_info = rdap_whois(etld1)
        tls_info, tls_score, tls_reasons, tls_fatal = tls_probe(final)
        score = base["score"] + tls_score
        fatal = base["fatal"] or tls_fatal
        reasons = base["reasons"] + tls_reasons

        resp = {
            "finalUrl": final,
            "hostname": host,
            "chain": chain,
            "dns": dns_info,
            "whois": whois_info,
            "tls": tls_info,
            "score": score,
            "fatal": fatal,
            "reasons": reasons,
        }

        return jsonify(ok=True, data=resp)
    except Exception as e:
        return jsonify(ok=False, error=str(e))

# ================================
# STATUS + CLEANUP
# ================================
@app.route("/cleanup", methods=["POST"])
def cleanup():
    now = int(time.time())
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT id,created,ttl FROM sessions").fetchall()
    for sid, created, ttl in rows:
        if now - created > ttl:
            path = os.path.join(UPLOAD_DIR, sid)
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
            conn.execute("DELETE FROM sessions WHERE id=?", (sid,))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route("/status")
def status():
    return jsonify(ok=True, message="Sandbox server is running", port=8080)

# ================================
# CLEANUP THREAD
# ================================
def cleanup_thread():
    while True:
        time.sleep(60)
        try:
            requests.post("http://127.0.0.1:8080/cleanup", timeout=5)
        except requests.RequestException:
            pass

if __name__ == "__main__":
    threading.Thread(target=cleanup_thread, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, use_reloader=False)
