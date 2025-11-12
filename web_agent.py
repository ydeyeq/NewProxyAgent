#!/usr/bin/env python3
"""
Proxy Agent (Dual Mode + Duplicate Mode) — unified input/output format

Features:
- Input accepts: HOST:PORT, USER:PASS@HOST:PORT, socks5://..., HOST:PORT:USER:PASS
- Internally normalizes to socks5h://user:pass@host:port for resolution
- Output / copy payload always in HOST:PORT:USER:PASS form
- Proxy Mode: Resolve Only | Resolve + IPQS
- Duplicate Handling: drop_all | keep_one | keep_all
- When keep_one is used, each kept row includes total duplication count for that IP
- Port fallback, thread pools, IPQS cache, and retries included
"""

import os
import re
import time
import secrets
import logging
import threading
import ipaddress
import socket
from datetime import datetime, timezone
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from flask import Flask, request, render_template_string, session
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("proxy-agent")

# ---------- SOCKS dependency check ----------
try:
    import socks  # noqa: F401
except Exception:
    socks = None

# ---------- Config ----------
IPIFY_URL = "https://api.ipify.org?format=text"
IPQS_BASE = "https://ipqualityscore.com/api/json/ip"

def _cpu():
    try:
        return os.cpu_count() or 4
    except:
        return 4

PROXY_WORKERS   = int(os.getenv("PROXY_WORKERS", str(min(100, 8 * _cpu()))))
IPQS_WORKERS    = int(os.getenv("IPQS_WORKERS",  str(min(80, 6 * _cpu()))))
MAX_INPUT_LINES = int(os.getenv("MAX_INPUT_LINES", "50000"))
REQ_TIMEOUT     = (4, 6)
CACHE_MAX_AGE_DAYS = int(os.getenv("CACHE_MAX_AGE_DAYS", "7"))
IPQS_CACHE_MAXSIZE = int(os.getenv("IPQS_CACHE_MAXSIZE", "10000"))
IPQS_RATE_LIMIT_PER_SEC = float(os.getenv("IPQS_RATE_LIMIT_PER_SEC", "8"))

# ---------- HTTP session ----------
def _build_session():
    s = requests.Session()
    retry = Retry(total=3, connect=3, read=3, backoff_factor=0.7,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET"]))
    adapter = HTTPAdapter(pool_connections=100, pool_maxsize=200, max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "ProxyAgent-Unified/1.0"})
    return s

DIRECT_SESSION = _build_session()

# ---------- Flask ----------
app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FLASK_SECRET") or secrets.token_urlsafe(32)

# ---------- Simple LRU cache ----------
class LRUCache:
    def __init__(self, maxsize=10000):
        self.maxsize = int(maxsize)
        self.lock = threading.RLock()
        self.data = OrderedDict()

    def get(self, key):
        with self.lock:
            if key not in self.data:
                return None
            value, checked_at = self.data.pop(key)
            self.data[key] = (value, checked_at)
            return {"raw": value, "checked_at": checked_at}

    def put(self, key, value):
        with self.lock:
            if key in self.data:
                self.data.pop(key)
            self.data[key] = (value, datetime.now(timezone.utc))
            while len(self.data) > self.maxsize:
                self.data.popitem(last=False)

    def clear(self):
        with self.lock:
            self.data.clear()

IP_CACHE = LRUCache(maxsize=IPQS_CACHE_MAXSIZE)

# ---------- Helpers ----------
def _utcnow():
    return datetime.now(timezone.utc)

def validate_ip_text(ip_text):
    try:
        ipaddress.ip_address(ip_text)
        return True
    except Exception:
        return False

def _workers_for(n, cap): 
    return max(1, min(n, cap))

# ---------- Input normalization (accept many input types) ----------
def normalize_proxy(line: str) -> str:
    """
    Normalize input proxy into a socks5h://... URL for internal use.

    Accepted inputs:
      - HOST:PORT
      - USER:PASS@HOST:PORT
      - socks5://user:pass@host:port
      - HOST:PORT:USER:PASS (the specific format you use often)
    """
    s = (line or "").strip()
    if not s:
        return ""

    # If it's exactly HOST:PORT:USER:PASS (four colon segments, and host looks like host)
    # We'll be a bit permissive: accept IPv4/hostname with four parts
    parts = s.split(":")
    if len(parts) == 4:
        host_part = parts[0]
        port_part = parts[1]
        user = parts[2]
        pw = parts[3]
        # Basic validation for port numeric
        if port_part.isdigit():
            # convert to socks5h://user:pw@host:port
            return f"socks5h://{user}:{pw}@{host_part}:{port_part}"

    # If it's a URL already (socks5:// or socks5h://), return as-is
    if s.startswith("socks5://") or s.startswith("socks5h://"):
        return s

    # If it contains @ it's probably user:pass@host:port (add scheme if missing)
    if "@" in s:
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", s):
            return "socks5h://" + s
        return s

    # If it's host:port (two parts), add scheme
    if len(parts) == 2 and parts[1].isdigit():
        return "socks5h://" + s

    # Fallback: prefix scheme so urllib can parse it
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", s):
        return "socks5h://" + s

    return s

def parse_proxy_to_parts(proxy_url: str):
    """
    Parse a proxy URL into host, port, user, password.
    Works with socks5h://..., user:pass@host:port, and host:port:user:pass post-normalization.
    """
    s = (proxy_url or "").strip()
    if not s:
        return "", "", "", ""
    # Ensure a scheme so urlparse works
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", s):
        s = "socks5h://" + s
    try:
        p = urlparse(s)
        host = p.hostname or ""
        port = str(p.port or "")
        user = p.username or ""
        password = p.password or ""
        return host, port, user, password
    except Exception:
        return "", "", "", ""

def format_proxy_hostport_userpass(proxy_url: str) -> str:
    """
    Always return HOST:PORT:USER:PASS (empty segments when missing).
    """
    h, p, u, w = parse_proxy_to_parts(proxy_url)
    return f"{h or ''}:{p or ''}:{u or ''}:{w or ''}"

# ---------- Proxy resolution ----------
def _build_proxy_session():
    s = requests.Session()
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5,
                  status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset(["GET"]))
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def get_ip_via_proxy(proxy_url: str):
    """
    Use api.ipify.org through the given proxy URL and return (ok, ip_or_error_str).
    """
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        sess = _build_proxy_session()
        r = sess.get(IPIFY_URL, proxies=proxies, timeout=REQ_TIMEOUT)
        if r.status_code != 200:
            raise RuntimeError(f"status {r.status_code}")
        ip = (r.text or "").strip()
        if not ip or not validate_ip_text(ip):
            raise RuntimeError(f"invalid ip response: {ip}")
        return True, ip
    except Exception as e:
        return False, str(e)

# ---------- IPQS integration ----------
def query_ipqs(api_key: str, ip: str):
    url = f"{IPQS_BASE}/{api_key}/{ip}"
    try:
        r = DIRECT_SESSION.get(url, params={"strictness": 3}, timeout=REQ_TIMEOUT)
        if r.status_code != 200:
            return {"success": False, "message": f"status {r.status_code}", "_body": r.text[:400]}
        return r.json()
    except Exception as e:
        return {"success": False, "message": str(e)}

def _is_limit_error(resp: dict) -> bool:
    if not isinstance(resp, dict): 
        return False
    msg = (resp.get("message") or "").lower()
    return any(s in msg for s in ["limit", "usage", "exhaust", "credit"]) and resp.get("success") is False

def query_ipqs_with_keys(api_keys: list, ip: str):
    last = {"success": False, "message": "no api key provided"}
    for key in [k for k in (api_keys or []) if k]:
        resp = query_ipqs(key, ip)
        if not _is_limit_error(resp):
            return resp
        last = resp
    return last

def verdict_icon(fraud_score):
    if fraud_score in (None, ""):
        return '<span style="color:#999">?</span>'
    try:
        fs = int(fraud_score)
    except Exception:
        return '<span style="color:#999">?</span>'
    if fs == 0:
        return '<span style="color:#0a8a0a;font-weight:bold;">✓</span>'
    if 1 <= fs <= 28:
        return '<span style="color:#000000;font-weight:bold;">✓</span>'
    return '<span style="color:#c32020;font-weight:bold;">✗</span>'

# ---------- Cache helpers ----------
def cache_get(ip: str):
    entry = IP_CACHE.get(ip)
    if not entry:
        return None
    when = entry.get("checked_at") or datetime(1970, 1, 1, tzinfo=timezone.utc)
    age_days = int((_utcnow() - when).total_seconds() // 86400)
    return {"fraud_score": entry.get("raw", {}).get("fraud_score"), "raw": entry.get("raw", {}), "age_days": age_days}

def cache_put(ip: str, fraud_score, raw_json):
    if raw_json is None:
        raw_json = {}
    raw_copy = dict(raw_json)
    if "fraud_score" not in raw_copy and fraud_score is not None:
        raw_copy["fraud_score"] = fraud_score
    IP_CACHE.put(ip, raw_copy)

# ---------- Duplicate handling (returns dup_count) ----------
def deduplicate(ip_to_proxies: dict, dup_mode: str):
    """
    ip_to_proxies: { ip: [proxy_url1, proxy_url2, ...] }
    dup_mode: "drop_all", "keep_one", "keep_all"

    Returns:
      kept: list of tuples (proxy_url, ip, formatted_str, dup_count)
      dropped: integer number of dropped proxies
    """
    kept = []
    dropped = 0
    for ip, plist in ip_to_proxies.items():
        total = len(plist)
        if dup_mode == "keep_all":
            for p in plist:
                kept.append((p, ip, format_proxy_hostport_userpass(p), total))
        elif dup_mode == "keep_one":
            # keep first; record total count
            kept.append((plist[0], ip, format_proxy_hostport_userpass(plist[0]), total))
            dropped += total - 1
        elif dup_mode == "drop_all":
            if total == 1:
                kept.append((plist[0], ip, format_proxy_hostport_userpass(plist[0]), 1))
            else:
                dropped += total
        else:
            # unknown mode: default to drop_all for safety
            if total == 1:
                kept.append((plist[0], ip, format_proxy_hostport_userpass(plist[0]), 1))
            else:
                dropped += total
    return kept, dropped

# ---------- Core: Resolve Only ----------
def resolve_only(text: str, dup_mode: str):
    raw = [l.strip() for l in text.splitlines() if l.strip()]
    proxies = [normalize_proxy(l) for l in raw[:MAX_INPUT_LINES]]
    proxy_to_result = {}

    with ThreadPoolExecutor(max_workers=_workers_for(len(proxies), PROXY_WORKERS)) as ex:
        fut = {ex.submit(get_ip_via_proxy, p): p for p in proxies}
        for f in as_completed(fut):
            p = fut[f]
            ok, val = f.result()
            proxy_to_result[p] = (ok, val)

    ip_to_proxies = defaultdict(list)
    failures = []
    for proxy, (ok, val) in proxy_to_result.items():
        if ok:
            ip_to_proxies[val].append(proxy)
        else:
            # collect failures to show in results (format as HOST:PORT:USER:PASS)
            failures.append((proxy, val))

    kept, dropped_dupes = deduplicate(ip_to_proxies, dup_mode)
    rows = []
    copy_list = []

    for proxy_url, ip, formatted, dup_count in kept:
        # formatted is already HOST:PORT:USER:PASS
        # dup_count is total proxies that shared IP
        rows.append({
            "proxy_formatted": formatted,
            "resolved_ip": ip,
            "country": "",  # left blank in resolve-only mode
            "proxy_ok": "✅",
            "ipqs_success": "—",
            "fraud_score": "",
            "verdict_icon": "",
            "ipqs_message": "",
            "dup_count": dup_count if dup_mode == "keep_one" else ""
        })
        # copy payload for resolve-only: include all kept
        copy_list.append(formatted)

    # show failures as separate rows (no resolved ip)
    for p, err in failures:
        rows.append({
            "proxy_formatted": format_proxy_hostport_userpass(p),
            "resolved_ip": "",
            "country": "",
            "proxy_ok": "❌",
            "ipqs_success": "",
            "fraud_score": "",
            "verdict_icon": '<span style="color:#999">?</span>',
            "ipqs_message": f"Resolve error: {err}",
            "dup_count": ""
        })

    copy_payload = "\n".join(copy_list)
    kept_count = len(kept)
    return rows, dropped_dupes, kept_count, copy_payload

# ---------- Core: Resolve + IPQS ----------
def resolve_and_ipqs(api_keys: list, text: str, dup_mode: str):
    raw = [l.strip() for l in text.splitlines() if l.strip()]
    proxies = [normalize_proxy(l) for l in raw[:MAX_INPUT_LINES]]
    proxy_to_result = {}

    with ThreadPoolExecutor(max_workers=_workers_for(len(proxies), PROXY_WORKERS)) as ex:
        fut = {ex.submit(get_ip_via_proxy, p): p for p in proxies}
        for f in as_completed(fut):
            p = fut[f]
            ok, val = f.result()
            proxy_to_result[p] = (ok, val)

    ip_to_proxies = defaultdict(list)
    failures = []
    for proxy, (ok, val) in proxy_to_result.items():
        if ok:
            ip_to_proxies[val].append(proxy)
        else:
            failures.append((proxy, val))

    kept, dropped_dupes = deduplicate(ip_to_proxies, dup_mode)
    unique_ips = [ip for _, ip, _, _ in kept]

    # lookup IPQS for unique IPs (with caching)
    ip_to_ipqs = {}

    def lookup_or_cache(ip):
        cached = cache_get(ip)
        if cached and cached["age_days"] < CACHE_MAX_AGE_DAYS:
            data = cached["raw"]
            if "fraud_score" not in data:
                data["fraud_score"] = cached["fraud_score"]
            return ip, data, True
        data = query_ipqs_with_keys(api_keys, ip)
        if data.get("fraud_score") is not None:
            cache_put(ip, data.get("fraud_score"), data)
        return ip, data, False

    if unique_ips:
        with ThreadPoolExecutor(max_workers=_workers_for(len(unique_ips), IPQS_WORKERS)) as ex:
            fut2 = {ex.submit(lookup_or_cache, ip): ip for ip in unique_ips}
            for f in as_completed(fut2):
                ip, data, _ = f.result()
                ip_to_ipqs[ip] = data

    rows = []
    copy_list = []

    for proxy_url, ip, formatted, dup_count in kept:
        info = ip_to_ipqs.get(ip, {})
        fs = info.get("fraud_score") if isinstance(info, dict) else None
        try:
            fs_int = int(fs) if fs not in (None, "") else None
        except Exception:
            fs_int = None

        if fs_int is not None and fs_int <= 28:
            copy_list.append(formatted)

        rows.append({
            "proxy_formatted": formatted,
            "resolved_ip": ip,
            "country": (info.get("country_code") or info.get("country") or "") if isinstance(info, dict) else "",
            "proxy_ok": "✅",
            "ipqs_success": "✅" if not (isinstance(info, dict) and info.get("success") is False) else "❌",
            "fraud_score": fs_int if fs_int is not None else "",
            "verdict_icon": verdict_icon(fs),
            "ipqs_message": info.get("message") if isinstance(info, dict) else "",
            "dup_count": dup_count if dup_mode == "keep_one" else ""
        })

    for p, err in failures:
        rows.append({
            "proxy_formatted": format_proxy_hostport_userpass(p),
            "resolved_ip": "",
            "country": "",
            "proxy_ok": "❌",
            "ipqs_success": "",
            "fraud_score": "",
            "verdict_icon": '<span style="color:#999">?</span>',
            "ipqs_message": f"Resolve error: {err}",
            "dup_count": ""
        })

    copy_payload = "\n".join(copy_list)
    kept_count = len(kept)
    return rows, dropped_dupes, kept_count, copy_payload

# ---------- HTML ----------
INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Proxy Agent</title>
  <style>
    body{font-family:-apple-system,Arial,sans-serif;margin:32px;}
    .btn{padding:8px 14px;border:1px solid #ccc;border-radius:6px;background:#f6f6f6;cursor:pointer;}
    .btn:hover{background:#eee;}
    table{border-collapse:collapse;margin-top:24px;width:100%;max-width:1100px;}
    th,td{border:1px solid #ddd;padding:8px 10px;text-align:left;vertical-align:top;}
    th{background:#fafafa;}
    code{white-space: pre-wrap;}
  </style>
</head>
<body>
  <h2>Proxy Agent</h2>

  <form method="post" action="{{ url_for('submit') }}">
    <p><strong>Proxy Mode:</strong><br>
      <label><input type="radio" name="mode" value="resolve" {% if mode=='resolve' %}checked{% endif %}> Resolve Only</label>
      <label><input type="radio" name="mode" value="ipqs" {% if mode!='resolve' %}checked{% endif %}> Resolve + IPQS</label>
    </p>

    <p><strong>Duplicate Handling:</strong><br>
      <label><input type="radio" name="dup_mode" value="drop_all" {% if dup_mode=='drop_all' %}checked{% endif %}> Drop all duplicates (strict)</label><br>
      <label><input type="radio" name="dup_mode" value="keep_one" {% if dup_mode=='keep_one' %}checked{% endif %}> Keep one per IP (show duplication count)</label><br>
      <label><input type="radio" name="dup_mode" value="keep_all" {% if dup_mode=='keep_all' %}checked{% endif %}> Keep all (no deduplication)</label>
    </p>

    <p><strong>IPQS API Key(s)</strong> <span style="color:#666">(ignored in Resolve Only)</span><br>
      <input type="password" name="api_key" style="width:400px" placeholder="Paste IPQS key(s), comma or whitespace separated"></p>

    <p><strong>Paste Proxies (one per line)</strong><br>
    <textarea name="proxies" rows="12" cols="100" placeholder="Supported: HOST:PORT, USER:PASS@HOST:PORT, HOST:PORT:USER:PASS, socks5://..."></textarea><br><br>
    <button class="btn" type="submit">Submit & Process</button>
    </p>
  </form>

  {% if note %}
    <div style="margin-top:10px;padding:8px;background:#f9f9f9;border:1px solid #eee;">{{ note|safe }}</div>
  {% endif %}

  {% if rows %}
    <h3>Results ({{ rows|length }})</h3>
    <table>
      <thead>
        <tr>
          <th>Proxy (HOST:PORT:USER:PASS)</th>
          <th>Resolved IP</th>
          <th>Country</th>
          <th>Proxy OK</th>
          <th>IPQS OK</th>
          <th>Fraud Score</th>
          <th>Verdict</th>
          <th>Message</th>
          <th>Duplicates</th>
        </tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td><code>{{ r.proxy_formatted }}</code></td>
          <td>{{ r.resolved_ip }}</td>
          <td>{{ r.country }}</td>
          <td>{{ r.proxy_ok }}</td>
          <td>{{ r.ipqs_success }}</td>
          <td>{{ r.fraud_score }}</td>
          <td>{{ r.verdict_icon | safe }}</td>
          <td>{{ r.ipqs_message }}</td>
          <td>{{ r.dup_count }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h3>Copy proxies with fraud score ≤ 28 (HOST:PORT:USER:PASS)</h3>
    <div>
      <button class="btn" type="button" onclick="copyLe28()">Copy to clipboard</button>
      <span style="color:#666">Format: <code>HOST:PORT:USER:PASS</code></span>
    </div>
    <textarea id="le28" rows="8" style="width:100%;max-width:1100px;">{{ copy_payload }}</textarea>
  {% endif %}

<script>
function copyLe28() {
  const ta = document.getElementById('le28');
  if (!ta) return;
  ta.select();
  ta.setSelectionRange(0, 999999);
  try {
    document.execCommand('copy');
    alert('Copied!');
  } catch (e) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(ta.value).then(()=>alert('Copied!'), ()=>alert('Copy failed'));
    } else {
      alert('Copy not supported in this browser.');
    }
  }
}
</script>
</body>
</html>
"""

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    mode = session.get("mode", "ipqs")
    dup_mode = session.get("dup_mode", "drop_all")
    return render_template_string(INDEX_HTML, rows=None, note=None, copy_payload="", mode=mode, dup_mode=dup_mode)

@app.route("/submit", methods=["POST"])
def submit():
    mode = request.form.get("mode", "ipqs")
    dup_mode = request.form.get("dup_mode", "drop_all")
    session["mode"] = mode
    session["dup_mode"] = dup_mode

    # Collect API keys if provided (space/comma separated)
    api_keys = [k.strip() for k in re.split(r"[\s,]+", (request.form.get("api_key") or "")) if k.strip()]
    text = request.form.get("proxies", "")

    if socks is None:
        return render_template_string(INDEX_HTML, rows=None, note="Missing PySocks. Run: <code>pip install \"requests[socks]\"</code>", copy_payload="", mode=mode, dup_mode=dup_mode)
    if not text.strip():
        return render_template_string(INDEX_HTML, rows=None, note="Please paste proxies.", copy_payload="", mode=mode, dup_mode=dup_mode)

    try:
        if mode == "resolve":
            rows, dropped_dupes, kept_count, copy_payload = resolve_only(text, dup_mode)
            note = f"[Resolve Only | Duplicates: {dup_mode.replace('_',' ').title()}] Removed {dropped_dupes} duplicates. Kept {kept_count} proxies."
        else:
            rows, dropped_dupes, kept_count, copy_payload = resolve_and_ipqs(api_keys, text, dup_mode)
            note = f"[Resolve + IPQS | Duplicates: {dup_mode.replace('_',' ').title()}] Removed {dropped_dupes} duplicates. Kept {kept_count} proxies."
    except Exception as e:
        logger.exception("Processing error")
        rows = [{
            "proxy_formatted": "",
            "resolved_ip": "",
            "country": "",
            "proxy_ok": "❌",
            "ipqs_success": "",
            "fraud_score": "",
            "verdict_icon": '<span style="color:#999">?</span>',
            "ipqs_message": f"Error: {e}",
            "dup_count": ""
        }]
        copy_payload = ""
        note = "There was an error during processing."

    return render_template_string(INDEX_HTML, rows=rows, note=note, copy_payload=copy_payload, mode=mode, dup_mode=dup_mode)

# ---------- Port fallback ----------
def find_free_port(preferred=5000, tries=10):
    for port in range(preferred, preferred + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No available port found in range.")

def start_app():
    preferred = int(os.environ.get("PORT", "5000"))
    try:
        app.run(host="127.0.0.1", port=preferred, debug=False, threaded=True)
    except OSError as e:
        logger.warning(f"Port {preferred} unavailable ({e}); trying next free port...")
        port = find_free_port(preferred + 1)
        logger.info(f"Running on next available port: {port}")
        app.run(host="127.0.0.1", port=port, debug=False, threaded=True)

if __name__ == "__main__":
    logger.info("Starting Proxy Agent (Unified format + DupCounts).")
    start_app()