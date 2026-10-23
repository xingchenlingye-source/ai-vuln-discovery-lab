#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 webvulnlab.py — 整合靶場：補全剩餘 7 類缺口
=============================================================================

 對應 Bilibili 84 集課程的剩餘缺口（見 S1k 學習筆記）。

 涵蓋（原本完全未做的類別）：
   U  文件上傳漏洞（黑名單繞過 / 白名單 / 檔案頭） ...... CWE-434
   O  CORS 配置錯誤（內網探測 + 憑證洩漏） ............... CWE-942
   T  SSTI 服務端模板注入 ............................... CWE-1336
   Cr CRLF 注入（標頭注入） ............................ CWE-113
   R  URL 重定向（開放重導向） .......................... CWE-601
   J  JSONP 劫持（跨域資訊洩漏） ........................ CWE-346
   A  未授權訪問（系統化） .............................. CWE-862

 ⚠ 刻意含漏洞，僅供本機教育用途。
    · 上傳的「檔案」只寫入本機 uploads/ 目錄，且內容固定為無害字串
    · SSTI 模板只做無害運算（如 7*7），不執行系統指令
    · CORS / CRLF / 重定向 / JSONP 皆只在本機測試

 用法：
   python webvulnlab.py 8930
=============================================================================
"""

import html
import json
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8930
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ★ U：上傳黑名單（典型錯誤實作）
UPLOAD_BLACKLIST = [".php", ".jsp", ".asp", ".exe"]
# ★ U：允許的白名單（正確做法）
UPLOAD_WHITELIST = [".txt", ".png", ".jpg"]

UPLOADS = []

# ★ A：未授權訪問（無認證的內部端點）
INTERNAL_DATA = {
    "users": [{"id": 1, "name": "alice", "email": "alice@corp.local", "role": "user"},
              {"id": 99, "name": "admin", "email": "admin@corp.local", "role": "admin"}],
    "config": {"db_host": "10.0.0.5", "db_user": "app", "api_key": "sk-internal-FAKE-1234567890"},
}

# 模擬內網服務（CORS 內網探測目標）
INTERNAL_SERVICES = {
    "intranet.local": "FLAG{cors_internal_intranet}",
    "jenkins.local": "FLAG{cors_internal_jenkins}",
    "admin.local": "FLAG{cors_internal_admin}",
}


def jinja2_available():
    try:
        import jinja2  # noqa: F401
        return True
    except ImportError:
        return False


# ★ T：SSTI 用的模板引擎（若無 Jinja2 則用簡單替代）
def render_template_vulnerable(tpl, name):
    """★ 漏洞版：直接渲染使用者輸入。"""
    try:
        from jinja2 import Template
        return Template(tpl).render(name=name), "jinja2"
    except ImportError:
        # 後備：模擬常見模板語法（僅支援無害運算）
        out = tpl.replace("{{name}}", name)
        # 模擬 {{7*7}} 這種運算（只允許數字運算，不執行其他東西）
        def _eval(m):
            expr = m.group(1)
            if re.fullmatch(r"[\d\s\+\-\*/\(\)\.]+", expr):
                try:
                    return str(eval(expr, {"__builtins__": {}}, {}))
                except Exception:                            # noqa: BLE001
                    return m.group(0)
            return m.group(0)
        out = re.sub(r"\{\{(.+?)\}\}", _eval, out)
        return out, "fallback"


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>WebVulnLab — 剩餘缺口整合靶場</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:960px;
      margin:32px auto;line-height:1.7;color:#1b2430}}
 .warn{{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:18px}}
 .card{{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;
       margin:12px 0;background:#f8fafc}}
 h3{{margin:0 0 6px;font-size:16px;color:#1f4e79}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .pl{{background:#fff4e5;border-left:4px solid #e8a33d;padding:8px 12px;
     border-radius:6px;font-family:Consolas,monospace;font-size:13px;
     margin:6px 0;word-break:break-all}}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：刻意含 7 類漏洞。</b>
上傳僅寫入本機 <code>uploads/</code>；SSTI 僅做無害運算。僅限本機使用。</div>
<h1>WebVulnLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<div class="card"><h3>U · 文件上傳漏洞（CWE-434）</h3>
<pre>POST /upload        body: filename=shell.php&amp;content=TEST</pre>
<p>黑名單只擋 <code>.php/.jsp/.asp/.exe</code>——試試 <code>.pHp</code>、<code>.php5</code>、<code>.php%00.txt</code>。</p>
<p>安全對照：<code>POST /upload-safe</code>（白名單 + 內容檢查）</p></div>

<div class="card"><h3>O · CORS 配置錯誤（CWE-942）</h3>
<pre>GET /api/public    → 觀察 Access-Control-Allow-Origin
GET /api/private   → 反射 Origin 且允許憑證
GET /cors-probe?host=intranet.local   → 內網探測</pre></div>

<div class="card"><h3>T · SSTI 服務端模板注入（CWE-1336）</h3>
<pre>GET /greet?name={{7*7}}
GET /render?tpl={{7*7}}          # 直接渲染使用者模板</pre>
<p>安全對照：<code>GET /render-safe?tpl=...</code>（不渲染使用者輸入）</p></div>

<div class="card"><h3>Cr · CRLF 注入（CWE-113）</h3>
<pre>GET /setlang?lang=zh%0d%0aX-Injected:%20yes</pre>
<p>若回應出現 <code>X-Injected: yes</code> 標頭，代表換行符被注入標頭。</p></div>

<div class="card"><h3>R · URL 重定向（CWE-601）</h3>
<pre>GET /login?next=https://evil.example.com</pre>
<p>不檢查目標即 302 到任意外部網域。</p></div>

<div class="card"><h3>J · JSONP 劫持（CWE-346）</h3>
<pre>GET /api/user?callback=steal</pre>
<p>回傳 <code>steal({...})</code>——任意外站可讀取。</p></div>

<div class="card"><h3>A · 未授權訪問（CWE-862）</h3>
<pre>GET /api/internal/users
GET /api/internal/config</pre>
<p>內部 API 完全沒有認證。</p></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "WebVulnLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        # ★ O：CORS 相關標頭由各端點自行決定（見下）
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8", extra)

    def log_message(self, fmt, *args):
        pass          # 靜音，避免大量輸出

    # ---------------- GET ----------------
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        origin = self.headers.get("Origin", "")

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY))

        # ===== T：SSTI =====
        if path == "/greet":
            name = qs.get("name", ["guest"])[0]
            # ★ 漏洞：把使用者輸入放進模板再渲染
            tpl = "你好，%s！" % name
            out, eng = render_template_vulnerable(tpl, name)
            return self._send(200, PAGE.format(body=(
                "<h2>問候</h2><p>%s</p><p>引擎：%s</p>"
                "<p>FLAG{ssti_template_injection}</p>" % (out, eng))))

        if path == "/render":
            tpl = qs.get("tpl", [""])[0]
            if not tpl:
                return self._json({"error": "缺少 tpl"}, 400)
            out, eng = render_template_vulnerable(tpl, "guest")
            return self._json({"ok": True, "engine": eng, "tpl": tpl, "output": out,
                               "flag": "FLAG{ssti_arbitrary_template}"})

        if path == "/render-safe":
            tpl = qs.get("tpl", [""])[0]
            # 安全版：不渲染，只當純文字（並轉義）
            return self._json({"ok": True, "safe": True, "output": html.escape(tpl)})

        # ===== O：CORS =====
        if path == "/api/public":
            # 漏洞：萬用字元
            return self._json({"public": "ok"},
                              extra={"Access-Control-Allow-Origin": "*"})

        if path == "/api/private":
            # ★ 漏洞：反射任意 Origin + 允許憑證
            extra = {}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
                extra["Vary"] = "Origin"
            return self._json({"secret": "user-private-data",
                               "flag": "FLAG{cors_credentials_reflected}"}, extra=extra)

        if path == "/cors-probe":
            host = qs.get("host", ["intranet.local"])[0]
            # ★ 漏洞：以「內網主機」視角回應，可用 CORS 讀取
            served = INTERNAL_SERVICES.get(host, None)
            extra = {}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            return self._json({"ok": True, "probed_host": host,
                               "internal_content": served,
                               "flag": "FLAG{cors_internal_probe}" if served else None},
                              extra=extra)

        # ===== Cr：CRLF 注入 =====
        if path == "/setlang":
            lang = qs.get("lang", ["zh"])[0]
            # ★ 漏洞：把使用者輸入直接放進 Location 標頭
            #    （未過濾 \r\n → 可注入任意標頭）
            raw = "Set-Cookie: lang=%s; Path=/" % lang
            # 手動處理，讓換行真的進入標頭
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # 這裡刻意用原始寫法模擬「未過濾」的後果
            for line in raw.split("\r\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    try:
                        self.send_header(k.strip(), v.strip())
                    except Exception:                        # noqa: BLE001
                        pass
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # ===== R：URL 重定向 =====
        if path == "/login":
            nxt = qs.get("next", ["/"])[0]
            # ★ 漏洞：不檢查目標
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # ===== J：JSONP 劫持 =====
        if path == "/api/user":
            cb = qs.get("callback", [None])[0]
            data = {"id": 1, "name": "alice", "email": "alice@corp.local",
                    "token": "session-token-FAKE-abc123",
                    "flag": "FLAG{jsonp_data_leak}"}
            if cb:
                # ★ 漏洞：把 callback 原樣包進回應（未驗證字元）
                body = "%s(%s);" % (cb, json.dumps(data, ensure_ascii=False))
                return self._send(200, body,
                                  "application/javascript; charset=utf-8")
            return self._json(data)

        # ===== A：未授權訪問 =====
        if path == "/api/internal/users":
            return self._json({"flag": "FLAG{unauth_internal_users}",
                               "note": "此端點無任何認證",
                               "users": INTERNAL_DATA["users"]})
        if path == "/api/internal/config":
            return self._json({"flag": "FLAG{unauth_internal_config}",
                               "note": "此端點無任何認證",
                               "config": INTERNAL_DATA["config"]})

        return self._send(404, PAGE.format(body="<h2>404</h2>"))

    # ---------------- POST ----------------
    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        # ★ U：上傳（黑名單版本）
        if u.path == "/upload":
            try:
                data = json.loads(raw)
            except Exception:                                # noqa: BLE001
                data = {k: v[0] for k, v in parse_qs(raw).items()}
            fname = data.get("filename", "")
            content = data.get("content", "")
            if not fname:
                return self._json({"ok": False, "error": "缺少 filename"}, 400)

            base = fname.lower()
            # ★ 漏洞 1：黑名單只比對「小寫結尾」，可用大小寫繞過
            blocked = any(base.endswith(b) for b in UPLOAD_BLACKLIST)
            if blocked:
                return self._json({"ok": False, "error": "黑名單攔阻",
                                   "filename": fname}, 403)

            # ★ 漏洞 2：不看內容（MIME / magic bytes）
            # ★ 漏洞 3：不處理 `%00`、多重副檔名
            safe_name = fname.replace("/", "_").replace("\\", "_")
            path = os.path.join(UPLOAD_DIR, safe_name)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("# uploaded test file\n" + content)
            except Exception as e:                           # noqa: BLE001
                return self._json({"ok": False, "error": str(e)}, 500)

            UPLOADS.append(safe_name)
            return self._json({
                "ok": True, "filename": fname, "stored_as": safe_name,
                "path": path,
                "flag": "FLAG{upload_blacklist_bypass}",
                "note": "黑名單只做小寫結尾比對 → 可用大小寫／多重副檔名繞過",
                "checks_done": {"blacklist": "小寫結尾比對（可繞過）",
                                "content_type": "未檢查",
                                "magic_bytes": "未檢查"},
            })

        # 安全對照：白名單 + 內容檢查
        if u.path == "/upload-safe":
            try:
                data = json.loads(raw)
            except Exception:                                # noqa: BLE001
                data = {k: v[0] for k, v in parse_qs(raw).items()}
            fname = data.get("filename", "")
            content = data.get("content", "")
            ext = os.path.splitext(fname.lower())[1]
            if ext not in UPLOAD_WHITELIST:
                return self._json({"ok": False,
                                   "error": "副檔名不在白名單（%s）" % ext,
                                   "allowed": UPLOAD_WHITELIST}, 403)
            # 內容檢查：PNG magic bytes
            if ext == ".png" and not content.startswith("\x89PNG"):
                return self._json({"ok": False,
                                   "error": "內容與副檔名不符（缺少 PNG magic bytes）"}, 403)
            return self._json({"ok": True, "filename": fname,
                               "note": "通過白名單 + 內容檢查"})

        return self._json({"error": "not found"}, 404)

    def do_OPTIONS(self):
        """★ O：CORS 預檢（刻意寬鬆）。"""
        origin = self.headers.get("Origin", "")
        self.send_response(204)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             self.headers.get("Access-Control-Request-Headers", "*"))
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)
    print("=" * 78)
    print(" WebVulnLab — 剩餘缺口整合靶場（7 類）")
    print(" 僅限本機教育用途")
    print("=" * 78)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 上傳目錄: %s" % UPLOAD_DIR)
    print()
    print(" 端點速查：")
    print("   U  上傳      : POST /upload（黑名單）      POST /upload-safe（白名單）")
    print("   O  CORS      : /api/public  /api/private  /cors-probe?host=")
    print("   T  SSTI      : /greet?name={{7*7}}        /render?tpl={{7*7}}")
    print("   Cr CRLF      : /setlang?lang=zh%%0d%%0aX-Injected:%%20yes")
    print("   R  重定向    : /login?next=https://evil.example.com")
    print("   J  JSONP     : /api/user?callback=steal")
    print("   A  未授權    : /api/internal/users  /api/internal/config")
    print("=" * 78)
    print(" Jinja2 可用: %s（影響 SSTI 的引擎）" % jinja2_available())
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
