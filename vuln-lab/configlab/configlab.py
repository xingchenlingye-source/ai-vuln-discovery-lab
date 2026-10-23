#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 configlab.py — A02 安全設定錯誤 練習靶場
=============================================================================

 對應研究報告 CH06 S1（OWASP Top 10:2025 **A02 Security Misconfiguration**）。

 為什麼要專門做這一類？
   A02 在 2025 版**從第 5 名躍升至第 2 名**，但它是唯一「部分涵蓋」的類別。
   更關鍵的是：A02 的漏洞**幾乎都不是「寫錯程式」，而是「設定沒做好」**——
   同一份程式碼，只要設定正確就是安全的。
   這使它的驗證方式也與眾不同（見下）。

 ⚠ 刻意含設定缺陷，僅供本機教育用途。

 包含的問題：
   C1  DEBUG 模式開啟（洩漏堆疊追蹤與原始碼路徑） ... A02 / CWE-489
   C2  缺少安全標頭（CSP / X-Content-Type-Options 等）A02 / CWE-693
   C3  CORS 萬用字元（配合 credentials 更嚴重） ..... A02 / CWE-942
   C4  預設憑證未變更（admin/admin） ............... A02 / CWE-1392
   C5  允許危險 HTTP 方法（PUT / DELETE） .......... A02 / CWE-749
   C6  環境變數與設定洩漏（含密鑰） ................ A02 / CWE-200

 用法：
   python configlab.py 8908
=============================================================================
"""

import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8908
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ★ C6：把「機密」直接放在程式碼／環境中，且可被端點讀出
FAKE_SECRETS = {
    "DATABASE_URL": "postgres://app:SuperSecret123@db.internal:5432/prod",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "JWT_SECRET": "dev-secret-do-not-use-in-prod",
    "STRIPE_KEY": "sk_live_EXAMPLE0000000000000000",
}

# ★ C4：預設憑證未變更
DEFAULT_USERS = {"admin": "admin", "root": "root", "guest": "guest"}

DEBUG_MODE = True          # ★ C1

# 示範用的「資料」
DOCS = {"readme": "公開說明文件", "internal": "內部設計文件（不應公開）"}


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>ConfigLab — A02 安全設定錯誤</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:940px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .warn{{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:20px}}
 .ep{{background:#f5f7fa;border:1px solid #e2e8f0;border-radius:10px;
     padding:14px 18px;margin:12px 0}}
 .ep h3{{margin:0 0 6px;font-size:16px;color:#1f4e79}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
</style></head><body>
<div class="warn"><b>⚠ 刻意含「設定缺陷」的教學靶場（A02）。</b>
注意：本靶場的程式碼本身幾乎沒有錯——問題全在設定。僅限本機使用。</div>
<h1>ConfigLab (A02)</h1>
{body}
</body></html>"""

INDEX = """
<div class="ep"><h3>C1 · DEBUG 模式開啟 — CWE-489</h3>
<pre>GET /boom            # 回傳完整堆疊追蹤與檔案路徑</pre></div>
<div class="ep"><h3>C2 · 缺少安全標頭 — CWE-693</h3>
<pre>GET /                # 觀察回應標頭（無 CSP、無 X-Content-Type-Options）</pre></div>
<div class="ep"><h3>C3 · CORS 萬用字元 — CWE-942</h3>
<pre>GET /api/data        # Access-Control-Allow-Origin: * 且允許 credentials</pre></div>
<div class="ep"><h3>C4 · 預設憑證未變更 — CWE-1392</h3>
<pre>GET /login?u=admin&amp;p=admin</pre></div>
<div class="ep"><h3>C5 · 允許危險 HTTP 方法 — CWE-749</h3>
<pre>PUT /docs/readme     # 未限制方法，可直接覆寫</pre></div>
<div class="ep"><h3>C6 · 設定與密鑰洩漏 — CWE-200</h3>
<pre>GET /env             # 直接輸出環境與密鑰</pre></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ConfigLab/1.0"
    sys_version = ""            # 連同 server_version 一起暴露版本資訊（A02 常見問題）

    # ★ C2：完全不加任何安全標頭
    def _headers_common(self):
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # ★ C3：CORS 萬用字元 + 允許 credentials（這個組合特別危險）
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

    def _respond(self, code, body, raw=False):
        payload = body.encode("utf-8") if raw else PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self._headers_common()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[ConfigLab] %s\n" % (fmt % args))

    # ★ C5：沒有 do_PUT/do_DELETE 的「不允許」處理，而是直接實作它們
    def do_OPTIONS(self):
        self.send_response(204)
        self._headers_common()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        u = urlparse(self.path)
        if u.path.startswith("/docs/"):
            name = u.path[len("/docs/"):]
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            DOCS[name] = body
            return self._respond(200,
                "<h2>已覆寫</h2><pre>%s = %s</pre><p>FLAG{a02_unsafe_http_method}</p>"
                % (name, body))
        return self._respond(404, "<h2>404</h2>")

    def do_DELETE(self):
        u = urlparse(self.path)
        if u.path.startswith("/docs/"):
            name = u.path[len("/docs/"):]
            DOCS.pop(name, None)
            return self._respond(200, "<h2>已刪除 %s</h2>" % name)
        return self._respond(404, "<h2>404</h2>")

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._respond(200, INDEX)

        # ---------------- C1：DEBUG 模式（堆疊追蹤 + 原始碼路徑）--------
        if path == "/boom":
            try:
                _ = 1 / 0
            except ZeroDivisionError:
                if DEBUG_MODE:
                    # ★ C1：把完整 traceback 回給使用者（含本機檔案路徑與行號）
                    return self._respond(500,
                        "<h2>Internal Server Error（DEBUG 模式）</h2><pre>%s</pre>"
                        % traceback.format_exc())
                return self._respond(500, "<h2>系統錯誤</h2>")

        # ---------------- C4：預設憑證（含使用者列舉）------------------
        if path == "/login":
            uname = qs.get("u", [""])[0]
            pw = qs.get("p", [""])[0]
            if uname in DEFAULT_USERS and DEFAULT_USERS[uname] == pw:
                return self._respond(200,
                    "<h2>登入成功</h2><pre>user=%s\nrole=%s</pre>"
                    "<p>FLAG{a02_default_credentials}</p>"
                    % (uname, "admin" if uname in ("admin", "root") else "user"))
            # ★ C4 附帶：錯誤訊息區分帳號是否存在
            if uname in DEFAULT_USERS:
                return self._respond(401, "<h2>登入失敗</h2><p>密碼錯誤</p>")
            return self._respond(401, "<h2>登入失敗</h2><p>使用者不存在</p>")

        # ---------------- C6：設定與密鑰洩漏 --------------------------
        if path == "/env":
            data = {
                "server": {"debug": DEBUG_MODE, "python": sys.version.split()[0],
                           "cwd": BASE_DIR, "argv": sys.argv},
                "environment": dict(os.environ),
                "secrets": FAKE_SECRETS,          # ★ C6：機密直接輸出
                "config": {"default_users": DEFAULT_USERS},
            }
            return self._respond(200,
                "<h2>環境與設定</h2><pre>%s</pre>"
                "<p>FLAG{a02_config_leak}</p>" % json.dumps(data, ensure_ascii=False, indent=2))

        # ---------------- C5 觀察：文件 ---------------------------------
        if path.startswith("/docs"):
            if path == "/docs" or path == "/docs/":
                # ★ C2 附帶：目錄列表（Directory Listing）
                items = "".join("<li><code>/docs/%s</code> — %s</li>" % (k, v[:20])
                                for k, v in DOCS.items())
                return self._respond(200, "<h2>文件列表（Directory Listing 開啟）</h2><ul>%s</ul>" % items)
            name = path[len("/docs/"):]
            if name in DOCS:
                return self._respond(200, "<h2>%s</h2><pre>%s</pre>" % (name, DOCS[name]))
            return self._respond(404, "<h2>404</h2>")

        # ---------------- C3 觀察：API ---------------------------------
        if path == "/api/data":
            return self._respond(200,
                "<h2>API 資料</h2><pre>{&quot;user&quot;: &quot;alice&quot;, "
                "&quot;email&quot;: &quot;alice@example.com&quot;}</pre>")

        return self._respond(404, "<h2>404</h2>")


def main():
    print("=" * 74)
    print(" ConfigLab — A02 安全設定錯誤 練習靶場")
    print(" 僅限本機教育用途")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 端點: / /boom /login /env /docs /api/data  (PUT/DELETE 亦可)")
    print(" ⚠ 本靶場的程式碼本身幾乎沒錯——問題全在設定")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
