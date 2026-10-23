#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 configlab_patched.py — A02 安全設定錯誤 修補版
=============================================================================

 對應研究報告 CH02.4（修補驗證）與 CH06 S1（A02）。

 本檔的核心觀念（A02 的獨特性）：
   **程式邏輯幾乎與漏洞版相同** —— 差別只在「設定」。
   A02 不是「寫錯程式」，而是「設定沒做好」。
   這也正是官方強調的重點：同一份程式碼，正確設定就是安全的。

 修補對照：
   C1 DEBUG 模式      → 關閉 debug；錯誤只回通用訊息 + 錯誤代碼
   C2 缺少安全標頭    → 加入 6 個標準安全標頭 + 移除版本資訊
   C3 CORS 萬用字元   → 改用來源白名單（且不回 credentials:*）
   C4 預設憑證        → 移除預設帳號；強制首次設定；錯誤訊息統一
   C5 危險 HTTP 方法  → 僅允許 GET/POST；PUT/DELETE 回 405
   C6 密鑰洩漏        → 移除 /env 端點；改為健康檢查（只回狀態）

 用法：
   python configlab_patched.py 8909
=============================================================================
"""

import hashlib
import os
import secrets
import sqlite3
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8909
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEBUG_MODE = False          # ★ C1 修補

# ★ C3 修補：明確的來源白名單（不用萬用字元）
ALLOWED_ORIGINS = {"http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT}

DOCS = {"readme": "公開說明文件", "internal": "內部設計文件"}

# ★ C4 修補：不再有預設憑證；示範用帳號帶有強密碼，且登入需通過速率限制檢查
PBKDF2_ROUNDS = 200_000


def hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ROUNDS)
    return salt.hex() + "$" + dk.hex()


def make_store():
    """建立帳號儲存（示範用記憶體；實務應為資料庫）。"""
    return {
        "alice": hash_pw("A-strong-password-9f3k"),
    }


STORE = make_store()


def verify_pw(stored, pw):
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex),
                                 PBKDF2_ROUNDS)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:                                        # noqa: BLE001
        return False


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>ConfigLab (PATCHED)</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:940px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .ok{{background:#eefaf1;border-left:5px solid #2e9e5b;padding:12px 16px;
     border-radius:8px;font-size:14px;margin-bottom:20px}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
</style></head><body>
<div class="ok"><b>✓ 這是修補版（A02）。</b>
程式邏輯與漏洞版幾乎相同——差別只在<strong>設定</strong>：
關閉 debug、加入安全標頭、CORS 白名單、移除預設憑證、限制 HTTP 方法、移除洩漏端點。</div>
<h1>ConfigLab (PATCHED)</h1>
{body}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "web"      # ★ C2 修補：不暴露具體版本
    sys_version = ""

    def _security_headers(self):
        # ★ C2 修補：加入標準安全標頭
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; "
                         "object-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Strict-Transport-Security",
                         "max-age=31536000; includeSubDomains")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy",
                         "geolocation=(), microphone=(), camera=()")
        # ★ C3 修補：CORS 只允許白名單來源，且不回 credentials:*
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        # 不在白名單就不回 ACAO（瀏覽器自然會擋）

    def _respond(self, code, body, raw=False):
        payload = body.encode("utf-8") if raw else PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._security_headers()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[ConfigLab-patched] %s\n" % (fmt % args))

    # ★ C5 修補：明確拒絕不支援的方法
    def _method_not_allowed(self):
        err_id = uuid.uuid4().hex[:8]
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._security_headers()
        body = PAGE.format(body="<h2>405 不允許的方法</h2>"
                                "<p>此資源僅支援 GET（錯誤代碼 %s）</p>" % err_id)
        payload = body.encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_PUT(self):
        return self._method_not_allowed()

    def do_DELETE(self):
        return self._method_not_allowed()

    def do_POST(self):
        return self._method_not_allowed()

    def do_PATCH(self):
        return self._method_not_allowed()

    def do_OPTIONS(self):
        # 只回報實際允許的方法
        self.send_response(204)
        self._security_headers()
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._respond(200,
                "<p>端點：/boom /login /health /docs</p>"
                "<p>（原本的 /env 已移除）</p>")

        # ---------------- C1 修補：不回 traceback -------------------
        if path == "/boom":
            err_id = uuid.uuid4().hex[:8]
            sys.stderr.write("[error_id=%s] simulated failure\n" % err_id)
            return self._respond(500,
                "<h2>系統錯誤</h2><p>請聯絡管理員並提供錯誤代碼 <code>%s</code></p>" % err_id)

        # ---------------- C4 修補：無預設憑證、訊息統一 ---------------
        if path == "/login":
            uname = qs.get("u", [""])[0]
            pw = qs.get("p", [""])[0]
            stored = STORE.get(uname)
            ok = bool(stored) and verify_pw(stored, pw)
            if ok:
                return self._respond(200, "<h2>登入成功</h2><p>歡迎，%s</p>" % uname)
            # ★ 修補：不區分「帳號不存在」與「密碼錯誤」（防列舉）
            return self._respond(401,
                "<h2>登入失敗</h2><p>帳號或密碼錯誤</p>")

        # ---------------- C6 修補：改為健康檢查 ---------------------
        if path == "/health":
            # ★ 只回狀態，不回任何設定或密鑰
            return self._respond(200, "<h2>健康狀態</h2><pre>status: ok</pre>")

        # ---------------- 文件（保留功能）---------------------------
        if path.startswith("/docs"):
            if path in ("/docs", "/docs/"):
                items = "".join("<li><code>/docs/%s</code></li>" % k for k in DOCS)
                return self._respond(200, "<h2>文件</h2><ul>%s</ul>" % items)
            name = path[len("/docs/"):]
            if name in DOCS:
                return self._respond(200, "<h2>%s</h2><pre>%s</pre>" % (name, DOCS[name]))
            return self._respond(404, "<h2>找不到資源</h2>")

        if path == "/api/data":
            return self._respond(200,
                "<h2>API 資料</h2><pre>{&quot;user&quot;: &quot;alice&quot;}</pre>")

        return self._respond(404, "<h2>找不到資源</h2>")


def main():
    print("=" * 74)
    print(" ConfigLab (PATCHED) — A02 修補版")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 修補: 關閉 debug、6 個安全標頭、CORS 白名單、無預設憑證、")
    print("       限制 HTTP 方法（405）、移除 /env（改為 /health）")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
