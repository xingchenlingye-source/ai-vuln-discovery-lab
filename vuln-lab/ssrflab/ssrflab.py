#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 ssrflab.py — SSRF 靶場（補足課程最大模組 + OWASP A10/SSRF）
=============================================================================

 對應研究報告 CH06 S1 與 OWASP Top 10:2025（SSRF 相關 CWE-918）。

 為什麼這是重大缺口？
   課程用了 **10 集**講 SSRF（P20–P22、P44–P50），是本專案完全沒有的類別。
   在雲環境下，SSRF 是**首要風險**之一——因為雲端 metadata 端點
   （169.254.169.254）常能直接取得**臨時憑證**，等同接管雲帳號。

 ⚠ 安全邊界（本靶場嚴格遵守）
   · 只監聽 127.0.0.1
   · 「內部服務」也是本機的另一個埠（8926），**不出本機、不連網際網路**
   · 模擬的 metadata 是**本機假端點**，不是真的雲端服務
   · 所有 URL 只指向 127.0.0.1

 架構：
    ┌─────────────────┐  SSRF   ┌──────────────────────┐
    │ 主應用 :8925     │ ──────▶ │ 內部服務 :8926        │
    │ GET /fetch?url= │         │  · /internal/admin   │
    └─────────────────┘         │  · /latest/meta-data │
                                 └──────────────────────┘

 包含的問題：
   S1  完全無 SSRF 防護（可直接打內網） ........ CWE-918
   S2  白名單可用 @ 與大小寫繞過 ............... CWE-918
   S3  可用 302 重導向繞過驗證 ................. CWE-918
   S4  雲端 metadata 可讀取（取得憑證） ........ CWE-918 / CWE-522
   S5  內部服務無認證（內網橫向移動） .......... CWE-306

 用法：
   python ssrflab.py 8925 8926        # 主應用埠、內部服務埠
=============================================================================
"""

import json
import os
import re
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8925
INTERNAL_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8926
INTERNAL_BASE = "http://%s:%d" % (HOST, INTERNAL_PORT)

# 本機測試用的假網域（透過 Host 標頭模擬，不實際解析 DNS）
FAKE_PUBLIC_HOST = "public.example.com"

# ★ S2：漏洞版白名單（可用 @ 與大小寫繞過）
ALLOWED_HOSTS_VULN = ["public.example.com"]

# 模擬的雲端憑證（假值，僅供教學）
FAKE_CREDENTIALS = {
    "Code": "Success",
    "AccessKeyId": "ASIAFAKEEXAMPLE123456",
    "SecretAccessKey": "FakeSecretKeyForTeachingPurposesOnly000000",
    "Token": "FakeSessionTokenEXAMPLE",
    "Expiration": "2026-10-16T00:00:00Z",
}

PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>SSRFLab — 伺服器端請求偽造</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:940px;
      margin:32px auto;line-height:1.7;color:#1b2430}}
 .warn{{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:18px}}
 .card{{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;
       margin:12px 0;background:#f8fafc}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .pl{{background:#fff4e5;border-left:4px solid #e8a33d;padding:8px 12px;
     border-radius:6px;font-family:Consolas,monospace;font-size:13px;
     margin:6px 0;word-break:break-all}}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：刻意含 SSRF。</b>
所有 URL 僅指向 <b>本機</b>（內部服務在 127.0.0.1:8926）；
模擬的 metadata 是<b>本機假端點</b>，不涉及任何真實雲端服務。僅限本機使用。</div>
<h1>SSRFLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<p>主應用提供一個「抓取外部網址」的功能（這是 SSRF 的典型入口）。</p>

<div class="card"><h3>主應用端點</h3>
<pre>GET /fetch?url=&lt;網址&gt;        # 抓取網址內容（漏洞點）
GET /fetch-safe?url=&lt;網址&gt;   # 安全對照（有防護）
GET /redirect?to=&lt;網址&gt;       # 302 重導向（用於繞過示範）</pre>
</div>

<div class="card"><h3>內部服務（應該只有內網能存取）</h3>
<pre>%s/internal/admin        # 內部管理頁（無認證）
%s/latest/meta-data/     # 模擬雲端 metadata
%s/latest/meta-data/iam/security-credentials/   # 模擬臨時憑證</pre>
</div>

<div class="card"><h3>練習：五種 SSRF 手法</h3>
<div class="pl">S1 直接打內網：/fetch?url=%s/internal/admin</div>
<div class="pl">S2 白名單繞過：/fetch?url=http://public.example.com@%s/internal/admin</div>
<div class="pl">S3 重導向繞過：/fetch?url=%s/redirect?to=%s/internal/admin</div>
<div class="pl">S4 讀取雲端憑證：/fetch?url=%s/latest/meta-data/iam/security-credentials/</div>
<div class="pl">S5 內網橫向：用 S1 發現的內部服務繼續探測</div>
</div>
"""


# ---------------------------------------------------------------------------
# SSRF 防護邏輯（漏洞版 vs 安全版）
# ---------------------------------------------------------------------------
def is_private_ip(host):
    """判斷是否為私有／內部位址。"""
    try:
        ip = socket.gethostbyname(host)
    except Exception:                                        # noqa: BLE001
        return True                       # 解析失敗 → 視為不安全
    parts = [int(x) for x in ip.split(".")]
    if parts[0] == 127:
        return True
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 169 and parts[1] == 254:      # link-local（雲端 metadata）
        return True
    if ip == "0.0.0.0":
        return True
    return False


def check_url_vulnerable(url):
    """★ 漏洞版：幾乎沒檢查。

    只做一個「看起來有防護」的字串比對——
    可以用 @ 分隔、大小寫、重導向等方式繞過。
    """
    m = re.match(r"^https?://([^/]+)", url, re.I)
    if not m:
        return False, "必須是 http/https URL"
    host_part = m.group(1)
    # ★ 典型錯誤實作：用 startswith 檢查白名單
    for allowed in ALLOWED_HOSTS_VULN:
        if host_part.startswith(allowed):
            return True, "通過白名單"
    # 更糟的是：只要不是「明顯內網」就放行
    if "169.254" in url:
        return False, "禁止 metadata 位址"
    return True, "未命中任何規則 → 放行（這是漏洞）"


def check_url_safe(url):
    """安全版：解析真實主機 + 阻擋私有位址 + 禁止重導向。"""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False, "僅允許 http/https"
    host = p.hostname
    if not host:
        return False, "缺少主機名稱"
    if is_private_ip(host):
        return False, "禁止存取私有／內部位址"
    if host not in ALLOWED_HOSTS_VULN:
        return False, "主機不在白名單"
    return True, "通過"


def fetch(url, allow_redirect=True, timeout=6):
    """實際發出請求（限制在本機，避免失控）。"""
    req = urllib.request.Request(url, headers={
        "User-Agent": "SSRFLab/1.0",
        "Host": urlparse(url).hostname or "",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, dict(r.headers), body, None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace"), None
    except Exception as e:                                   # noqa: BLE001
        return -1, {}, "", "%s: %s" % (type(e).__name__, e)


# ---------------------------------------------------------------------------
# 內部服務
# ---------------------------------------------------------------------------
INTERNAL_PAGE = """<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8">
<title>內部服務</title><style>body{{font-family:system-ui;margin:28px;line-height:1.7}}
code{{background:#eef2f7;padding:2px 6px;border-radius:4px}}
pre{{background:#1e2733;color:#e6edf3;padding:12px;border-radius:8px;overflow-x:auto}}
.warn{{background:#fdecea;border-left:5px solid #c0392b;padding:10px 14px;border-radius:8px}}
</style></head><body>
<div class="warn"><b>這是「內部服務」——正常情況下不應從外部存取。</b></div>
<h1>Internal Service</h1>
{body}</body></html>"""


class InternalHandler(BaseHTTPRequestHandler):
    server_version = "InternalService/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8")

    def log_message(self, fmt, *args):
        sys.stderr.write("[Internal] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path

        if path == "/":
            return self._send(200, INTERNAL_PAGE.format(body=(
                "<p>內部服務運行中。</p><ul>"
                "<li><code>/internal/admin</code></li>"
                "<li><code>/latest/meta-data/</code></li>"
                "<li><code>/latest/meta-data/iam/security-credentials/</code></li>"
                "<li><code>/health</code></li></ul>")))

        # ★ S5：內部管理頁（無認證）
        if path == "/internal/admin":
            return self._send(200, INTERNAL_PAGE.format(body=(
                "<h2>內部管理頁</h2>"
                "<p>FLAG{ssrf_internal_admin_access}</p>"
                "<pre>服務：internal-api\n環境：prod-internal\n"
                "資料庫：postgres://app:InternalPass123@10.0.0.5:5432/prod\n"
                "Redis  ：redis://10.0.0.6:6379\n"
                "備註  ：本頁設計為『僅內網可存取』，無任何認證</pre>")))

        # ★ S4：模擬雲端 metadata
        if path == "/latest/meta-data/":
            return self._send(200,
                "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\n"
                "placement/\nsecurity-groups\n", "text/plain; charset=utf-8")

        if path == "/latest/meta-data/iam/security-credentials/":
            return self._send(200, "SSRFLab-EC2-Role\n", "text/plain; charset=utf-8")

        if path.startswith("/latest/meta-data/iam/security-credentials/"):
            return self._json(FAKE_CREDENTIALS)

        if path == "/latest/meta-data/hostname":
            return self._send(200, "ip-10-0-0-7.internal\n", "text/plain; charset=utf-8")

        if path == "/latest/meta-data/local-ipv4":
            return self._send(200, "10.0.0.7\n", "text/plain; charset=utf-8")

        if path == "/health":
            return self._json({"status": "ok", "service": "internal-api"})

        return self._send(404, INTERNAL_PAGE.format(body="<h2>404</h2>"))


# ---------------------------------------------------------------------------
# 主應用
# ---------------------------------------------------------------------------
class MainHandler(BaseHTTPRequestHandler):
    server_version = "SSRFLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8")

    def log_message(self, fmt, *args):
        sys.stderr.write("[SSRFLab] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY % (
                INTERNAL_BASE, INTERNAL_BASE, INTERNAL_BASE,
                INTERNAL_BASE, INTERNAL_BASE, INTERNAL_BASE,
                INTERNAL_BASE, INTERNAL_BASE)))

        # ★ S1/S2/S3/S4：SSRF 漏洞端點
        if path == "/fetch":
            url = qs.get("url", [""])[0]
            if not url:
                return self._json({"error": "缺少 url 參數"}, 400)
            ok, why = check_url_vulnerable(url)
            if not ok:
                return self._json({"ok": False, "reason": why, "url": url}, 403)
            st, hdr, body, err = fetch(url)
            return self._json({
                "ok": True, "url": url, "check": why,
                "status": st,
                "content": body if body else "",   # 保留完整內容（否則 FLAG 會被截斷）
                "error": err,
                "flag": ("FLAG{ssrf_internal_admin_access}" if "FLAG{ssrf" in body
                         else ("FLAG{ssrf_metadata_credentials}" if "AccessKeyId" in body
                               else None)),
            })

        # 安全對照
        if path == "/fetch-safe":
            url = qs.get("url", [""])[0]
            if not url:
                return self._json({"error": "缺少 url 參數"}, 400)
            ok, why = check_url_safe(url)
            if not ok:
                return self._json({"ok": False, "reason": why, "url": url}, 403)
            st, hdr, body, err = fetch(url)
            return self._json({"ok": True, "url": url, "check": why,
                               "status": st, "content": body, "error": err})

        # ★ S3：開放重導向（用於繞過）
        if path == "/redirect":
            to = qs.get("to", [""])[0]
            if not to:
                return self._json({"error": "缺少 to 參數"}, 400)
            self.send_response(302)
            self.send_header("Location", to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        return self._send(404, PAGE.format(body="<h2>404</h2>"))


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 本靶場僅允許綁定 127.0.0.1")
        sys.exit(2)

    internal = ThreadingHTTPServer((HOST, INTERNAL_PORT), InternalHandler)
    t = threading.Thread(target=internal.serve_forever, daemon=True)
    t.start()

    print("=" * 78)
    print(" SSRFLab — 伺服器端請求偽造（補足課程最大模組）")
    print(" 僅限本機；內部服務亦在本機；metadata 為假端點")
    print("=" * 78)
    print(" 主應用   : http://%s:%d/" % (HOST, PORT))
    print(" 內部服務 : %s  ← 正常不應從外部存取" % INTERNAL_BASE)
    print()
    print(" 練習 URL（複製到瀏覽器）：")
    print("   S1 直接打內網 : /fetch?url=%s/internal/admin" % INTERNAL_BASE)
    print("   S2 白名單繞過 : /fetch?url=http://public.example.com@%s/internal/admin"
          % INTERNAL_BASE.replace("http://", ""))
    print("   S3 重導向繞過 : /fetch?url=%s/redirect?to=%s/internal/admin"
          % (INTERNAL_BASE, INTERNAL_BASE))
    print("   S4 雲端憑證   : /fetch?url=%s/latest/meta-data/iam/security-credentials/"
          % INTERNAL_BASE)
    print("   安全對照      : /fetch-safe?url=%s/internal/admin" % INTERNAL_BASE)
    print("=" * 78)

    main_srv = ThreadingHTTPServer((HOST, PORT), MainHandler)
    try:
        main_srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        main_srv.server_close()
        internal.shutdown()


if __name__ == "__main__":
    main()
