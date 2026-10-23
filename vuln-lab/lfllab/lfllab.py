#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 lfllab.py — LFI（本機檔案包含）靶場
=============================================================================

 對應研究報告 CH06 S1 與 Natas natas7 的補強缺口。

 為什麼補這個？
   本專案有 SSRF（伺服器端請求）與文件上傳，但**沒有 LFI**——
   而 LFI 是 Web 滲透中最常見的檔案讀取途徑。
   OverTheWire natas7 就是用 `?page=/etc/natas_webpass/natas8` 直接讀取。

 ⚠ 刻意含漏洞，僅供本機教育用途。
    所有「敏感檔案」都是本機建立的模擬檔案，不涉及真實系統檔案。

 包含的漏洞：
   L1  基本 LFI（路徑穿越） ....................... CWE-22 / CWE-98
   L2  過濾 ../ 但可用 ....// 繞過 ................. CWE-22
   L3  副檔名強制加上 .php（可用 null byte/路徑穿越） CWE-22
   L4  php://filter 讀取原始碼 ..................... CWE-98
   L5  絕對路徑讀取 ................................ CWE-22

 安全對照：/safe 端點（白名單 + realpath 驗證）

 用法：
   python lfllab.py 8950
=============================================================================
"""

import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8950
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAGES_DIR = os.path.join(BASE_DIR, "pages")
SECRETS_DIR = os.path.join(BASE_DIR, "secrets")

# 白名單（安全對照用）
ALLOWED_PAGES = {"home.php", "about.php", "contact.php"}


def init_files():
    """建立模擬的頁面與敏感檔案。"""
    os.makedirs(PAGES_DIR, exist_ok=True)
    os.makedirs(SECRETS_DIR, exist_ok=True)

    pages = {
        "home.php": "<?php echo 'Welcome to Home'; ?>\n<h1>Home</h1><p>這是首頁。</p>",
        "about.php": "<?php echo 'About Us'; ?>\n<h1>About</h1><p>這是關於頁。</p>",
        "contact.php": "<?php echo 'Contact'; ?>\n<h1>Contact</h1><p>聯絡我們。</p>",
    }
    for name, content in pages.items():
        p = os.path.join(PAGES_DIR, name)
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

    secret = ("DB_PASSWORD=SuperSecretDbPass123\n"
              "API_KEY=sk-live-FAKE-0000-1111-2222\n"
              "ADMIN_TOKEN=FLAG{lfi_secret_file_read}\n"
              "SSH_KEY=-----BEGIN FAKE PRIVATE KEY-----\n")
    p = os.path.join(SECRETS_DIR, "config.txt")
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as f:
            f.write(secret)

    # 模擬「系統檔案」（僅本機）
    sysfile = os.path.join(SECRETS_DIR, "passwd.txt")
    if not os.path.exists(sysfile):
        with open(sysfile, "w", encoding="utf-8") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                    "FLAG{lfi_system_file_read}\n")


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>LfiLab — 本機檔案包含</title>
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
     border-radius:6px;font-family:Consolas,monospace;font-size:13px;margin:6px 0;
     word-break:break-all}}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：刻意含 LFI。</b>
所有「敏感檔案」都是本機建立的模擬檔案。僅限本機使用。</div>
<h1>LfiLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<p>這是一個典型的多頁網站，用 <code>?page=</code> 載入頁面。</p>
<div class="card"><h3>正常使用</h3>
<pre>/page?page=home.php
/page?page=about.php
/page?page=contact.php</pre></div>

<div class="card"><h3>L1 · 基本路徑穿越（CWE-22）</h3>
<div class="pl">?page=../secrets/config.txt</div></div>

<div class="card"><h3>L2 · 過濾 ../ 的繞過（CWE-22）</h3>
<div class="pl">?page=....//secrets/config.txt</div>
<p>（此關使用 <code>/page-filtered</code> 端點）</p>
<div class="pl">/page-filtered?page=....//secrets/config.txt</div>
<p>若程式只把 <code>../</code> 取代為空字串，<code>....//</code> 會還原成 <code>../</code>。</p></div>

<div class="card"><h3>L3 · 強制副檔名繞過（CWE-22）</h3>
<div class="pl">?page=../secrets/config.txt%00</div>
<p>舊版 PHP 的 null byte 截斷；或路徑穿越覆蓋 <code>.php</code> 後綴。</p></div>

<div class="card"><h3>L4 · php://filter 讀原始碼（CWE-98）</h3>
<div class="pl">?page=php://filter/convert.base64-encode/resource=home.php</div>
<p>可讀出 PHP 原始碼（而非執行結果）。</p></div>

<div class="card"><h3>L5 · 絕對路徑（CWE-22）</h3>
<div class="pl">?page=/secrets/passwd.txt</div></div>

<div class="card"><h3>安全對照</h3>
<pre>/safe?page=home.php    → 正常
/safe?page=../secrets/config.txt  → 應被阻擋</pre></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LfiLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass

    def _render(self, body_text):
        return self._send(200, PAGE.format(body=body_text))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._render(INDEX_BODY)

        # ===== 漏洞端點：/page =====
        if path == "/page":
            page = qs.get("page", ["home.php"])[0]
            if not page:
                return self._render("<h2>缺少 page 參數</h2>")

            # ★ L4：php://filter 支援（模擬）
            if page.startswith("php://filter"):
                m = re.search(r"resource=([^&]+)", page)
                res = m.group(1) if m else "home.php"
                target = os.path.join(PAGES_DIR, res)
                if os.path.exists(target):
                    with open(target, "r", encoding="utf-8", errors="replace") as f:
                        src = f.read()
                    import base64
                    b64 = base64.b64encode(src.encode()).decode()
                    return self._render(
                        "<h2>php://filter 輸出（base64）</h2><pre>%s</pre>"
                        "<p>解碼後即可讀出原始碼。</p>" % b64)
                return self._render("<h2>找不到資源</h2>")

            # ★ L1/L4/L5：直接串接路徑（**完全沒有過濾**）
            #   模擬「開發者直接把 $_GET['page'] 接到檔案路徑」
            if page.startswith("/"):
                target = os.path.join(BASE_DIR, page.lstrip("/"))
            else:
                target = os.path.join(PAGES_DIR, page)

            # ★ L3：自動加上 .php（若沒副檔名）
            if "." not in os.path.basename(target):
                target += ".php"

            # 正規化（這會把 ....// 變成 ../）
            target = os.path.normpath(target)

            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                # 偵測是否讀到敏感檔案
                flag = None
                m = re.search(r"FLAG\{[^}]+\}", content)
                if m:
                    flag = m.group(0)
                return self._render(
                    "<h2>頁面內容</h2><pre>%s</pre>%s"
                    % (content[:2500],
                       ("<p>★ 讀到敏感檔案：<code>%s</code></p>" % flag) if flag else ""))
            except FileNotFoundError:
                return self._render("<h2>404</h2><p>找不到頁面：%s</p>"
                                    % page.replace("<", "&lt;"))
            except Exception as e:                           # noqa: BLE001
                return self._render("<h2>錯誤</h2><pre>%s</pre>" % e)

        # ===== L2：有過濾的端點（可用 ....// 繞過）=====
        if path == "/page-filtered":
            page = qs.get("page", ["home.php"])[0]
            # ★ 錯誤的防護：把 "../" 取代為空
            #   但 "....//" 經過 replace 後會變成 "../" → 反而繞過
            filtered_page = page.replace("../", "")
            if filtered_page.startswith("/"):
                target = os.path.join(BASE_DIR, filtered_page.lstrip("/"))
            else:
                target = os.path.join(PAGES_DIR, filtered_page)
            target = os.path.normpath(target)
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                m = re.search(r"FLAG\{[^}]+\}", content)
                flag = m.group(0) if m else None
                return self._render(
                    "<h2>頁面內容（有過濾）</h2><pre>%s</pre>%s"
                    % (content[:2500],
                       ("<p>★ 讀到敏感檔案：<code>%s</code></p>" % flag) if flag else ""))
            except Exception:                                # noqa: BLE001
                return self._render("<h2>404</h2><p>找不到頁面</p>")

        # ===== 安全對照：/safe =====
        if path == "/safe":
            page = qs.get("page", ["home.php"])[0]
            # ① 白名單（只允許已存在的頁面名稱，不含路徑）
            base = os.path.basename(page)
            if base not in ALLOWED_PAGES:
                return self._render(
                    "<h2>403 拒絕</h2><p>頁面 <code>%s</code> 不在白名單中</p>"
                    "<p>允許的頁面：%s</p>" % (page.replace("<", "&lt;"),
                                              ", ".join(sorted(ALLOWED_PAGES))))
            target = os.path.join(PAGES_DIR, base)
            # ② realpath 驗證：確保解析後仍在 PAGES_DIR 內
            real = os.path.realpath(target)
            if not real.startswith(os.path.realpath(PAGES_DIR) + os.sep):
                return self._render("<h2>403 拒絕</h2><p>路徑穿越被阻擋</p>")
            try:
                with open(real, "r", encoding="utf-8", errors="replace") as f:
                    return self._render("<h2>頁面內容（安全版）</h2><pre>%s</pre>"
                                        % f.read()[:2000])
            except Exception:                                # noqa: BLE001
                return self._render("<h2>404</h2>")

        return self._render("<h2>404</h2>")


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)
    init_files()
    print("=" * 78)
    print(" LfiLab — 本機檔案包含（補強 Natas natas7 缺口）")
    print(" 僅限本機教育用途；所有敏感檔案皆為本機模擬檔")
    print("=" * 78)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print()
    print(" 頁面目錄  : %s" % PAGES_DIR)
    print(" 敏感目錄  : %s" % SECRETS_DIR)
    print()
    print(" 練習：")
    print("   L1 基本穿越 : /page?page=../secrets/config.txt")
    print("   L2 過濾繞過 : /page?page=....//secrets/config.txt")
    print("   L3 副檔名   : /page?page=../secrets/config.txt")
    print("   L4 filter   : /page?page=php://filter/convert.base64-encode/resource=home.php")
    print("   L5 絕對路徑 : /page?page=/secrets/config.txt")
    print("   安全對照    : /safe?page=../secrets/config.txt（應被阻擋）")
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
