#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 修補版靶場 — vulnapp v2（PATCHED 版本）
=============================================================================

 這是 vulnapp_v1 的修補版本，逐一對應 v1 的 5 個漏洞。
 用途：示範 CH02.4 的「patch 驗證」與 CH06 S2 的「寫出正確修補」。

 驗證方式（必須兩個都通過才算修好）：
   條件 1：原攻擊輸入不再觸發漏洞（原 PoC 失效）
   條件 2：正常功能仍然可用（未破壞程式）

 修補對照表：
   V1  CWE-89  SQL Injection   → 參數化查詢（prepared statement）
   V2  CWE-79  Reflected XSS   → 輸出 HTML 編碼（html.escape）
   V3  CWE-22  Path Traversal  → realpath + 共同前綴邊界檢查
   V4  CWE-78  Command Inj.    → 關閉 shell + 白名單 + 參數陣列
   V5  CWE-502  Deserialization → 改用 JSON（拒絕 pickle）

 啟動：
   python vulnapp_v2.py 8766
=============================================================================
"""

import html
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8766

LAB_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "targets", "sandbox")
)
os.makedirs(LAB_ROOT, exist_ok=True)

SECRET_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "targets", "SECRET_FOR_LAB.txt"
)

DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "targets", "lab.db"
)

# 白名單：僅允許合法的檔案名稱樣式（不含路徑分隔符與 ..）
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_\-]+\.(txt|md|log)$")
# 白名單：僅允許 IPv4／IPv6 字面值
SAFE_HOST = re.compile(r"^[0-9a-fA-F:.]{1,45}$")


def init_db_if_needed():
    """若資料庫不存在則建立（修補版不主動 DROP，避免破壞 v1 的資料）。"""
    if os.path.exists(DB_PATH):
        return
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret TEXT)"
    )
    cur.executemany(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?)",
        [
            (1, "alice", "user", "alice-not-a-secret"),
            (2, "bob", "user", "bob-not-a-secret"),
            (3, "admin", "admin", "FLAG{sql_injection_revealed_admin_secret}"),
        ],
    )
    con.commit()
    con.close()


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>VulnLab v2 (PATCHED)</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:900px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .ok{{background:#eefaf1;border-left:5px solid #2e9e5b;padding:12px 16px;
     border-radius:8px;font-size:14px;margin-bottom:22px}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .out{{background:#fff;border:1px dashed #b8c4d4;padding:12px 16px;
      border-radius:8px;font-family:Consolas,monospace;font-size:13px;
      white-space:pre-wrap;margin-top:10px}}
</style></head><body>
<div class="ok"><b>✓ 這是修補版（v2）。</b>
所有 v1 的漏洞都已修補；原本的攻擊輸入應該全部失效，但正常功能仍可用。</div>
<h1>VulnLab v2 (PATCHED)</h1>
{body}
</body></html>"""


def render(body: str) -> bytes:
    return PAGE.format(body=body).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnLab/2.0-patched"

    def _send(self, code: int, payload: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        route = u.path

        if route == "/":
            body = "<p>端點：/search?q= /hello?name= /file?file= /ping?host= /import?d=</p>"
            return self._send(200, render(body))

        # ---------------- V1 修補：參數化查詢 -------------------------
        if route == "/search":
            term = qs.get("q", [""])[0]
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            # 修補點：使用參數化查詢，輸入永遠是「資料」而不是「語法」
            sql = "SELECT id, username, role, secret FROM users WHERE username = ?"
            try:
                cur.execute(sql, (term,))
                rows = cur.fetchall()
                if not rows:
                    body = "<h2>/search</h2><p>查無結果（輸入被視為純資料）。</p>"
                else:
                    # 修補點：查詢結果同樣做 HTML 編碼後才輸出
                    body = "<h2>/search</h2><pre>%s</pre>" % html.escape(
                        "\n".join(" | ".join(str(c) for c in r) for r in rows)
                    )
            except Exception as e:
                body = "<h2>/search</h2><p>查詢失敗。</p><div class='out'>%s</div>" % html.escape(str(e))
            finally:
                con.close()
            return self._send(200, render(body))

        # ---------------- V2 修補：輸出編碼 ---------------------------
        if route == "/hello":
            name = qs.get("name", ["World"])[0]
            # 修補點：輸出前做 HTML 編碼，標籤變成純文字
            body = "<h2>/hello</h2><p>Hello, %s!</p>" % html.escape(name)
            return self._send(200, render(body))

        # ---------------- V3 修補：路徑邊界檢查 -----------------------
        if route == "/file":
            fname = qs.get("file", ["readme.txt"])[0]
            # 修補點 1：白名單驗證檔名格式（阻擋 ../ 與路徑分隔符）
            if not SAFE_FILENAME.match(fname):
                body = "<h2>/file</h2><p>拒絕：檔名格式不符白名單。</p>"
                return self._send(200, render(body))
            path = os.path.realpath(os.path.join(LAB_ROOT, fname))
            # 修補點 2：正規化後確認仍在沙箱之下（防 symlink 與萬用字元繞過）
            if not (path == LAB_ROOT or path.startswith(LAB_ROOT + os.sep)):
                body = "<h2>/file</h2><p>拒絕：路徑超出允許範圍。</p>"
                return self._send(200, render(body))
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                body = "<h2>/file</h2><pre>%s</pre>" % html.escape(content)
            except Exception as e:
                body = "<h2>/file</h2><p>讀取失敗。</p><div class='out'>%s</div>" % html.escape(str(e))
            return self._send(200, render(body))

        # ---------------- V4 修補：關閉 shell + 白名單 -----------------
        if route == "/ping":
            host = qs.get("host", ["127.0.0.1"])[0]
            # 修補點 1：嚴格白名單
            if not SAFE_HOST.match(host):
                body = "<h2>/ping</h2><p>拒絕：僅允許 IP 位址格式。</p>"
                return self._send(200, render(body))
            # 修補點 2：再以 ipaddress 模組做語意驗證
            try:
                ipaddress.ip_address(host)
            except ValueError:
                body = "<h2>/ping</h2><p>拒絕：不是合法 IP 位址。</p>"
                return self._send(200, render(body))
            # 修補點 3：參數陣列 + shell=False（完全不經 shell 解析）
            try:
                proc = subprocess.run(
                    ["ping", "-n", "1", host],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                out = proc.stdout or proc.stderr
            except Exception as e:
                out = "執行失敗: %s" % e
            body = "<h2>/ping</h2><pre>%s</pre>" % html.escape(out)
            return self._send(200, render(body))

        # ---------------- V5 修補：改用 JSON --------------------------
        if route == "/import":
            d = qs.get("d", [""])[0]
            # 修補點：完全移除 pickle；只接受 JSON（純資料，無程式碼執行能力）
            try:
                obj = json.loads(d)  # 注意：v2 的參數改為直接傳 JSON 字串
                body = "<h2>/import</h2><p>解析結果（JSON）：</p><div class='out'>%s</div>" % html.escape(
                    json.dumps(obj, ensure_ascii=False)
                )
            except Exception as e:
                body = "<h2>/import</h2><p>拒絕：僅接受合法 JSON。</p><div class='out'>%s</div>" % html.escape(str(e))
            return self._send(200, render(body))

        return self._send(404, render("<h2>404 Not Found</h2>"))


def main():
    init_db_if_needed()
    print("=" * 68)
    print(" VulnLab v2 (PATCHED) — 修補版靶場")
    print("=" * 68)
    print(" 監聽位置 : http://%s:%d/" % (HOST, PORT))
    print(" 沙箱目錄 : %s" % LAB_ROOT)
    print("=" * 68)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止] 已關閉")
        httpd.server_close()


if __name__ == "__main__":
    main()
