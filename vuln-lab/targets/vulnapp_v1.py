#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 刻意含漏洞的練習靶場 — vulnapp v1（VULNERABLE 版本）
=============================================================================

 !!! 警告 !!!
 本程式「刻意」包含多個安全漏洞，僅供「本機、隔離環境、教育用途」使用。
 請勿部署到任何可被他人存取的網路位置。
 請勿將其中的任何技術用於未經授權的目標。

 對應報告章節：
   - CH06 第一階段（S1）：漏洞原理基礎 —— CWE 分類、Web 漏洞、資料流思維
   - CH06 第二階段（S2）：工具鏈 —— 靜態分析、執行驗證
   - CH08.3：自建靶場（零法律風險、完整掌控）

 設計原則：
   每個端點都有明確的「source（使用者輸入）→ sink（危險操作）」資料流，
   方便對照 CWE 編號與實際崩潰／外洩行為。

 本版包含的漏洞（對應 CWE）：
   V1  A01  SQL Injection ................ CWE-89
   V2  A03  Reflected XSS ................ CWE-79
   V3  A01  Path Traversal ............... CWE-22
   V4  A03  OS Command Injection ......... CWE-78
   V5  A04  Insecure Deserialization ..... CWE-502  （用 pickle 示範，見 /import）

 啟動方式：
   python vulnapp_v1.py            # 預設監聽 127.0.0.1:8080
   python vulnapp_v1.py 9090       # 指定埠號
=============================================================================
"""

import base64
import os
import pickle
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

# 靶場的「沙箱根目錄」：path traversal 練習只在此目錄內操作檔案。
LAB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
os.makedirs(LAB_ROOT, exist_ok=True)

# 示範用的機密檔（放在 sandbox 之外，用來證明 path traversal 可逃逸）
SECRET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SECRET_FOR_LAB.txt")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")


# ---------------------------------------------------------------------------
# 資料庫初始化
# ---------------------------------------------------------------------------
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret TEXT)"
    )
    rows = [
        (1, "alice", "user", "alice-not-a-secret"),
        (2, "bob", "user", "bob-not-a-secret"),
        (3, "admin", "admin", "FLAG{sql_injection_revealed_admin_secret}"),
    ]
    cur.executemany("INSERT INTO users VALUES (?,?,?,?)", rows)
    con.commit()
    con.close()


def init_secret():
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write("FLAG{path_traversal_escaped_the_sandbox}\n")


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>VulnLab v1 — 刻意含漏洞的練習靶場</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:900px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .warn{{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:22px}}
 .ep{{background:#f5f7fa;border:1px solid #e2e8f0;border-radius:10px;
     padding:14px 18px;margin:14px 0}}
 .ep h3{{margin:0 0 6px;font-size:16px;color:#1f4e79}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .out{{background:#fff;border:1px dashed #b8c4d4;padding:12px 16px;
      border-radius:8px;font-family:Consolas,monospace;font-size:13px;
      white-space:pre-wrap;margin-top:10px}}
</style></head><body>
<div class="warn"><b>⚠ 這是刻意含漏洞的教學靶場。</b>
僅限本機使用。所有漏洞都是設計好的學習素材，不是意外。</div>
<h1>VulnLab v1</h1>
<p>狀態：<b>{status}</b></p>
{body}
</body></html>"""

INDEX_BODY = """
<p>可用端點（每個都對應一個 CWE）：</p>

<div class="ep"><h3>V1 · SQL Injection — CWE-89</h3>
<p>Source: <code>?q=</code>｜Sink: 字串拼接的 SQL</p>
<pre>GET /search?q=alice</pre>
</div>

<div class="ep"><h3>V2 · Reflected XSS — CWE-79</h3>
<p>Source: <code>?name=</code>｜Sink: 未編碼直接輸出到 HTML</p>
<pre>GET /hello?name=World</pre>
</div>

<div class="ep"><h3>V3 · Path Traversal — CWE-22</h3>
<p>Source: <code>?file=</code>｜Sink: 未正規化的檔案路徑</p>
<pre>GET /file?file=readme.txt</pre>
</div>

<div class="ep"><h3>V4 · OS Command Injection — CWE-78</h3>
<p>Source: <code>?host=</code>｜Sink: shell=True 的 subprocess</p>
<pre>GET /ping?host=127.0.0.1</pre>
</div>

<div class="ep"><h3>V5 · Insecure Deserialization — CWE-502</h3>
<p>Source: <code>?d=</code>（base64 的 pickle 資料）｜Sink: pickle.loads</p>
<pre>GET /import?d=&lt;base64&gt;</pre>
</div>
"""


def render(status: str, body: str) -> bytes:
    return PAGE.format(status=status, body=body).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnLab/1.0"

    def _send(self, code: int, payload: bytes, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):  # 保留可審計軌跡
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    # ------------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        route = u.path

        if route == "/":
            return self._send(200, render("running", INDEX_BODY))

        # ---------------- V1: SQL Injection (CWE-89) --------------------
        # 漏洞點：把使用者輸入「字串拼接」進 SQL，沒有參數化。
        if route == "/search":
            term = qs.get("q", [""])[0]
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            sql = "SELECT id, username, role, secret FROM users WHERE username = '%s'" % term
            try:
                cur.execute(sql)
                rows = cur.fetchall()
                if not rows:
                    body = "<h2>/search</h2><p>查無結果。</p><pre>%s</pre>" % sql
                else:
                    body = "<h2>/search</h2><p>查詢：<code>%s</code></p><pre>%s</pre>" % (
                        sql,
                        "\n".join(" | ".join(str(c) for c in r) for r in rows),
                    )
            except Exception as e:
                body = "<h2>/search</h2><p>SQL 錯誤：</p><div class='out'>%s</div><pre>%s</pre>" % (
                    e,
                    sql,
                )
            finally:
                con.close()
            return self._send(200, render("running", body))

        # ---------------- V2: Reflected XSS (CWE-79) --------------------
        # 漏洞點：使用者輸入未經 HTML 編碼即寫入回應。
        if route == "/hello":
            name = qs.get("name", ["World"])[0]
            body = "<h2>/hello</h2><p>Hello, %s!</p>" % name  # 未轉義
            return self._send(200, render("running", body))

        # ---------------- V3: Path Traversal (CWE-22) -------------------
        # 漏洞點：未正規化、未限制在 LAB_ROOT 內。
        if route == "/file":
            fname = qs.get("file", ["readme.txt"])[0]
            path = os.path.join(LAB_ROOT, fname)  # 未做 realpath 邊界檢查
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                body = "<h2>/file</h2><p>讀取：<code>%s</code></p><pre>%s</pre>" % (path, content)
            except Exception as e:
                body = "<h2>/file</h2><p>讀取失敗：</p><div class='out'>%s</div>" % e
            return self._send(200, render("running", body))

        # ---------------- V4: Command Injection (CWE-78) ----------------
        # 漏洞點：shell=True 且未過濾輸入。
        if route == "/ping":
            host = qs.get("host", ["127.0.0.1"])[0]
            cmd = "ping -n 1 " + host  # Windows；Linux 請改 -c 1
            try:
                out = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=10
                ).stdout or subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=10
                ).stderr
            except Exception as e:
                out = "執行失敗: %s" % e
            body = "<h2>/ping</h2><p>指令：<code>%s</code></p><pre>%s</pre>" % (cmd, out)
            return self._send(200, render("running", body))

        # ---------------- V5: Insecure Deserialization (CWE-502) --------
        # 漏洞點：對使用者可控資料使用 pickle.loads。
        if route == "/import":
            d = qs.get("d", [""])[0]
            try:
                raw = base64.b64decode(d)
                obj = pickle.loads(raw)  # 危險：可執行任意程式碼
                body = "<h2>/import</h2><p>反序列化結果：</p><div class='out'>%s</div>" % obj
            except Exception as e:
                body = "<h2>/import</h2><p>失敗：</p><div class='out'>%s</div>" % e
            return self._send(200, render("running", body))

        return self._send(404, render("404", "<h2>404 Not Found</h2><p>%s</p>" % route))


def main():
    init_db()
    init_secret()
    with open(os.path.join(LAB_ROOT, "readme.txt"), "w", encoding="utf-8") as f:
        f.write("這是沙箱內的公開檔案，可以正常讀取。\n")

    print("=" * 68)
    print(" VulnLab v1 — 刻意含漏洞的練習靶場")
    print(" 僅限本機教育用途，請勿部署到可被他人存取的位置。")
    print("=" * 68)
    print(" 監聽位置 : http://%s:%d/" % (HOST, PORT))
    print(" 沙箱目錄 : %s" % LAB_ROOT)
    print(" 機密檔案 : %s  （在沙箱之外，用於驗證 path traversal）" % SECRET_FILE)
    print(" 資料庫   : %s" % DB_PATH)
    print("=" * 68)
    print(" 端點：/  /search?q=  /hello?name=  /file?file=  /ping?host=  /import?d=")
    print("=" * 68)

    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止] 靶場已關閉")
        httpd.server_close()


if __name__ == "__main__":
    main()
