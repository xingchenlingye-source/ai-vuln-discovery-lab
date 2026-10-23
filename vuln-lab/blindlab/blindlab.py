#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 blindlab.py — 「無回饋」情境的資訊洩漏靶場（盲注）
=============================================================================

 對應研究報告 CH06 S1 與 Natas natas15 / natas17 的補強缺口。

 為什麼補這個？
   本專案目前只有「有回饋」的注入靶場（錯誤訊息、資料輸出）。
   但真實世界更常見的是**完全沒有回饋**的情境——
   這時只能靠「是非題」甚至「時間差」來推導資料。
   OverTheWire natas15（布林盲注）與 natas17（time-based）正是此類。

 包含的漏洞：
   B1  SQL 布林盲注 ............ CWE-89
       · 回應只有 "exists" / "doesn't exist"（是非題）
       · 攻擊者用二分搜尋 ASCII 逐字元推導
   B2  time-based 盲注 ......... CWE-89
       · 回應**完全相同**（連是非題都沒有）
       · 唯一訊號是回應時間（SLEEP）
   B3  錯誤訊息洩漏（對照）...... CWE-209
       · 顯示 SQL 錯誤 → 洩漏結構
   B4  安全對照：參數化查詢 ...... 防護
       · 完全無法注入

 ⚠ 刻意含漏洞，僅供本機教育用途。
    使用本機 SQLite，資料為模擬。

 用法：
   python blindlab.py 8960
=============================================================================
"""

import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8960
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blind.db")

# 目標密碼（真實情境中是資料庫裡的機密）
SECRET = "FLAG{blind_sqli_leaked_secret_2026}"

PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>BlindLab — 無回饋情境的資訊洩漏</title>
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
 .ok{{background:#e8f5e9;border-left:4px solid #43a047;padding:8px 12px;
     border-radius:6px;font-size:13px;margin:6px 0}}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：刻意含盲注漏洞。</b>
使用本機 SQLite，資料為模擬。僅限本機使用。</div>
<h1>BlindLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<p>這四個端點展示「<b>無回饋</b>」情境下如何洩漏資訊。</p>

<div class="card"><h3>B1 · SQL 布林盲注（CWE-89）</h3>
<pre>GET /b1?username=admin
  → "This user exists." / "This user doesn't exist."

# 是非題 oracle：
GET /b1?username=admin' AND 1=1 --
GET /b1?username=admin' AND 1=2 --</pre>
<p>攻擊者用二分成是是非題，逐字元猜出機密。</p></div>

<div class="card"><h3>B2 · time-based 盲注（CWE-89）</h3>
<pre>GET /b2?username=admin
  → 回應**完全相同**（沒有任何文字差異）

# 唯一訊號是時間：
GET /b2?username=admin' AND CASE WHEN (1=1) THEN sleep(1) ELSE 0 END --</pre>
<p>連「是非題」都沒有，只能靠回應變慢與否。</p></div>

<div class="card"><h3>B3 · 錯誤訊息洩漏（CWE-209）</h3>
<pre>GET /b3?username=x'
  → 直接印出 SQL 錯誤</pre></div>

<div class="card"><h3>B4 · 安全對照：參數化查詢</h3>
<pre>GET /safe?username=admin' AND 1=1 --
  → 無法注入（整個字串被當作使用者名稱）</pre>
<div class="ok">✓ 參數化查詢（prepared statement）從根本上阻止注入</div></div>
"""


def init_db():
    """建立資料庫。"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
              ("admin", SECRET))
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
              ("guest", "guest-pass-not-secret"))
    c.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT)")
    c.execute("INSERT INTO secrets (name, value) VALUES (?, ?)", ("api_key", SECRET))
    conn.commit()
    conn.close()


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    # ★ B2：註冊 sleep 函式（time-based 用）
    conn.create_function("sleep", 1, lambda x: time.sleep(float(x)) or 0)
    return conn


class Handler(BaseHTTPRequestHandler):
    server_version = "BlindLab/1.0"

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

        # ===== B1：布林盲注（只有是非題）=====
        if path == "/b1":
            username = qs.get("username", [""])[0]
            if not username:
                return self._render("<h2>B1 布林盲注</h2><p>需要 username 參數</p>")
            # ★ 漏洞：字串拼接
            query = "SELECT * FROM users WHERE username='%s'" % username
            try:
                conn = get_conn()
                c = conn.cursor()
                c.execute(query)
                rows = c.fetchall()
                conn.close()
                # ★ 只回傳存在/不存在（沒有任何資料）
                if rows:
                    return self._render("<h2>B1</h2><p>This user exists.</p>")
                return self._render("<h2>B1</h2><p>This user doesn't exist.</p>")
            except Exception as e:                           # noqa: BLE001
                return self._render("<h2>B1</h2><p>Error in query.</p>")

        # ===== B2：time-based 盲注（完全無文字差異）=====
        if path == "/b2":
            username = qs.get("username", [""])[0]
            if not username:
                return self._render("<h2>B2 time-based</h2><p>需要 username 參數</p>")
            query = "SELECT * FROM users WHERE username='%s'" % username
            try:
                conn = get_conn()
                c = conn.cursor()
                c.execute(query)
                c.fetchall()
                conn.close()
            except Exception:                                # noqa: BLE001
                pass
            # ★ 完全相同的回應（沒有任何 True/False 差異）
            return self._render("<h2>B2</h2><p>查詢已執行。</p>")

        # ===== B3：錯誤訊息洩漏 =====
        if path == "/b3":
            username = qs.get("username", [""])[0]
            if not username:
                return self._render("<h2>B3 錯誤洩漏</h2><p>需要 username 參數</p>")
            query = "SELECT * FROM users WHERE username='%s'" % username
            try:
                conn = get_conn()
                c = conn.cursor()
                c.execute(query)
                c.fetchall()
                conn.close()
                return self._render("<h2>B3</h2><p>查詢成功。</p>")
            except Exception as e:                           # noqa: BLE001
                # ★ 漏洞：把**完整 SQL 與錯誤**原樣回傳（洩漏表名/欄位）
                return self._render(
                    "<h2>B3</h2><p>資料庫錯誤：</p>"
                    "<pre>Query: %s\nError: %s</pre>"
                    "<p>可看出：表格名稱 users、欄位 username、以及確切的語法位置</p>"
                    % (query.replace("<", "&lt;"), str(e).replace("<", "&lt;")))

        # ===== B4：安全對照（參數化查詢）=====
        if path == "/safe":
            username = qs.get("username", [""])[0]
            if not username:
                return self._render("<h2>B4 安全版</h2><p>需要 username 參數</p>")
            # ★ 正確：參數化查詢
            try:
                conn = get_conn()
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username=?", (username,))
                rows = c.fetchall()
                conn.close()
                if rows:
                    return self._render("<h2>B4 安全版</h2><p>This user exists.</p>")
                return self._render("<h2>B4 安全版</h2><p>This user doesn't exist.</p>")
            except Exception:                                # noqa: BLE001
                return self._render("<h2>B4 安全版</h2><p>查詢失敗（但無注入）</p>")

        return self._render("<h2>404</h2>")


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)
    init_db()
    print("=" * 78)
    print(" BlindLab — 「無回饋」情境的資訊洩漏（盲注）")
    print(" 僅限本機教育用途；SQLite 資料為模擬")
    print("=" * 78)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 資料庫: %s" % DB_PATH)
    print()
    print(" 練習：")
    print("   B1 布林盲注 : /b1?username=admin' AND 1=1 --")
    print("                 /b1?username=admin' AND 1=2 --")
    print("   B2 時間盲注 : /b2?username=admin' AND CASE WHEN (1=1)")
    print("                     THEN sleep(1) ELSE 0 END --")
    print("   B3 錯誤洩漏 : /b3?username=x'")
    print("   B4 安全對照 : /safe?username=admin' AND 1=1 --")
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
