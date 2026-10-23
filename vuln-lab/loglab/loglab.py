#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 loglab.py — A09 日誌與警報失效 練習靶場（對照組）
=============================================================================

 對應研究報告 CH06 S1（OWASP Top 10:2025 **A09 Security Logging and
 Alerting Failures**）。

 為什麼需要專門的靶場？
   先前所有靶場（authlab、authlab2、audit_target）都有日誌相關的缺口：
     - authlab.py    ：完全沒有 logging，登入失敗不留痕跡
     - authlab2.py   ：把失敗次數「顯示給攻擊者」，卻不寫入日誌
     - audit_target  ：有 log_message 但只記請求行，無安全事件
   → A09 的三個官方面向（無法偵測入侵／缺乏審計日誌／日誌本身不安全）
     在此檔中具體示範。

 ⚠ 刻意設計為「日誌與警報失效」的對照組，僅供本機教育用途。

 包含的漏洞（全部屬 A09）：
   L1  登入失敗不記錄（無偵測能力） ......... CWE-778
   L2  關鍵操作無審計日誌（無可歸責性） ...... CWE-778 / CWE-284
   L3  日誌含明文敏感資料（日誌本身洩漏） .... CWE-532
   L4  暴力破解無告警（無異常偵測） .......... CWE-778 / CWE-307
   L5  日誌檔無保護（可被攻擊者清除） ........ CWE-732
   L6  無關聯 ID（無法串連同一事件） ......... CWE-778

 用法：
   python loglab.py 8904
=============================================================================
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8904
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "loglab.db")
LOG_PATH = os.path.join(BASE_DIR, "loglab.log")
ALERT_PATH = os.path.join(BASE_DIR, "loglab_alerts.log")

LOGIN_FAILS = {}          # uid -> 次數（只用於回應，不用於告警）
LOG_READS = []            # 記錄讀取日誌的請求（L5 驗證用）


def md5_unsalted(pw):
    return hashlib.md5(pw.encode("utf-8")).hexdigest()


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("DROP TABLE IF EXISTS audit")
    cur.execute(
        "CREATE TABLE accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
        "password_hash TEXT, role TEXT)"
    )
    cur.executemany(
        "INSERT INTO accounts VALUES (?,?,?,?)",
        [
            (1, "alice", md5_unsalted("123456"), "user"),
            (2, "bob", md5_unsalted("password"), "user"),
            (3, "admin", md5_unsalted("admin"), "admin"),
        ],
    )
    # 審計表（L2：正確做法應該寫入，但漏洞版從不寫）
    cur.execute(
        "CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, "
        "actor TEXT, action TEXT, target TEXT, result TEXT)"
    )
    con.commit()
    con.close()


def log_write_vulnerable(msg):
    """L1/L3/L6：漏洞版日誌函式 —— 問題很多。

    問題 1：只記非安全性事件（呼叫點很少）
    問題 2：沒有時間戳以外的結構（無 actor/action/result）
    問題 3：沒有關聯 ID
    問題 4：會把敏感資料原樣寫入（由呼叫端決定，見 /login）
    問題 5：權限 644（任何人可讀）
    """
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>LogLab — A09 日誌與警報失效</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:920px;
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
<div class="warn"><b>⚠ 刻意設計為「日誌與警報失效」的對照組（A09）。</b>
僅限本機使用。帳號 alice/123456、admin/admin。</div>
<h1>LogLab (A09 對照組)</h1>
{body}
</body></html>"""

INDEX = """
<div class="ep"><h3>L1 · 登入失敗不記錄 — CWE-778</h3>
<pre>GET /login?u=alice&amp;p=wrong
然後觀察 GET /log        # 應該什麼都沒有</pre></div>
<div class="ep"><h3>L2 · 關鍵操作無審計 — CWE-778</h3>
<pre>GET /change_role?actor=alice&amp;target=admin&amp;role=user
然後 GET /audit          # 應該沒有記錄</pre></div>
<div class="ep"><h3>L3 · 日誌含明文敏感資料 — CWE-532</h3>
<pre>GET /login?u=alice&amp;p=MySecretPassword123
然後 GET /log            # 密碼會原樣出現</pre></div>
<div class="ep"><h3>L4 · 暴力破解無告警 — CWE-778</h3>
<pre>連續 GET /login?u=admin&amp;p=x0..x9
然後 GET /alerts         # 應該沒有告警</pre></div>
<div class="ep"><h3>L5 · 日誌檔無保護 — CWE-732</h3>
<pre>GET /log?clear=1         # 攻擊者可清除日誌</pre></div>
<div class="ep"><h3>L6 · 無關聯 ID — CWE-778</h3>
<pre># 每個事件都是獨立一行，無法串連攻擊鏈</pre></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LogLab/1.0"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        # 只記請求行（不含 actor / 結果 / 安全語意）—— 這本身也是一種 A09 缺口
        sys.stderr.write("[LogLab] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._respond(200, INDEX)

        # ---------------- L1 + L3 + L4：登入 -------------------------
        if path == "/login":
            uname = qs.get("u", [""])[0]
            pw = qs.get("p", [""])[0]
            LOGIN_FAILS[uname] = LOGIN_FAILS.get(uname, 0) + 1

            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                cur.execute(
                    "SELECT id, password_hash FROM accounts WHERE username = ?", (uname,)
                )
                row = cur.fetchone()
            finally:
                con.close()

            ok = bool(row and row[1] == md5_unsalted(pw))

            # ★ L1：登入失敗完全不寫日誌
            # ★ L3：登入成功時，把「帳號與密碼」原樣寫進日誌（明文敏感資料）
            if ok:
                log_write_vulnerable(
                    "login ok user=%s password=%s" % (uname, pw)   # ★ L3
                )
                return self._respond(200, "<h2>登入成功</h2><p>user=%s</p>" % uname)
            # 失敗時什麼都不記（L1）
            return self._respond(401,
                "<h2>登入失敗</h2><p>失敗次數：%d（僅顯示，未記錄、未告警）</p>"
                % LOGIN_FAILS[uname])

        # ---------------- L2：關鍵操作無審計 ------------------------
        if path == "/change_role":
            actor = qs.get("actor", [""])[0]
            target = qs.get("target", [""])[0]
            role = qs.get("role", [""])[0]
            if not actor or not target or role not in ("user", "admin"):
                return self._respond(400, "<h2>參數錯誤</h2>")
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                # ★ L2：直接改角色，不寫入 audit 表、也不記日誌
                cur.execute("UPDATE accounts SET role = ? WHERE username = ?",
                            (role, target))
                con.commit()
            finally:
                con.close()
            return self._respond(200,
                "<h2>角色已變更</h2><pre>actor=%s 把 %s 改成 %s</pre>"
                "<p>FLAG{a09_no_audit_trail}</p>" % (actor, target, role))

        # ---------------- L2 觀察：審計表 ---------------------------
        if path == "/audit":
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                cur.execute("SELECT COUNT(*) FROM audit")
                n = cur.fetchone()[0]
                cur.execute("SELECT ts, actor, action, target, result FROM audit")
                rows = cur.fetchall()
            finally:
                con.close()
            body = "<h2>審計表</h2><p>記錄數：<b>%d</b></p><pre>%s</pre>" % (
                n, "\n".join(str(r) for r in rows) or "（空）")
            return self._respond(200, body)

        # ---------------- L1/L3/L5 觀察：日誌 -----------------------
        if path == "/log":
            # ★ L5：允許攻擊者清除日誌（無任何授權檢查）
            if qs.get("clear", [""])[0] == "1":
                open(LOG_PATH, "w", encoding="utf-8").close()
                return self._respond(200, "<h2>日誌已清空</h2><p>（無授權檢查）</p>")
            content = ""
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            mode = oct(os.stat(LOG_PATH).st_mode & 0o777) if os.path.exists(LOG_PATH) else "N/A"
            body = ("<h2>日誌內容</h2><p>檔案權限：<code>%s</code></p><pre>%s</pre>"
                    % (mode, content or "（空）"))
            return self._respond(200, body)

        # ---------------- L4 觀察：告警 -----------------------------
        if path == "/alerts":
            content = ""
            if os.path.exists(ALERT_PATH):
                with open(ALERT_PATH, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            body = ("<h2>告警記錄</h2><pre>%s</pre>"
                    "<p>告警是否存在：<b>%s</b></p>"
                    % (content or "（無）", "是" if content.strip() else "否"))
            return self._respond(200, body)

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    # ★ L5：日誌檔權限 644（同機其他使用者可讀）
    open(LOG_PATH, "a", encoding="utf-8").close()
    try:
        os.chmod(LOG_PATH, 0o644)
    except Exception:                                        # noqa: BLE001
        pass
    # 告警檔刻意不存在（L4：從不產生告警）
    if os.path.exists(ALERT_PATH):
        os.remove(ALERT_PATH)

    print("=" * 74)
    print(" LogLab — A09 日誌與警報失效（對照組）")
    print(" 僅限本機教育用途")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 端點: /login /change_role /audit /log /alerts")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
