#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 authlab2.py — A07 認證失效 + A01 垂直越權 練習靶場
=============================================================================
 *
 *  !!! 警告 !!!
 *  本程式「刻意」包含 OWASP Top 10:2025 的 A07 與 A01 漏洞，
 *  僅供本機、隔離環境、教育用途。
 *
 *  補足 authlab.py 未涵蓋的部分：
 *    A07 Authentication Failures —— 原本完全未涵蓋
 *    A01 垂直越權（privilege escalation）—— 原本只做水平越權
 *
 *  包含的漏洞：
 *    W1  弱密碼雜湊（無 salt 的 MD5） ....... A02/A04 / CWE-916
 *    W2  使用者列舉（錯誤訊息不一致） ....... A07 / CWE-204
 *    W3  無速率限制（可暴力破解） ........... A07 / CWE-307
 *    W4  會話固定（登入後不換 session id） ... A07 / CWE-384
 *    W5  過期會話仍有效（無逾時） ........... A07 / CWE-613
 *    W6  登出未真正失效（僅前端清除） ....... A07 / CWE-613
 *    W7  垂直越權（改 role 參數即變 admin） .. A01 / CWE-269
 *
 *  用法：
 *    python authlab2.py 8903
 * ============================================================================
"""

import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8903
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "authlab2.db")

# 會話表（記憶體）：sid -> {uid, created}
SESSIONS = {}
LOGIN_ATTEMPTS = {}          # username -> 失敗次數（W3 觀察用）


def md5_unsalted(pw: str) -> str:
    """W1：無 salt 的 MD5（弱雜湊）。"""
    return hashlib.md5(pw.encode("utf-8")).hexdigest()


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute(
        "CREATE TABLE accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
        "password_hash TEXT, role TEXT, email TEXT)"
    )
    # 刻意使用極弱的密碼
    rows = [
        (1, "alice", md5_unsalted("123456"), "user", "alice@example.com"),
        (2, "bob", md5_unsalted("password"), "user", "bob@example.com"),
        (3, "admin", md5_unsalted("admin"), "admin", "admin@example.com"),
    ]
    cur.executemany("INSERT INTO accounts VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()


def verify_login(username, password):
    """回傳 (ok, uid, reason)。"""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, password_hash FROM accounts WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if row is None:
        return False, None, "no_such_user"          # ★ W2：與密碼錯誤區分
    if row[1] == md5_unsalted(password):
        return True, row[0], "ok"
    return False, None, "bad_password"              # ★ W2：訊息不同


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>AuthLab2 — A07 / A01 垂直越權</title>
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
<div class="warn"><b>⚠ 刻意含漏洞的教學靶場（A07 認證失效 + A01 垂直越權）。</b>
僅限本機使用。帳號為 alice/123456、bob/password、admin/admin。</div>
<h1>AuthLab2</h1>
{body}
</body></html>"""

INDEX = """
<div class="ep"><h3>W1 · 弱密碼雜湊 — CWE-916</h3>
<p>資料庫內為無 salt 的 MD5。觀察：<code>GET /shadow</code></p></div>
<div class="ep"><h3>W2 · 使用者列舉 — CWE-204</h3>
<pre>GET /login?u=nobody&amp;p=x     → "no_such_user"
GET /login?u=alice&amp;p=wrong   → "bad_password"</pre></div>
<div class="ep"><h3>W3 · 無速率限制 — CWE-307</h3>
<pre>GET /login?u=alice&amp;p=猜錯        # 可無限次嘗試</pre></div>
<div class="ep"><h3>W4 · 會話固定 — CWE-384</h3>
<pre>GET /preset?sid=FIXED123&amp;u=admin   # 預設 sid，登入後不變</pre></div>
<div class="ep"><h3>W5 · 過期會話仍有效 — CWE-613</h3>
<pre>GET /whoami?sid=&lt;舊 sid&gt;          # 無逾時檢查</pre></div>
<div class="ep"><h3>W6 · 登出未真正失效 — CWE-613</h3>
<pre>GET /logout?sid=&lt;sid&gt; 然後再用同一 sid 存取</pre></div>
<div class="ep"><h3>W7 · 垂直越權 — CWE-269</h3>
<pre>GET /update_role?uid=1&amp;role=admin   # 無授權檢查即可改角色</pre></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthLab2/1.0"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[AuthLab2] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._respond(200, INDEX)

        # ---------------- W1：洩漏雜湊（示範弱雜湊可被查表還原）--------
        if path == "/shadow":
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            cur.execute("SELECT id, username, password_hash, role FROM accounts")
            rows = cur.fetchall()
            con.close()
            body = "<h2>accounts 表</h2><pre>%s</pre>" % "\n".join(
                "%s | %s | %s | %s" % r for r in rows)
            return self._respond(200, body)

        # ---------------- W2 + W3：登入（使用者列舉、無速率限制）------
        if path == "/login":
            uname = qs.get("u", [""])[0]
            pw = qs.get("p", [""])[0]
            LOGIN_ATTEMPTS[uname] = LOGIN_ATTEMPTS.get(uname, 0) + 1
            ok, uid, reason = verify_login(uname, pw)
            if ok:
                # ★ W4：登入後不重新產生 session id（沿用既有或新開但可預測）
                sid = qs.get("sid", [None])[0] or secrets.token_hex(4)
                SESSIONS[sid] = {"uid": uid, "created": time.time()}
                return self._respond(200,
                    "<h2>登入成功</h2><p>sid=<code>%s</code></p><p>嘗試次數：%d</p>"
                    % (sid, LOGIN_ATTEMPTS[uname]))
            # ★ W2：錯誤訊息區分「使用者不存在」與「密碼錯誤」
            return self._respond(401,
                "<h2>登入失敗</h2><p>原因：<code>%s</code></p><p>嘗試次數：%d（無速率限制）</p>"
                % (reason, LOGIN_ATTEMPTS[uname]))

        # ---------------- W4：會話固定（可預先指定 sid）--------------
        if path == "/preset":
            sid = qs.get("sid", ["FIXED123"])[0]
            uid = qs.get("u", ["1"])[0]
            SESSIONS[sid] = {"uid": int(uid), "created": time.time()}
            return self._respond(200,
                "<h2>已預設會話</h2><p>sid=<code>%s</code> uid=%s</p>" % (sid, uid))

        # ---------------- W5：無逾時檢查 ----------------------------
        if path == "/whoami":
            sid = qs.get("sid", [""])[0]
            s = SESSIONS.get(sid)
            if s is None:
                return self._respond(401, "<h2>無效會話</h2>")
            age = time.time() - s["created"]
            # ★ W5：完全沒有檢查 age，過期會話永遠有效
            return self._respond(200,
                "<h2>已登入</h2><p>uid=%s</p><p>會話已存在 %.1f 秒（無逾時）</p>"
                % (s["uid"], age))

        # ---------------- W6：登出未真正失效 ------------------------
        if path == "/logout":
            sid = qs.get("sid", [""])[0]
            # ★ W6：只從回應中「假裝」登出，實際上沒有刪除 SESSIONS[sid]
            #    正確做法：del SESSIONS[sid]
            return self._respond(200,
                "<h2>已登出（僅前端）</h2><p>sid=<code>%s</code> 仍在伺服器端有效</p>" % sid)

        # ---------------- W7：垂直越權 ------------------------------
        if path == "/update_role":
            uid = qs.get("uid", [""])[0]
            role = qs.get("role", [""])[0]
            if not uid.isdigit() or role not in ("user", "admin"):
                return self._respond(400, "<h2>參數錯誤</h2>")
            # ★ W7：完全沒有檢查「請求者是否為 admin」
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            cur.execute("UPDATE accounts SET role = ? WHERE id = ?", (role, int(uid)))
            con.commit()
            con.close()
            return self._respond(200,
                "<h2>角色已更新</h2><pre>uid=%s → role=%s</pre>"
                "<p>FLAG{vertical_privilege_escalation}</p>" % (uid, role))

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    print("=" * 74)
    print(" AuthLab2 — A07 認證失效 + A01 垂直越權 練習靶場")
    print(" 僅限本機教育用途")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 帳號: alice/123456  bob/password  admin/admin")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
