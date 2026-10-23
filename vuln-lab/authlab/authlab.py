#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 authlab.py — A01 水平越權（IDOR）與 A10 fail-open 練習靶場
=============================================================================
 *
 *  !!! 警告 !!!
 *  本程式「刻意」包含 OWASP Top 10:2025 的 A01 與 A10 漏洞，
 *  僅供本機、隔離環境、教育用途。請勿部署到任何可被他人存取的位置。
 *
 *  對應研究報告 CH06 S1（OWASP Top 10:2025 練習缺口）：
 *    本專案原有靶場充分涵蓋 A05（注入）、A08（反序列化）、A10（CWE-209），
 *    但 A01（存取控制失效）與 A10 的 fail-open 完全未涵蓋。
 *    本檔補上這兩個缺口。
 *
 *  包含的漏洞：
 *    V1  IDOR 水平越權 .................. A01 / CWE-639
 *    V2  fail-open 認證 ................. A10 / CWE-636
 *    V3  未檢查回傳值 ................... A10 / CWE-252
 *    V4  資源未釋放（例外時） ........... A10 / CWE-460
 *    V5  錯誤訊息洩漏 ................... A10 / CWE-209
 *    V6  缺省允許（缺少預設拒絕） ....... A01 / CWE-862
 *
 *  用法：
 *    python authlab.py              # 預設 127.0.0.1:8080
 *    python authlab.py 8899
 * ============================================================================
"""

import json
import os
import re
import sqlite3
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "authlab.db")

# 模擬的「已登入使用者」（用 query 參數模擬 session，簡化練習）
# 真實系統用 cookie/token，但練習重點在授權判斷，故簡化。
LOCK = threading.Lock()
OPEN_HANDLES = 0          # V4：用於觀察資源洩漏


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS documents")
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, api_key TEXT)"
    )
    cur.execute(
        "CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT, classified INTEGER)"
    )
    cur.executemany(
        "INSERT INTO users VALUES (?,?,?,?)",
        [
            (1, "alice", "user", "ALICE_KEY_1111"),
            (2, "bob", "user", "BOB_KEY_2222"),
            (3, "admin", "admin", "ADMIN_KEY_9999"),
        ],
    )
    cur.executemany(
        "INSERT INTO documents VALUES (?,?,?,?,?)",
        [
            (101, 1, "alice-notes", "alice 的私人筆記", 0),
            (102, 1, "alice-plan", "alice 的計畫", 0),
            (201, 2, "bob-secrets", "FLAG{idor_read_bob_private_document}", 0),
            (202, 2, "bob-notes", "bob 的私人筆記", 0),
            (301, 3, "admin-vault", "FLAG{admin_classified_document}", 1),
        ],
    )
    con.commit()
    con.close()


def current_user(qs):
    """從 query 取得「目前使用者」（模擬 session）。"""
    uid = qs.get("uid", [""])[0]
    if uid.isdigit():
        return int(uid)
    return None


# ---------------------------------------------------------------------------
# V2：fail-open 認證（CWE-636）
#
# 漏洞點：當授權檢查「發生例外」時，程式選擇「放行」而不是「拒絕」。
#   - 真實情境：權限服務暫時不可用、資料庫逾時、設定檔讀取失敗
#   - 正確做法是 fail closed（例外 → 拒絕），而不是 fail open（例外 → 通過）
# ---------------------------------------------------------------------------
def check_permission_fail_open(user_id, doc_id):
    """回傳 True 表示允許。漏洞版：例外時回傳 True（fail open）。"""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT owner_id, classified FROM documents WHERE id = ?", (doc_id,))
        row = cur.fetchone()
        con.close()
        if row is None:
            # 文件不存在 → 這裡回傳 True 是另一個漏洞（缺省允許）
            return True
        owner_id, classified = row
        if classified:
            # 需要 admin：故意用一個「可能拋例外」的查詢模擬權限服務故障
            return user_id == 3
        return owner_id == user_id or user_id == 3
    except Exception:
        # ★ 漏洞點：fail open —— 檢查失敗時放行
        return True


# ---------------------------------------------------------------------------
# V3：未檢查回傳值（CWE-252）
#
# 漏洞點：呼叫一個可能失敗的函式，但沒有檢查其回傳值就繼續執行。
# ---------------------------------------------------------------------------
def load_user_profile(user_id):
    """模擬會失敗的查詢。回傳 None 表示失敗。"""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT username, role, api_key FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        con.close()
        return row
    except Exception:
        return None


def render_profile(user_id):
    """漏洞版：未檢查 load_user_profile 的回傳值。"""
    profile = load_user_profile(user_id)
    # ★ 漏洞點：沒有 if profile is None 的檢查
    # 正常情況下 None 會在下一行拋 TypeError，但若上層有寬鬆的 except，
    # 就會變成「看似成功但其實失敗」的操作（CWE-391 Unchecked Error Condition）
    return profile[0], profile[1], profile[2]     # noqa: E501


# ---------------------------------------------------------------------------
# V4：資源未釋放（CWE-460 Improper Cleanup on Thrown Exception）
#
# 漏洞點：開啟資源後，若中途拋出例外，資源沒有被關閉。
# ---------------------------------------------------------------------------
def process_document_leaky(doc_id, mode):
    """漏洞版：資源在例外路徑上不會被釋放。"""
    global OPEN_HANDLES
    f = open(os.path.join(BASE_DIR, "audit.log"), "a", encoding="utf-8")
    OPEN_HANDLES += 1
    f.write("process doc=%s mode=%s\n" % (doc_id, mode))
    if mode == "bad":
        # ★ 漏洞點：拋出例外，f 沒有 close()（沒有 try/finally）
        raise ValueError("模擬處理失敗")
    f.close()
    OPEN_HANDLES -= 1
    return "ok"


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>AuthLab — A01 / A10 練習靶場</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:900px;
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
<div class="warn"><b>⚠ 這是刻意含漏洞的教學靶場（A01 IDOR + A10 fail-open）。</b>
僅限本機使用。</div>
<h1>AuthLab</h1>
{body}
</body></html>"""

INDEX = """
<p>端點（每個對應 OWASP Top 10:2025 的類別）：</p>
<div class="ep"><h3>V1 · IDOR 水平越權 — A01 / CWE-639</h3>
<p>Source: <code>?uid=&amp;doc=</code>｜Sink: 未驗證擁有者即回傳文件</p>
<pre>GET /doc?uid=1&amp;doc=201      # alice 讀 bob 的文件</pre></div>

<div class="ep"><h3>V2 · fail-open 認證 — A10 / CWE-636</h3>
<p>權限檢查拋例外時「放行」而非「拒絕」</p>
<pre>GET /admin?uid=1              # 非 admin 也可能通過</pre></div>

<div class="ep"><h3>V3 · 未檢查回傳值 — A10 / CWE-252</h3>
<pre>GET /profile?uid=1</pre></div>

<div class="ep"><h3>V4 · 資源未釋放 — A10 / CWE-460</h3>
<pre>GET /process?doc=101&amp;mode=bad</pre></div>

<div class="ep"><h3>V5 · 錯誤訊息洩漏 — A10 / CWE-209</h3>
<pre>GET /doc?uid=abc&amp;doc=999</pre></div>

<div class="ep"><h3>V6 · 缺省允許 — A01 / CWE-862</h3>
<pre>GET /doc?uid=1&amp;doc=999        # 不存在的文件也可能回 200</pre></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthLab/1.0"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[AuthLab] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        uid = current_user(qs)

        if path == "/":
            return self._respond(200, INDEX)

        # ---------------- V1 修補對照：IDOR --------------------------
        if path == "/doc":
            doc = qs.get("doc", [""])[0]
            if not doc.isdigit():
                # V5：把原始例外回顯（CWE-209）
                return self._respond(500,
                    "<h2>錯誤</h2><pre>ValueError: invalid literal for int(): %r</pre>" % doc)
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            cur.execute("SELECT id, owner_id, title, body, classified FROM documents WHERE id = ?",
                        (int(doc),))
            row = cur.fetchone()
            con.close()

            if row is None:
                # V6：文件不存在卻回 200（缺省允許 / 資訊洩漏）
                return self._respond(200,
                    "<h2>文件</h2><p>查無 <code>%s</code> 的內容，但服務正常運作。</p>" % doc)

            doc_id, owner_id, title, body, classified = row
            # ★ V1 漏洞點：完全沒有驗證 uid 是否有權讀取 owner_id 的文件
            return self._respond(200,
                "<h2>文件 %s</h2><p>擁有者 id=%s</p><pre>%s</pre>" % (doc_id, owner_id, body))

        # ---------------- V2：fail-open 認證 -------------------------
        if path == "/admin":
            if uid is None:
                return self._respond(403, "<h2>未登入</h2>")
            allowed = check_permission_fail_open(uid, 301)
            if allowed:
                # ★ V2 漏洞點：非 admin 也可能因為 fail open 而進入
                return self._respond(200,
                    "<h2>管理區</h2><p>uid=%s 已進入管理區。</p><pre>FLAG{admin_vault_via_fail_open}</pre>" % uid)
            return self._respond(403, "<h2>拒絕</h2><p>權限不足。</p>")

        # ---------------- V3：未檢查回傳值 ---------------------------
        if path == "/profile":
            if uid is None:
                return self._respond(400, "<h2>缺少 uid</h2>")
            try:
                name, role, key = render_profile(uid)
                return self._respond(200,
                    "<h2>個人資料</h2><pre>username=%s\nrole=%s\napi_key=%s</pre>" % (name, role, key))
            except Exception:
                # ★ 寬鬆的 except 讓 CWE-252 變成「靜默失敗」
                return self._respond(200, "<h2>個人資料</h2><p>（無資料）</p>")

        # ---------------- V4：資源未釋放 -----------------------------
        if path == "/process":
            doc = qs.get("doc", ["101"])[0]
            mode = qs.get("mode", ["ok"])[0]
            try:
                r = process_document_leaky(doc, mode)
                return self._respond(200, "<h2>處理完成</h2><pre>%s</pre><p>開啟中的資源：%d</p>"
                                     % (r, OPEN_HANDLES))
            except Exception:
                # V5：把完整 traceback 回顯（CWE-209）
                return self._respond(500,
                    "<h2>處理失敗</h2><pre>%s</pre><p>開啟中的資源（未釋放）：%d</p>"
                    % (traceback.format_exc(), OPEN_HANDLES))

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    open(os.path.join(BASE_DIR, "audit.log"), "a", encoding="utf-8").close()
    print("=" * 74)
    print(" AuthLab — A01 IDOR + A10 fail-open 練習靶場")
    print(" 僅限本機教育用途")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 端點: /  /doc?uid=&doc=  /admin?uid=  /profile?uid=  /process?doc=&mode=")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
