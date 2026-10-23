#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 authlab_patched.py — A01 / A10 修補版靶場
=============================================================================

 對應研究報告 CH02.4「修補驗證」與 CH06 S1。

 本檔是 authlab.py 的修補版本，逐一修補 6 個漏洞。
 修補驗證的兩個必要條件（見 README.md 第三節）：
   ① 攻擊失效 —— 原本的攻擊輸入不再觸發
   ② 功能保留 —— 正常功能仍然可用

 修補對照（詳見 PATCH_GUIDE.md）：
   V1 IDOR 水平越權    → 授權條件放入 SQL 查詢
   V2 缺省允許         → 查無資料一律 404
   V3 錯誤訊息洩漏     → 通用訊息 + 錯誤代碼（詳細進內部日誌）
   V4 資源未釋放       → try/finally 確保釋放
   V5 未檢查回傳值     → 檢查回傳值 + 精確 except
   V6 fail-open 認證   → fail closed（例外時拒絕並回 503）

 用法：
   python authlab_patched.py 8902
=============================================================================
"""

import logging
import os
import sqlite3
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8902
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "authlab_patched.db")
LOG_PATH = os.path.join(BASE_DIR, "authlab_patched.log")

logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("authlab")

LOCK = threading.Lock()
OPEN_HANDLES = 0


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
            (201, 2, "bob-secrets", "bob 的私人內容（修補版仍可被 bob 自己讀取）", 0),
            (202, 2, "bob-notes", "bob 的私人筆記", 0),
            (301, 3, "admin-vault", "admin 專屬內容", 1),
        ],
    )
    con.commit()
    con.close()


def is_admin(uid):
    """輔助：查詢是否為 admin。"""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute("SELECT role FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
    finally:
        con.close()
    return bool(row and row[0] == "admin")


# ---------------------------------------------------------------------------
# V6 修補：fail closed
# ---------------------------------------------------------------------------
class PermissionServiceError(Exception):
    """權限服務不可用（與「無權限」明確區分）。"""


def check_permission(uid, doc_id):
    """修補版：例外時 fail closed（拋出 PermissionServiceError）。"""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        try:
            cur.execute(
                "SELECT owner_id, classified FROM documents WHERE id = ?", (doc_id,)
            )
            row = cur.fetchone()
        finally:
            con.close()

        if row is None:
            return False                    # 修補：查無資料 → 拒絕
        owner_id, classified = row
        if classified:
            return is_admin(uid)
        return owner_id == uid or is_admin(uid)
    except PermissionServiceError:
        raise
    except Exception as e:                  # noqa: BLE001
        # 修補：fail closed —— 不吞掉、不放行，明確拋出
        log.exception("permission check failed uid=%s doc=%s", uid, doc_id)
        raise PermissionServiceError("permission service unavailable") from e


# ---------------------------------------------------------------------------
# V5 修補：檢查回傳值
# ---------------------------------------------------------------------------
class ProfileNotFound(Exception):
    pass


def load_user_profile(user_id):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute("SELECT username, role, api_key FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()
    finally:
        con.close()


def render_profile(user_id):
    """修補版：檢查回傳值。"""
    profile = load_user_profile(user_id)
    if profile is None:
        raise ProfileNotFound("uid=%s" % user_id)
    return profile[0], profile[1], profile[2]


# ---------------------------------------------------------------------------
# V4 修補：try/finally 確保釋放
# ---------------------------------------------------------------------------
def process_document(doc_id, mode):
    global OPEN_HANDLES
    with LOCK:
        OPEN_HANDLES += 1
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write("process doc=%s mode=%s\n" % (doc_id, mode))
            if mode == "bad":
                raise ValueError("模擬處理失敗")
        return "ok"
    finally:
        with LOCK:
            OPEN_HANDLES -= 1


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>AuthLab (PATCHED)</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:900px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .ok{{background:#eefaf1;border-left:5px solid #2e9e5b;padding:12px 16px;
     border-radius:8px;font-size:14px;margin-bottom:20px}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
</style></head><body>
<div class="ok"><b>✓ 這是修補版。</b>
authlab.py 的 6 個漏洞都已修補；原本的攻擊輸入應全部失效，但正常功能仍可用。</div>
<h1>AuthLab (PATCHED)</h1>
{body}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthLab/2.0-patched"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[AuthLab-patched] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        uid_raw = qs.get("uid", [""])[0]
        uid = int(uid_raw) if uid_raw.isdigit() else None

        if path == "/":
            return self._respond(200,
                "<p>端點：/doc?uid=&doc=  /admin?uid=  /profile?uid=  /process?doc=&mode=</p>")

        # ---------------- V1 + V2 修補 --------------------------------
        if path == "/doc":
            doc = qs.get("doc", [""])[0]
            if not doc.isdigit():
                # V3 修補：不回顯原始例外
                err_id = uuid.uuid4().hex[:8]
                log.warning("invalid doc param=%r err_id=%s", doc, err_id)
                return self._respond(400, "<h2>參數錯誤</h2><p>錯誤代碼 %s</p>" % err_id)
            if uid is None:
                err_id = uuid.uuid4().hex[:8]
                log.warning("missing uid err_id=%s", err_id)
                return self._respond(400, "<h2>缺少 uid</h2><p>錯誤代碼 %s</p>" % err_id)

            # 修補 1：授權條件直接放入查詢（結構性防護）
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                cur.execute(
                    """SELECT id, owner_id, title, body, classified FROM documents
                       WHERE id = ? AND (owner_id = ? OR ? = 1)""",
                    (int(doc), uid, 1 if is_admin(uid) else 0),
                )
                row = cur.fetchone()
            finally:
                con.close()

            # 修補 2：查無資料與無權限回同一個 404（不洩漏存在性）
            if row is None:
                return self._respond(404, "<h2>找不到資源</h2>")

            doc_id, owner_id, title, body, classified = row
            return self._respond(200,
                "<h2>文件 %s</h2><p>擁有者 id=%s</p><pre>%s</pre>" % (doc_id, owner_id, body))

        # ---------------- V6 修補：fail closed -----------------------
        if path == "/admin":
            if uid is None:
                return self._respond(401, "<h2>未登入</h2>")
            try:
                allowed = check_permission(uid, 301)
            except PermissionServiceError:
                # 修補：服務故障明確回 503，而非放行
                return self._respond(503, "<h2>權限服務暫時無法使用</h2>")
            if allowed:
                return self._respond(200, "<h2>管理區</h2><p>uid=%s 已進入。</p>" % uid)
            return self._respond(404, "<h2>找不到資源</h2>")

        # ---------------- V5 修補：檢查回傳值 ------------------------
        if path == "/profile":
            if uid is None:
                return self._respond(400, "<h2>缺少 uid</h2>")
            try:
                name, role, key = render_profile(uid)
                return self._respond(200,
                    "<h2>個人資料</h2><pre>username=%s\nrole=%s</pre>" % (name, role))
            except ProfileNotFound:
                return self._respond(404, "<h2>找不到使用者</h2>")
            except Exception:
                log.exception("unexpected error uid=%s", uid)
                return self._respond(500, "<h2>系統錯誤</h2>")

        # ---------------- V4 修補：try/finally -----------------------
        if path == "/process":
            doc = qs.get("doc", ["101"])[0]
            mode = qs.get("mode", ["ok"])[0]
            try:
                r = process_document(doc, mode)
                return self._respond(200,
                    "<h2>處理完成</h2><pre>%s</pre><p>開啟中的資源：%d</p>" % (r, OPEN_HANDLES))
            except ValueError as e:
                # V3 修補：不回顯 traceback
                err_id = uuid.uuid4().hex[:8]
                log.warning("process failed doc=%s err_id=%s (%s)", doc, err_id, e)
                return self._respond(500,
                    "<h2>處理失敗</h2><p>錯誤代碼 %s</p><p>開啟中的資源：%d</p>"
                    % (err_id, OPEN_HANDLES))
            except Exception:
                log.exception("unexpected process error")
                return self._respond(500, "<h2>系統錯誤</h2>")

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    open(LOG_PATH, "a", encoding="utf-8").close()
    print("=" * 74)
    print(" AuthLab (PATCHED) — A01 / A10 修補版")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
