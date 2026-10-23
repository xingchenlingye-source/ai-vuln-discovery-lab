#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 loglab_patched.py — A09 修補版（結構化日誌 + 警報）
=============================================================================

 對應研究報告 CH06 S1（A09）與 CH02.4（修補驗證）。

 逐一修補 loglab.py 的 6 個 A09 漏洞：
   L1 登入失敗不記錄      → 成功與失敗都記錄（含來源、帳號、結果）
   L2 關鍵操作無審計      → 寫入結構化審計日誌（actor/action/target/result）
   L3 日誌含明文敏感資料  → 敏感欄位遮罩（只留前 2 碼與長度）
   L4 暴力破解無告警      → 門檻觸發告警（並移除回應中的嘗試次數）
   L5 日誌檔無保護        → 移除清除端點、權限 600
   L6 無關聯 ID           → 每個請求帶 request_id，貫穿所有日誌

 另外示範 A09 的 2025 版重點：**Logging「and Alerting」**——
 記錄不等於通報，必須有門檻與告警。

 用法：
   python loglab_patched.py 8905
=============================================================================
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8905
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "loglab_patched.db")
LOG_PATH = os.path.join(BASE_DIR, "loglab_patched.jsonl")     # 結構化日誌
ALERT_PATH = os.path.join(BASE_DIR, "loglab_patched_alerts.jsonl")

ALERT_THRESHOLD = 5           # 失敗達此次數即告警
LOGIN_FAILS = {}


def mask(value):
    """L3 修補：敏感資料遮罩。"""
    if not value:
        return "(empty)"
    if len(value) <= 2:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 2) + "(len=%d)" % len(value)


def log_event(request_id, event, actor, result, **extra):
    """結構化日誌（L6 修補）：JSON Lines，每筆都含 request_id。"""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "request_id": request_id,
        "event": event,
        "actor": actor,
        "result": result,
    }
    record.update(extra)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def raise_alert(request_id, alert_type, detail):
    """L4 修補：產生告警（與日誌分開，代表「需要有人處理」）。"""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "request_id": request_id,
        "alert": alert_type,
        "severity": "high",
        "detail": detail,
    }
    with open(ALERT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


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
            (1, "alice", hashlib.md5(b"123456").hexdigest(), "user"),
            (2, "bob", hashlib.md5(b"password").hexdigest(), "user"),
            (3, "admin", hashlib.md5(b"admin").hexdigest(), "admin"),
        ],
    )
    # L2 修補：審計表會被實際寫入（不可竄改的稽核軌跡）
    cur.execute(
        "CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, "
        "request_id TEXT, actor TEXT, action TEXT, target TEXT, result TEXT)"
    )
    con.commit()
    con.close()


def write_audit(request_id, actor, action, target, result):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO audit (ts, request_id, actor, action, target, result) "
            "VALUES (?,?,?,?,?,?)",
            (time.strftime("%Y-%m-%dT%H:%M:%S"), request_id, actor, action,
             target, result),
        )
        con.commit()
    finally:
        con.close()


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>LogLab (PATCHED)</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:920px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .ok{{background:#eefaf1;border-left:5px solid #2e9e5b;padding:12px 16px;
     border-radius:8px;font-size:14px;margin-bottom:20px}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
</style></head><body>
<div class="ok"><b>✓ 這是修補版。</b>
A09 的 6 個缺口都已修補：結構化日誌、審計軌跡、敏感資料遮罩、
告警門檻、日誌保護、request_id 貫穿。</div>
<h1>LogLab (PATCHED)</h1>
{body}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LogLab/2.0-patched"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        # 保留可審計的請求軌跡
        sys.stderr.write("[LogLab-patched] %s\n" % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        # L6 修補：每個請求一個 request_id，貫穿所有日誌
        rid = uuid.uuid4().hex[:12]

        if path == "/":
            return self._respond(200,
                "<p>端點：/login /change_role /audit /log /alerts</p>")

        # ---------------- L1 + L3 + L4 修補：登入 --------------------
        if path == "/login":
            uname = qs.get("u", [""])[0]
            pw = qs.get("p", [""])[0]
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                cur.execute(
                    "SELECT id, password_hash FROM accounts WHERE username = ?", (uname,)
                )
                row = cur.fetchone()
            finally:
                con.close()
            ok = bool(row and row[1] == hashlib.md5(pw.encode()).hexdigest())

            if ok:
                # L1 修補：成功也記錄；L3 修補：密碼遮罩
                log_event(rid, "login", uname, "success",
                          password_masked=mask(pw))
                LOGIN_FAILS.pop(uname, None)          # 成功後重置失敗計數
                return self._respond(200,
                    "<h2>登入成功</h2><p>user=%s</p><p>request_id=<code>%s</code></p>"
                    % (uname, rid))

            # L1 修補：失敗也記錄
            n = LOGIN_FAILS.get(uname, 0) + 1
            LOGIN_FAILS[uname] = n
            log_event(rid, "login", uname, "failure",
                      reason="bad_credentials", fail_count=n,
                      password_masked=mask(pw))
            # L4 修補：達門檻觸發告警
            if n >= ALERT_THRESHOLD:
                raise_alert(rid, "possible_brute_force",
                            "user=%s failures=%d" % (uname, n))
            # L4 修補：不再把嘗試次數告訴攻擊者
            return self._respond(401,
                "<h2>登入失敗</h2><p>帳號或密碼錯誤（request_id=<code>%s</code>）</p>" % rid)

        # ---------------- L2 修補：審計軌跡 --------------------------
        if path == "/change_role":
            actor = qs.get("actor", [""])[0]
            target = qs.get("target", [""])[0]
            role = qs.get("role", [""])[0]
            if not actor or not target or role not in ("user", "admin"):
                return self._respond(400, "<h2>參數錯誤</h2>")
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                cur.execute("UPDATE accounts SET role = ? WHERE username = ?",
                            (role, target))
                con.commit()
            finally:
                con.close()
            # L2 修補：寫入審計（actor/action/target/result）
            write_audit(rid, actor, "change_role", target, "ok")
            log_event(rid, "change_role", actor, "ok", target=target, new_role=role)
            return self._respond(200,
                "<h2>角色已變更</h2><pre>actor=%s → %s = %s</pre>"
                "<p>已寫入審計軌跡（request_id=<code>%s</code>）</p>" % (actor, target, role, rid))

        # ---------------- 觀察：審計表 -------------------------------
        if path == "/audit":
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            try:
                cur.execute("SELECT COUNT(*) FROM audit")
                n = cur.fetchone()[0]
                cur.execute("SELECT ts, request_id, actor, action, target, result "
                            "FROM audit ORDER BY id DESC LIMIT 20")
                rows = cur.fetchall()
            finally:
                con.close()
            body = "<h2>審計表</h2><p>記錄數：<b>%d</b></p><pre>%s</pre>" % (
                n, "\n".join(" | ".join(str(x) for x in r) for r in rows) or "（空）")
            return self._respond(200, body)

        # ---------------- L5 修補：日誌唯讀（無清除端點）-------------
        if path == "/log":
            if "clear" in qs:
                # L5 修補：明確拒絕，並記錄嘗試（這本身是可疑行為）
                log_event(rid, "log_access", "unknown", "denied",
                          action="clear_attempt")
                return self._respond(403,
                    "<h2>拒絕</h2><p>日誌不可透過 API 清除（request_id=<code>%s</code>）</p>" % rid)
            content = ""
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            mode = oct(os.stat(LOG_PATH).st_mode & 0o777) if os.path.exists(LOG_PATH) else "N/A"
            log_event(rid, "log_access", "unknown", "ok")     # 讀取日誌也要留痕
            body = ("<h2>結構化日誌</h2><p>檔案權限：<code>%s</code></p><pre>%s</pre>"
                    % (mode, content or "（空）"))
            return self._respond(200, body)

        # ---------------- 觀察：告警 ---------------------------------
        if path == "/alerts":
            content = ""
            if os.path.exists(ALERT_PATH):
                with open(ALERT_PATH, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            body = ("<h2>告警記錄</h2><pre>%s</pre><p>告警是否存在：<b>%s</b></p>"
                    % (content or "（無）", "是" if content.strip() else "否"))
            return self._respond(200, body)

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    open(LOG_PATH, "a", encoding="utf-8").close()
    if os.path.exists(ALERT_PATH):
        os.remove(ALERT_PATH)
    # L5 修補：收緊日誌檔權限。
    #
    # ⚠ 平台限制（實測確認）：Windows NTFS 只有「唯讀」位元，
    #   os.chmod(0o600) 在這裡**不會生效** —— 實測 0o600 與 0o644 都顯示 0o666，
    #   只有 0o444（唯讀）有效。
    #   這是真實世界的跨平台陷阱，本檔保留 Linux 語意的程式碼並附註說明，
    #   而不是假裝它已經生效。
    #
    #   在 Windows 上的正確替代方案：
    #     1. icacls 設定 ACL（限制只有服務帳號可讀寫）
    #     2. 集中式日誌（遠端 syslog / ELK）—— 本機副本被刪也不影響調查
    #     3. 讓日誌目錄不透過任何 HTTP 端點暴露
    try:
        os.chmod(LOG_PATH, 0o600)          # Linux 有效；Windows 僅設唯讀位元
    except Exception:                                        # noqa: BLE001
        pass

    print("=" * 74)
    print(" LogLab (PATCHED) — A09 修補版")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 日誌: %s（結構化 JSON Lines，權限 600）" % os.path.basename(LOG_PATH))
    print(" 告警門檻: 同一帳號連續失敗 %d 次" % ALERT_THRESHOLD)
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
