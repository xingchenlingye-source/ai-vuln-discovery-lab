#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 accountlab.py — 帳號接管全鏈 + 短信轟炸 + XSS 盲打平台整合靶場
=============================================================================

 對應 Bilibili 84 集課程的剩餘「需額外條件」缺口（見 S1m 報告）。

 本檔用一個靶場補齊三項，並附帶三個服務：
   · 主應用 :8940      —— 帳號流程（註冊/登入/找回密碼/改密碼）
   · SMS 服務 :8941    —— 模擬簡訊閘道（含速率限制對照）
   · 盲打平台 :8942    —— XSS callback 接收端（真實可用）

 ⚠ 刻意含漏洞，僅供本機教育用途。
    · 簡訊為**模擬**（不真的發送）
    · XSS 載荷僅為無害的 alert 或 callback 標記，不竊取真實 cookie
    · 所有服務僅監聽 127.0.0.1

 包含的漏洞：
   A1  使用者列舉（註冊/找回密碼回應差異） ........ CWE-204
   A2  密碼重置 token 可預測（時間戳 + MD5） ....... CWE-330 / CWE-640
   A3  重置 token 可用後不失效（可重放） ........... CWE-613
   A4  重置後舊 session 仍有效（未失效） ........... CWE-613
   A5  改密碼不需舊密碼 ........................... CWE-620
   A6  Host 標頭注入（重置連結被導向攻擊者） ....... CWE-640
   B1  短信轟炸（無速率限制） ...................... CWE-799
   B2  短信驗證碼可爆破（4 位數、無嘗試上限） ....... CWE-307
   X1  XSS 盲打（存儲型 XSS 觸發 callback） ........ CWE-79

 用法：
   python accountlab.py            # 同時啟動三個服務
=============================================================================
"""

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8940
SMS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8941
XSS_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8942

SMS_BASE = "http://%s:%d" % (HOST, SMS_PORT)
XSS_BASE = "http://%s:%d" % (HOST, XSS_PORT)

# ---------------------------------------------------------------- 資料
USERS = {
    "alice": {"password": "alice-old-pass", "email": "alice@corp.local",
              "sessions": ["sess-alice-old-001"]},
    "bob": {"password": "bob-old-pass", "email": "bob@corp.local", "sessions": []},
}
# ★ A2：可預測的重置 token（時間戳 + username + MD5）
RESET_TOKENS = {}          # token -> {user, created, used}
# ★ A3：已使用的 token 不刪除（可重放）
LOGIN_SESSIONS = {}        # sid -> user

# ★ B1/B2：簡訊記錄（模擬）
SMS_LOG = []               # {to, code, ts, ip}
SMS_FAILS = {}             # phone -> 失敗次數
SMS_CODES = {}             # phone -> code（用於驗證）

# ★ X1：盲打平台收到的 callback
XSS_CALLBACKS = []

# 存儲型 XSS 的留言
COMMENTS = []


def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


# ===========================================================================
# SMS 服務（模擬簡訊閘道）
# ===========================================================================
class SmsHandler(BaseHTTPRequestHandler):
    server_version = "SmsGateway/1.0"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)

        # 根端點（服務說明）
        if u.path == "/":
            return self._json({
                "service": "SmsGateway（模擬簡訊閘道）",
                "endpoints": ["/send?phone=", "/send-safe?phone=",
                              "/verify?phone=&code=", "/log"],
                "note": "★ /send 無速率限制；/send-safe 為正確對照",
            })

        # ★ B1：無速率限制的發送端點
        if u.path == "/send":
            phone = qs.get("phone", [""])[0]
            if not re.fullmatch(r"\d{11}", phone):
                return self._json({"ok": False, "error": "手機號格式錯誤"}, 400)
            code = "%06d" % secrets.randbelow(1000000)
            SMS_CODES[phone] = code
            SMS_LOG.append({"to": phone, "code": code,
                            "ts": datetime.now().isoformat(),
                            "ip": self.client_address[0]})
            return self._json({
                "ok": True, "sent_to": phone, "code_debug": code,
                "note": "★ 無速率限制——同一號碼可無限次發送",
                "total_sent": len(SMS_LOG),
                "flag": "FLAG{sms_flood_no_ratelimit}",
            })

        # 安全對照：有速率限制
        if u.path == "/send-safe":
            phone = qs.get("phone", [""])[0]
            now = time.time()
            recent = [r for r in SMS_LOG
                      if r["to"] == phone and (now - time.mktime(
                          datetime.fromisoformat(r["ts"]).timetuple())) < 60]
            if len(recent) >= 1:
                return self._json({"ok": False,
                                   "error": "同一號碼 60 秒內僅能發送一次",
                                   "recent_count": len(recent)}, 429)
            code = "%06d" % secrets.randbelow(1000000)
            SMS_CODES[phone] = code
            SMS_LOG.append({"to": phone, "code": code,
                            "ts": datetime.now().isoformat(),
                            "ip": self.client_address[0]})
            return self._json({"ok": True, "sent_to": phone,
                               "note": "✓ 已套用速率限制", "code_debug": code})

        # ★ B2：驗證端點（無嘗試次數限制）
        if u.path == "/verify":
            phone = qs.get("phone", [""])[0]
            code = qs.get("code", [""])[0]
            SMS_FAILS[phone] = SMS_FAILS.get(phone, 0) + 1
            expect = SMS_CODES.get(phone)
            ok = (expect is not None and code == expect)
            if ok:
                SMS_CODES.pop(phone, None)      # 成功後才清除
                SMS_FAILS[phone] = 0
                return self._json({"ok": True, "attempts": SMS_FAILS[phone],
                                   "flag": "FLAG{sms_code_correct}"})
            return self._json({
                "ok": False, "error": "驗證碼錯誤",
                "attempts": SMS_FAILS[phone],
                "note": "★ 沒有嘗試次數上限、沒有鎖定 → 可爆破 4~6 位數",
            }, 401)

        # 觀察端點
        if u.path == "/log":
            return self._json({"total": len(SMS_LOG),
                               "entries": SMS_LOG[-20:],
                               "failures": SMS_FAILS})

        return self._json({"error": "not found"}, 404)


# ===========================================================================
# 盲打平台（XSS callback 接收端）
# ===========================================================================
class XssHandler(BaseHTTPRequestHandler):
    server_version = "XssBlindPlatform/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[BlindPlatform] %s\n" % (fmt % args))

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(code)
        # ★ 盲打平台必須允許跨域（否則 XSS 載荷無法回傳資料）
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        # ★ X1：接收 XSS callback（記錄代表 payload 真的在瀏覽器執行了）
        if path in ("/c", "/collect", "/x"):
            rec = {
                "ts": datetime.now().isoformat(),
                "path": path,
                "query": {k: v[0] for k, v in qs.items()},
                "ua": self.headers.get("User-Agent", ""),
                "referer": self.headers.get("Referer", ""),
                "ip": self.client_address[0],
                "cookies_sent": bool(self.headers.get("Cookie")),
            }
            XSS_CALLBACKS.append(rec)
            sys.stderr.write("[BlindPlatform] ★ 收到 XSS callback: %s\n"
                             % json.dumps(rec, ensure_ascii=False))
            # 回傳可執行的 JS（讓載荷能繼續，形成完整的盲打鏈）
            return self._send(200, "// callback received\n", "application/javascript")

        if path == "/":
            rows = "".join(
                "<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                % (r["ts"], json.dumps(r["query"], ensure_ascii=False)[:80], r["path"])
                for r in XSS_CALLBACKS[-30:])
            return self._send(200, """<!DOCTYPE html><html lang="zh-Hant">
<head><meta charset="utf-8"><title>XSS 盲打平台</title>
<style>body{font-family:system-ui;margin:28px;line-height:1.7}
table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ddd;padding:6px;
font-size:13px}th{background:#f0f4f8}
.warn{background:#fdecea;border-left:5px solid #c0392b;padding:10px 14px;border-radius:8px}
code{background:#eef2f7;padding:2px 5px;border-radius:4px}
</style></head><body>
<div class="warn"><b>這是 XSS 盲打平台（callback 接收端）。</b>
當 XSS 載荷在瀏覽器執行並回傳時，這裡會出現記錄。僅限本機。</div>
<h1>XSS 盲打平台</h1>
<p>已收到 <b>%d</b> 筆 callback。</p>
<p>接收端點：<code>%s/c?u=&lt;資料&gt;</code></p>
<table><tr><th>時間</th><th>資料</th><th>路徑</th></tr>%s</table>
</body></html>""" % (len(XSS_CALLBACKS), XSS_BASE, rows))

        if path == "/records":
            return self._send(200, json.dumps(XSS_CALLBACKS, ensure_ascii=False, indent=2),
                              "application/json; charset=utf-8")

        return self._send(404, "<h2>404</h2>")


# ===========================================================================
# 主應用（帳號流程）
# ===========================================================================
PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>AccountLab — 帳號接管全鏈</title>
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
<div class="warn"><b>⚠ 教學靶場：帳號接管全鏈 + 短信轟炸 + XSS 盲打。</b>
簡訊為模擬（不真的發送）；XSS 載荷僅回傳標記，不竊取真實 cookie。僅限本機。</div>
<h1>AccountLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<p>本靶場涵蓋帳號接管的<b>完整攻擊鏈</b>（5 個階段），外加短信與 XSS 盲打。</p>

<div class="card"><h3>A1 · 使用者列舉（CWE-204）</h3>
<pre>POST /register      {username:alice}      → 「使用者已存在」
POST /forgot        {username=nobody}     → 「查無此使用者」</pre></div>

<div class="card"><h3>A2 · 重置 token 可預測（CWE-330/640）</h3>
<pre>POST /forgot {username:alice}    → 取得 token
# token = md5(username + 時間戳)  → 可在時間窗內自行推算</pre></div>

<div class="card"><h3>A3 · token 可重放（CWE-613）</h3>
<pre>POST /reset {token:T, new_password:X}   # 成功
POST /reset {token:T, new_password:Y}   # ★ 同一個 token 再用一次也成功</pre></div>

<div class="card"><h3>A4 · 重置後舊 session 仍有效（CWE-613）</h3>
<pre># 攻擊者先取得 session，受害者重置密碼後，攻擊者的 session 仍可用</pre></div>

<div class="card"><h3>A5 · 改密碼不需舊密碼（CWE-620）</h3>
<pre>POST /change-password {username:alice, new_password:NEW}</pre></div>

<div class="card"><h3>A6 · Host 標頭注入（CWE-640）</h3>
<pre>POST /forgot  (Host: evil.example.com)
# 重置連結被導向攻擊者網域 → token 洩漏</pre></div>

<div class="card"><h3>B1 · 短信轟炸（CWE-799）</h3>
<pre>GET %s/send?phone=13800138000        # ★ 無速率限制
GET %s/send-safe?phone=13800138000   # 安全對照（60 秒一次）</pre></div>

<div class="card"><h3>B2 · 短信驗證碼可爆破（CWE-307）</h3>
<pre>GET %s/verify?phone=...&amp;code=000000    # ★ 無嘗試上限</pre></div>

<div class="card"><h3>X1 · XSS 盲打（CWE-79）</h3>
<pre>POST /comment {text:"&lt;script&gt;..."}      # 存儲型留言
GET  /comments                          # 讀取時觸發
盲打平台：%s/c?u=資料</pre>
<p>存儲型 XSS 會在「任何訪客」瀏覽時執行——包含管理員。</p></div>
"""


class MainHandler(BaseHTTPRequestHandler):
    server_version = "AccountLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8", extra)

    def log_message(self, *a):
        pass

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            try:
                return {k: v[0] for k, v in parse_qs(raw).items()}          # noqa: BLE001
            except Exception:
                return {}

    # ---------------------------------------------------------- GET
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY % (
                SMS_BASE, SMS_BASE, SMS_BASE, XSS_BASE)))

        # ★ X1：存儲型 XSS（讀取時輸出未轉義內容）
        if path == "/comments":
            rows = "".join("<div class='card'>%s</div>" % c for c in COMMENTS)
            if not COMMENTS:
                rows = "<p>（還沒有留言）</p>"
            return self._send(200, PAGE.format(body="<h2>留言板</h2>" + rows))

        # 使用者列表（觀察用）
        if path == "/users":
            return self._json({"users": {k: {"email": v["email"],
                                             "sessions": v["sessions"]}
                                         for k, v in USERS.items()},
                               "reset_tokens": RESET_TOKENS,
                               "login_sessions": LOGIN_SESSIONS})

        # ★ A4 觀察：用 session 存取（用來證明「重置後 session 仍有效」）
        if path == "/me":
            sid = qs.get("sid", [""])[0]
            user = LOGIN_SESSIONS.get(sid)
            if not user:
                return self._json({"ok": False, "error": "無效 session"}, 401)
            return self._json({"ok": True, "sid": sid, "user": user,
                               "note": "★ session 在密碼重置後仍有效（漏洞）"})

        # 登入（取得 session）
        if path == "/login":
            uname = qs.get("username", [""])[0]
            pw = qs.get("password", [""])[0]
            if uname in USERS and USERS[uname]["password"] == pw:
                sid = "sess-" + secrets.token_hex(6)
                LOGIN_SESSIONS[sid] = uname
                USERS[uname]["sessions"].append(sid)
                return self._json({"ok": True, "sid": sid, "user": uname})
            return self._json({"ok": False, "error": "帳號或密碼錯誤"}, 401)

        return self._send(404, PAGE.format(body="<h2>404</h2>"))

    # ---------------------------------------------------------- POST
    def do_POST(self):
        u = urlparse(self.path)
        data = self._body()
        path = u.path

        # ★ A1：使用者列舉
        if path == "/register":
            uname = data.get("username", "")
            if uname in USERS:
                return self._json({"ok": False,
                                   "error": "使用者已存在: %s" % uname,
                                   "flag": "FLAG{user_enum_register}"}, 409)
            USERS[uname] = {"password": data.get("password", "x"),
                            "email": data.get("email", ""), "sessions": []}
            return self._json({"ok": True, "created": uname})

        # ★ A1 + A2 + A6：找回密碼
        if path == "/forgot":
            uname = data.get("username", "")
            if uname not in USERS:
                return self._json({"ok": False,
                                   "error": "查無此使用者: %s" % uname,
                                   "flag": "FLAG{user_enum_forgot}"}, 404)

            # ★ A2：可預測 token = md5(username + 時間戳秒)
            ts = int(time.time())
            token = md5("%s%d" % (uname, ts))
            RESET_TOKENS[token] = {"user": uname, "created": ts, "used": False}

            # ★ A6：用 Host 標頭組出重置連結（未驗證）
            host = self.headers.get("Host", "%s:%d" % (HOST, PORT))
            link = "http://%s/reset?token=%s" % (host, token)

            return self._json({
                "ok": True, "username": uname, "token": token,
                "reset_link": link,
                "token_algo": "md5(username + unix_timestamp)",
                "timestamp": ts,
                "flag": "FLAG{predictable_reset_token}",
                "note": "★ token 可預測；★ 連結使用未驗證的 Host 標頭",
            })

        # ★ A3：token 可重放（不標記 used）
        if path == "/reset":
            token = data.get("token", "")
            newpw = data.get("new_password", "")
            rec = RESET_TOKENS.get(token)
            if not rec:
                return self._json({"ok": False, "error": "無效 token"}, 400)
            USERS[rec["user"]]["password"] = newpw
            # ★ 漏洞：不設 rec["used"] = True，也不刪除 token
            return self._json({
                "ok": True, "user": rec["user"],
                "token_still_valid": True,
                "flag": "FLAG{token_replay_allowed}",
                "note": "★ token 未失效，可重複使用（重放）",
            })

        # ★ A5：改密碼不需舊密碼
        if path == "/change-password":
            uname = data.get("username", "")
            newpw = data.get("new_password", "")
            oldpw = data.get("old_password", None)
            if uname not in USERS:
                return self._json({"ok": False, "error": "查無使用者"}, 404)
            if oldpw is None:
                # ★ 漏洞：完全沒有要求舊密碼
                USERS[uname]["password"] = newpw
                return self._json({
                    "ok": True, "user": uname,
                    "old_password_required": False,
                    "flag": "FLAG{change_password_no_old}",
                    "note": "★ 未驗證舊密碼即可改密碼",
                })
            if oldpw != USERS[uname]["password"]:
                return self._json({"ok": False, "error": "舊密碼錯誤"}, 401)
            USERS[uname]["password"] = newpw
            return self._json({"ok": True, "user": uname,
                               "old_password_required": True})

        # ★ X1：存儲型 XSS（儲存時不處理）
        if path == "/comment":
            text = data.get("text", "")
            COMMENTS.append(text)
            return self._json({"ok": True, "stored": text,
                               "flag": "FLAG{stored_xss_from_comment}",
                               "note": "已原樣存入；GET /comments 會再次輸出"})

        return self._json({"error": "not found"}, 404)


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)

    sms = ThreadingHTTPServer((HOST, SMS_PORT), SmsHandler)
    xss = ThreadingHTTPServer((HOST, XSS_PORT), XssHandler)
    for srv in (sms, xss):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    print("=" * 78)
    print(" AccountLab — 帳號接管全鏈 + 短信轟炸 + XSS 盲打")
    print(" 僅限本機教育用途；簡訊為模擬，不真的發送")
    print("=" * 78)
    print(" 主應用   : http://%s:%d/" % (HOST, PORT))
    print(" SMS 服務 : %s（模擬簡訊閘道）" % SMS_BASE)
    print(" 盲打平台 : %s（XSS callback 接收端）" % XSS_BASE)
    print()
    print(" 帳號接管鏈（6 項）：")
    print("   A1 使用者列舉     : POST /register、/forgot")
    print("   A2 可預測 token   : POST /forgot → md5(username+timestamp)")
    print("   A3 token 可重放   : POST /reset（同 token 用兩次）")
    print("   A4 舊 session 存活: GET /me?sid=（重置後仍有效）")
    print("   A5 改密碼免舊密碼 : POST /change-password")
    print("   A6 Host 標頭注入  : POST /forgot（自訂 Host 標頭）")
    print()
    print(" 短信（2 項）：")
    print("   B1 短信轟炸       : GET %s/send?phone=13800138000" % SMS_BASE)
    print("   B2 驗證碼可爆破   : GET %s/verify?phone=..&code=.." % SMS_BASE)
    print()
    print(" XSS 盲打（1 項）：")
    print("   X1 存儲型盲打     : POST /comment → GET /comments")
    print("                       盲打平台 %s/c?u=資料" % XSS_BASE)
    print("=" * 78)

    httpd = ThreadingHTTPServer((HOST, PORT), MainHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()
        sms.shutdown()
        xss.shutdown()


if __name__ == "__main__":
    main()
