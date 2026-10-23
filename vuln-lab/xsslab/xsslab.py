#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 xsslab.py — XSS / CSRF / XXE 靶場（補足 A05 的另一半）
=============================================================================

 對應研究報告 CH06 S1（學習路徑缺口）與 OWASP Top 10:2025 **A05 Injection**。

 為什麼需要這個？
   本專案的 A05 覆蓋原本只有 SQL injection 與 command injection。
   但 A05 的另一半是**客戶端與解析器層的注入**：
     · XSS（存儲型／反射型／DOM 型）
     · CSRF（跨站請求偽造）
     · XXE（XML 外部實體）
   三者的驗證方式與 SQLi 完全不同（見下）。

 ⚠ 刻意含漏洞，僅供本機教育用途。
    XSS 載荷一律使用無害的 <script>alert(...)</script> 形式，
    不涉及竊取 cookie 或對外連線。

 驗證方式的差異（本靶場的教學重點）：
   ┌──────────┬──────────────────────────────────────────┐
   │ 漏洞     │ 驗證要看什麼                              │
   ├──────────┼──────────────────────────────────────────┤
   │ 反射型XSS│ 回應中是否**原樣出現未轉義的標籤**        │
   │ 存儲型XSS│ 再查詢一次，確認 payload 被**持久化**      │
   │ DOM型XSS │ 需檢查**前端 JS 是否有 sink**（本檔用靜態分析）│
   │ CSRF     │ 是否缺少 token／SameSite／Origin 檢查      │
   │ XXE      │ 解析器是否**展開外部實體**                │
   └──────────┴──────────────────────────────────────────┘

 用法：
   python xsslab.py 8925
=============================================================================
"""

import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, quote

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8925

# 存儲型 XSS：留言板（記憶體）
COMMENTS = []

# CSRF：已登入使用者的「狀態」與（刻意缺席的）token
SESSION = {"user": "alice", "logged_in": True}
CSRF_TOKEN = None            # ★ 刻意不產生 token


def html_escape_unsafe(s: str) -> str:
    """★ 漏洞版：完全不轉義。"""
    return s


def html_escape_safe(s: str) -> str:
    """修補版用的轉義（本靶場用來對照）。"""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


# ---------------------------------------------------------------------------
# ★ DOM 型 XSS 的前端 JS（用 base64 包裝，避免 Python 字串轉義地獄）
# ---------------------------------------------------------------------------
DOM_JS_PLAIN = """
// ★ DOM 型 XSS：直接從 location.hash 取值，未做任何處理就寫入 innerHTML
function showWelcome() {
  var name = decodeURIComponent(location.hash.slice(1));
  var el = document.getElementById("welcome");
  if (el && name) {
    el.innerHTML = "歡迎回來，" + name + "！";   // ★ sink：innerHTML
  }
}
window.addEventListener("hashchange", showWelcome);
window.addEventListener("DOMContentLoaded", showWelcome);

// 對照：安全版本應使用 textContent
function safeShowWelcome() {
  var name = decodeURIComponent(location.hash.slice(1));
  var el = document.getElementById("welcome");
  if (el && name) {
    el.textContent = "歡迎回來，" + name + "！";  // ✅ 不會解析 HTML
  }
}
"""
DOM_JS_B64 = base64.b64encode(DOM_JS_PLAIN.encode("utf-8")).decode()


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>XssLab — XSS / CSRF / XXE</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:920px;
      margin:32px auto;line-height:1.7;color:#1b2430}}
 .warn{{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:18px}}
 .card{{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;
       margin:12px 0;background:#f8fafc}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .payload{{background:#fff4e5;border-left:4px solid #e8a33d;padding:8px 12px;
          border-radius:6px;font-family:Consolas,monospace;font-size:13px;
          margin:6px 0;word-break:break-all}}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：刻意含 XSS / CSRF / XXE。</b>
載荷僅為無害的 <code>alert()</code>，不涉及竊取 cookie 或對外連線。僅限本機使用。</div>
<h1>XssLab</h1>
{body}
<script>
// ★ DOM 型 XSS 的邏輯（base64 解碼後執行）
eval(atob("{dom_js_b64}"));
</script>
</body></html>"""

INDEX_BODY = """
<div class="card"><h3>1. 反射型 XSS（Reflected）</h3>
<p>搜尋參數會<strong>原樣</strong>出現在回應中。</p>
<div class="payload">GET /search?q=&lt;script&gt;alert(1)&lt;/script&gt;</div></div>

<div class="card"><h3>2. 存儲型 XSS（Stored）</h3>
<p>留言會存進伺服器，之後每次讀取都再次輸出（未轉義）。</p>
<div class="payload">POST /comment  body: text=&lt;script&gt;alert(2)&lt;/script&gt;</div>
<p>張貼後用 <code>GET /comments</code> 確認 payload 被持久化。</p></div>

<div class="card"><h3>3. DOM 型 XSS（DOM-based）</h3>
<p>前端 JS 直接讀 <code>location.hash</code> 後寫入 <code>innerHTML</code>。</p>
<div class="payload">/#&lt;img src=x onerror=alert(3)&gt;</div>
<p>這一型的 payload <strong>永遠不會送到伺服器</strong>——
伺服器日誌看不到，只有瀏覽器會執行。</p></div>

<div class="card"><h3>4. CSRF（跨站請求偽造）</h3>
<p>轉帳端點沒有任何 token、也不檢查 Origin。</p>
<div class="payload">POST /transfer  body: to=bob&amp;amount=999</div>
<p>用 <code>GET /me</code> 觀察餘額變化。</p></div>

<div class="card"><h3>5. XXE（XML 外部實體）</h3>
<p>XML 解析器允許外部實體。</p>
<div class="payload">&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE r [ &lt;!ENTITY x SYSTEM "file:///etc/hostname"&gt; ]&gt;
&lt;r&gt;&amp;x;&lt;/r&gt;</div>
<p>若回應出現實體值（而非 <code>&amp;x;</code> 或錯誤），代表實體被展開。</p></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "XssLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        # ★ 刻意不加 CSP（XSS 才能執行）；也不加 X-Content-Type-Options
        # ★ CSRF 對照：沒有 SameSite cookie 設定
        self.send_header("Set-Cookie", "session=alice123; Path=/")   # 無 SameSite
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8")

    def log_message(self, fmt, *args):
        sys.stderr.write("[XssLab] %s\n" % (fmt % args))

    # ---------------- GET ----------------
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY, dom_js_b64=DOM_JS_B64))

        # ★ 1. 反射型 XSS：直接把 q 放進 HTML（未轉義）
        if path == "/search":
            q = qs.get("q", [""])[0]
            reflected = html_escape_unsafe(q)          # ★ 漏洞點
            return self._send(200, PAGE.format(
                body="<h2>搜尋結果</h2><p>你搜尋了：%s</p>" % reflected,
                dom_js_b64=DOM_JS_B64))

        # ★ 2. 存儲型 XSS：輸出所有留言（未轉義）
        if path == "/comments":
            out = "<h2>留言板</h2>"
            if not COMMENTS:
                out += "<p>（還沒有留言）</p>"
            for c in COMMENTS:
                out += "<div class='card'>%s</div>" % html_escape_unsafe(c)  # ★ 漏洞點
            return self._send(200, PAGE.format(body=out, dom_js_b64=DOM_JS_B64))

        # ★ 4. CSRF 觀察點
        if path == "/me":
            st = SESSION["state"]
            return self._json({"user": SESSION["user"], "balance": st["balance"],
                               "note": "轉帳端點沒有 CSRF token 保護"})

        # ★ 5. XXE 觀察點（提供範例 XML 讓使用者送出）
        if path == "/xxe-sample":
            sample = ('<?xml version="1.0"?>\n'
                      '<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/hostname"> ]>\n'
                      '<r>&x;</r>\n')
            return self._send(200, sample, "application/xml; charset=utf-8")

        return self._send(404, PAGE.format(body="<h2>404</h2>", dom_js_b64=DOM_JS_B64))

    # ---------------- POST ----------------
    def do_POST(self):
        u = urlparse(self.path)
        # ★ 修正：do_POST 先前漏了解析 query string，導致 NameError: qs
        qs = parse_qs(u.query)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        # ★ 2. 存儲型 XSS：儲存留言（不做任何處理）
        if u.path == "/comment":
            try:
                data = json.loads(raw)
            except Exception:                                # noqa: BLE001
                data = {k: v[0] for k, v in parse_qs(raw).items()}
            text = data.get("text", "")
            COMMENTS.append(text)
            return self._json({"ok": True, "stored": text,
                               "note": "已原樣存入，GET /comments 會再次輸出"})

        # ★ 4. CSRF：轉帳端點（無 token、無 Origin 檢查）
        if u.path == "/transfer":
            origin = self.headers.get("Origin", "")
            referer = self.headers.get("Referer", "")
            token = self.headers.get("X-CSRF-Token", "")
            try:
                data = json.loads(raw)
            except Exception:                                # noqa: BLE001
                data = {k: v[0] for k, v in parse_qs(raw).items()}
            to = data.get("to", "?")
            try:
                amount = int(data.get("amount", 0))
            except Exception:                                # noqa: BLE001
                amount = 0

            # ★ 漏洞點：完全不檢查 origin / referer / token
            SESSION["state"]["balance"] -= amount
            return self._json({
                "ok": True,
                "transferred": amount,
                "to": to,
                "balance": SESSION["state"]["balance"],
                "flag": "FLAG{csrf_no_token_check}",
                "observed": {"Origin": origin or "(未提供)",
                             "Referer": referer or "(未提供)",
                             "X-CSRF-Token": token or "(未提供)"},
                "note": "以上三個欄位完全未被檢查",
            })

        # ★ 5. XXE：解析 XML（刻意開啟危險選項）
        #
        # 實測發現（重要）：
        #   標準庫 xml.etree.ElementTree **預設會拒絕外部實體**
        #     → ParseError: undefined entity &x;
        #   所以「用標準庫寫的程式」天生不易有 XXE。
        #
        #   真實世界的 XXE 來自：
        #     ① 使用 lxml 等第三方解析器並主動開啟危險選項
        #     ② 舊版解析器（預設展開實體）
        #     ③ 開發者為了「支援 DTD」而關閉安全設定
        #
        #   本靶場用 lxml + resolve_entities=True 示範 ①，
        #   並提供 resolve_entities=False 的對照。
        if u.path == "/xml":
            unsafe = qs.get("safe", ["0"])[0] != "1"
            try:
                from lxml import etree
                if unsafe:
                    # ★ 漏洞點：開啟 DTD 與外部實體展開
                    parser = etree.XMLParser(resolve_entities=True, load_dtd=True,
                                             no_network=True)
                else:
                    parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                                             no_network=True)
                root = etree.fromstring(raw.encode("utf-8"), parser)
                text = root.text or ""
                expanded = bool(text.strip())
                return self._json({
                    "ok": True,
                    "mode": "unsafe（resolve_entities=True）" if unsafe
                            else "safe（resolve_entities=False）",
                    "parsed_text": text,
                    "entity_expanded": expanded,
                    "flag": "FLAG{xxe_entity_expanded}" if (unsafe and expanded) else None,
                    "note": ("若 parsed_text 出現檔案內容，代表外部實體被展開"
                             if unsafe else "安全設定下實體不會展開"),
                })
            except ImportError:
                # 後備：標準庫（本身就會拒絕外部實體）
                try:
                    root = ET.fromstring(raw)
                    text = "".join(root.itertext())
                    return self._json({
                        "ok": True, "mode": "標準庫（天生拒絕外部實體）",
                        "parsed_text": text,
                        "note": "xml.etree.ElementTree 預設不解析外部實體 → 無法示範 XXE",
                    })
                except Exception as e:                       # noqa: BLE001
                    return self._json({"ok": False, "error": str(e)}, 400)
            except Exception as e:                           # noqa: BLE001
                return self._json({"ok": False,
                                   "error": "%s: %s" % (type(e).__name__, e)}, 400)

        return self._json({"error": "not found"}, 404)


def main():
    SESSION["state"] = {"balance": 10000}
    print("=" * 78)
    print(" XssLab — XSS / CSRF / XXE 靶場（A05 的另一半）")
    print(" 僅限本機教育用途；載荷僅為無害 alert()")
    print("=" * 78)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print()
    print(" 端點：")
    print("   反射型 XSS : GET  /search?q=<script>alert(1)</script>")
    print("   存儲型 XSS : POST /comment  {text:...}  →  GET /comments")
    print("   DOM 型 XSS : /#<img src=x onerror=alert(3)>")
    print("   CSRF       : POST /transfer {to:...,amount:...}  →  GET /me")
    print("   XXE        : POST /xml（XML 內容）")
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
