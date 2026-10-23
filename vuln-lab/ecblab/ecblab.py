#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 ecblab.py — ECB 加密 + Block Splicing 攻擊靶場
=============================================================================

 對應 OverTheWire Natas natas28 的補強缺口。

 為什麼補這個？
   本專案有 XOR/known-plaintext（cryptolab），但**沒有 ECB block 操作攻擊**。
   而 natas28 正是用 ECB 的「相同明文 block → 相同密文 block」特性，
   在不需金鑰的情況下**操作密文**來改變明文。

 機制（模擬 natas28）：
   · 搜尋詞被 AES-ECB 加密後放在 URL
   · 明文 = PREFIX + query + SUFFIX
   · 伺服器解密後直接執行 SQL（模擬）

 漏洞：
   E1  ECB 模式本身 ..................... CWE-327
       · 相同明文 block → 相同密文 block（可偵測）
   E2  Block Splicing .................... CWE-353
       · 用「乾淨 block」替換含轉義字元的 block → 逃出字串
   E3  加密無完整性驗證 .................. CWE-353
       · 密文被拼接後仍被接受

 安全對照：
   · AES-GCM（認證加密）→ 任何篡改都會被偵測

 ⚠ 刻意含漏洞，僅供本機教育用途。

 用法：
   python ecblab.py 8980
=============================================================================
"""

import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8980
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecb.db")

# ===== 金鑰 =====
KEY = b"0123456789abcdef"          # AES-128
GCM_KEY = hashlib.sha256(b"gcm-secret-key-for-lab").digest()

# ===== 明文結構（模擬 natas28）=====
PREFIX = b"SELECT * FROM joke WHERE joke LIKE '%"
SUFFIX = b"%' ORDER BY id ASC LIMIT 10"

SECRET = "FLAG{ecb_block_splicing_2026}"


def addslashes(s: str) -> str:
    """模擬 PHP 的 addslashes（轉義引號與反斜線）。"""
    return (s.replace("\\", "\\\\")
             .replace("'", "\\'")
             .replace('"', '\\"'))


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE joke (id INTEGER PRIMARY KEY, joke TEXT)")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    jokes = [
        "Why do programmers prefer dark mode? Because light attracts bugs.",
        "A SQL query walks into a bar, walks up to two tables and asks: can I join you?",
        "There are 10 types of people: those who understand binary and those who don't.",
    ]
    for j in jokes:
        c.execute("INSERT INTO joke (joke) VALUES (?)", (j,))
    c.execute("INSERT INTO users (username, password) VALUES (?,?)",
              ("admin", SECRET))
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "ECBLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8")

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY))

        # ===== E：搜尋（加密）=====
        if path == "/search":
            query = qs.get("query", [""])[0]
            plaintext = PREFIX + addslashes(query).encode("utf-8") + SUFFIX
            ct = AES.new(KEY, AES.MODE_ECB).encrypt(pad(plaintext, 16))
            enc = base64.b64encode(ct).decode()
            return self._json({
                "query": query,
                "plaintext_len": len(plaintext),
                "blocks": len(ct) // 16,
                "ciphertext_b64": enc,
                "ciphertext_hex": ct.hex(),
            })

        # ===== E：解密並執行（漏洞點）=====
        if path == "/result":
            enc = qs.get("q", [""])[0]
            if not enc:
                return self._json({"error": "缺少 q"}, 400)
            try:
                ct = base64.b64decode(enc)
                pt = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16)
            except Exception as e:                           # noqa: BLE001
                return self._json({"error": "解密失敗: %s" % e}, 400)

            sql = pt.decode("utf-8", "replace")
            # ★ 漏洞：直接執行解密後的 SQL（無完整性驗證）
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute(sql)
                rows = c.fetchall()
                conn.close()
                return self._json({
                    "ok": True,
                    "sql": sql,
                    "row_count": len(rows),
                    "rows": [list(r) for r in rows[:10]],
                })
            except Exception as e:                           # noqa: BLE001
                return self._json({
                    "ok": False,
                    "sql": sql,
                    "error": str(e),
                })

        # ===== 安全對照：AES-GCM =====
        if path == "/safe-search":
            query = qs.get("query", [""])[0]
            plaintext = PREFIX + addslashes(query).encode("utf-8") + SUFFIX
            nonce = os.urandom(12)
            cipher = AES.new(GCM_KEY, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return self._json({
                "query": query,
                "nonce_b64": base64.b64encode(nonce).decode(),
                "ct_b64": base64.b64encode(ct).decode(),
                "tag_b64": base64.b64encode(tag).decode(),
            })

        if path == "/safe-result":
            nonce_b64 = qs.get("n", [""])[0]
            ct_b64 = qs.get("c", [""])[0]
            tag_b64 = qs.get("t", [""])[0]
            try:
                nonce = base64.b64decode(nonce_b64)
                ct = base64.b64decode(ct_b64)
                tag = base64.b64decode(tag_b64)
                cipher = AES.new(GCM_KEY, AES.MODE_GCM, nonce=nonce)
                pt = cipher.decrypt_and_verify(ct, tag)
                return self._json({"ok": True, "plaintext": pt.decode()})
            except Exception as e:                           # noqa: BLE001
                return self._json({"ok": False,
                                   "error": "認證失敗（密文被篡改）: %s" % e}, 403)

        # ===== 觀察：ECB 重複 block 偵測 =====
        if path == "/detect":
            enc = qs.get("q", [""])[0]
            try:
                ct = base64.b64decode(enc)
            except Exception:                                # noqa: BLE001
                return self._json({"error": "invalid"}, 400)
            blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
            seen = {}
            dupes = []
            for i, b in enumerate(blocks):
                if b in seen:
                    dupes.append((seen[b], i))
                else:
                    seen[b] = i
            return self._json({
                "blocks": len(blocks),
                "duplicates": dupes,
                "note": "ECB：相同明文 block → 相同密文 block",
            })

        return self._json({"error": "not found"}, 404)


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>ECBLab — ECB Block Splicing</title>
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
<div class="warn"><b>⚠ 教學靶場：ECB 加密 + Block Splicing。</b>
AES-ECB 無完整性驗證；安全對照用 AES-GCM。僅限本機。</div>
<h1>ECBLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<p>這是一個「加密搜尋」：「搜尋詞被 AES-ECB 加密後放在 URL，伺服器解密後執行 SQL」。</p>

<div class="card"><h3>正常流程</h3>
<pre>GET /search?query=hello   → 取得密文（base64）
GET /result?q=&lt;密文&gt;      → 解密並執行 SQL</pre></div>

<div class="card"><h3>E1 · ECB 模式（CWE-327）</h3>
<pre>GET /detect?q=&lt;密文&gt;
# 相同明文 block → 相同密文 block（可偵測出模式）</pre></div>

<div class="card"><h3>E2 · Block Splicing（CWE-353）</h3>
<p>明文 = <code>SELECT * FROM joke WHERE joke LIKE '%</code> + <b>query</b> + <code>%' ORDER BY id ASC LIMIT 10</code></p>
<p>query 會被 <code>addslashes</code> 轉義（<code>'</code> → <code>\'</code>），無法直接注入。</p>
<p><b>攻擊</b>：用 <code>query="A"*10</code> 產生「乾淨 block」，替換 <code>query="A"*9+"' OR 1=1 -- "</code> 中含 <code>\\</code> 的 block → 單引號裸露 → 逃出字串。</p></div>

<div class="card"><h3>E3 · 加密無完整性（CWE-353）</h3>
<pre># 密文被拼接後仍被接受 → 明文被改變</pre></div>

<div class="card"><h3>安全對照</h3>
<pre>GET /safe-search?query=hello   → AES-GCM（含 tag）
GET /safe-result?n=..&amp;c=..&amp;t=.. → 篡改 → 403</pre></div>
"""


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)
    init_db()
    print("=" * 78)
    print(" ECBLab — ECB 加密 + Block Splicing（補強 natas28 缺口）")
    print(" 僅限本機教育用途")
    print("=" * 78)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" PREFIX: %r" % PREFIX)
    print(" SUFFIX: %r" % SUFFIX)
    print()
    print(" 練習：")
    print("   /search?query=hello      取得密文")
    print("   /result?q=<密文>         解密並執行")
    print("   /detect?q=<密文>         偵測 ECB 重複 block")
    print("   /safe-search, /safe-result  AES-GCM 對照")
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
