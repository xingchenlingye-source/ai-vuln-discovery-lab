#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 cryptolab.py — XOR / known-plaintext 加密學攻擊靶場
=============================================================================

 對應研究報告 CH06 S1 與 Natas natas11 的補強缺口。

 為什麼補這個？
   本專案有「弱隨機」（CWE-338）與「弱雜湊」（CWE-916），
   但**沒有「加密學層面的偽造攻擊」**——
   而 Natas natas11 正是用 known-plaintext 推出 XOR 金鑰。

 ⚠ 刻意含漏洞，僅供本機教育用途。

 包含的漏洞：
   X1  固定 XOR 金鑰加密 cookie（known-plaintext） ...... CWE-327 / CWE-330
   X2  XOR 金鑰重用（crib dragging） .................... CWE-323
   X3  可預測 token（時間戳 + 固定字串） ................ CWE-330
   X4  加密但無完整性驗證（可篡改密文） ................. CWE-353

 安全對照：
   - HMAC-SHA256 簽章（完整性 + 來源）
   - CSPRNG token（secrets）
   - AES 風格的「加密 + 認證」概念（本機模擬）

 用法：
   python cryptolab.py 8951
=============================================================================
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8951

# ===== 金鑰 =====
# ★ X1：固定的短金鑰（會被 known-plaintext 推導）
XOR_KEY = b"kBSw"
# ★ 安全對照：HMAC 用的強金鑰（CSPRNG 產生）
HMAC_KEY = secrets.token_bytes(32)

# ★ X3：可預測 token 的固定前綴
TOKEN_PREFIX = "natas_crypto_"

# 已知的預設設定（攻擊者可以猜到）
DEFAULT_SETTINGS = {"user": "guest", "role": "user", "showflag": False}
SECRET_SETTINGS = {"user": "admin", "role": "admin", "showflag": True}


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return xor_encrypt(data, key)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>CryptoLab — XOR / known-plaintext</title>
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
<div class="warn"><b>⚠ 教學靶場：刻意使用弱加密。</b>
XOR 不是加密，只是混淆。僅限本機使用。</div>
<h1>CryptoLab</h1>
{body}
</body></html>"""

INDEX_BODY = """
<div class="card"><h3>X1 · 固定 XOR 金鑰加密 cookie（CWE-327）</h3>
<p>伺服器把你的設定用固定 XOR 金鑰加密後放在 cookie。</p>
<pre>GET /profile                    → 看 Set-Cookie
# cookie 解碼後是 {"user":"guest","role":"user","showflag":false}</pre>
<p><b>攻擊</b>：用已知明文 XOR 密文 → 推導金鑰 → 偽造 <code>showflag:true</code></p></div>

<div class="card"><h3>X2 · XOR 金鑰重用（CWE-323）</h3>
<pre>GET /msg?id=1    → 加密訊息 1
GET /msg?id=2    → 加密訊息 2
# 兩者用同一個金鑰 → XOR 兩密文 = XOR 兩明文（金鑰被消掉）</pre></div>

<div class="card"><h3>X3 · 可預測 token（CWE-330）</h3>
<pre>GET /token                       → 觀察 token 格式
# token = 前綴 + 時間戳 + 短隨機數 → 可預測</pre></div>

<div class="card"><h3>X4 · 加密但無完整性驗證（CWE-353）</h3>
<pre># 改動密文的任何一個位元 → 解密後內容改變，但伺服器不檢查 → 接受</pre></div>

<div class="card"><h3>安全對照</h3>
<pre>GET /safe/profile    → HMAC 簽章（改動即被偵測）
GET /safe/token      → CSPRNG token</pre></div>
"""


# ===== 加密訊息（X2 用）=====
MESSAGES = {
    1: b"FLAG{crypto_key_reuse_detected}",
    2: b"crypto_lab_alpha_second_msg_001",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "CryptoLab/1.0"

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

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        cookie = self.headers.get("Cookie", "")

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY))

        # ===== X1：固定 XOR 金鑰加密的 profile =====
        if path == "/profile":
            # 解析現有 cookie（沒有就用預設）
            settings = dict(DEFAULT_SETTINGS)
            m = None
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("profile="):
                    m = part[len("profile="):]
            if m:
                try:
                    pt = xor_decrypt(b64d(m), XOR_KEY).decode("utf-8", "replace")
                    settings = json.loads(pt)
                except Exception:                            # noqa: BLE001
                    pass
            pt = json.dumps(settings, separators=(",", ":"))
            ct = b64e(xor_encrypt(pt.encode(), XOR_KEY))
            resp = {
                "settings": settings,
                "cookie_raw": ct,
                "hint": "cookie = base64(xor(json, key))；key 固定",
                "flag": ("FLAG{xor_known_plaintext_attack}" if settings.get("showflag")
                         else None),
            }
            return self._json(resp, extra={"Set-Cookie": "profile=" + ct + "; Path=/"})

        # ===== X2：XOR 金鑰重用的加密訊息 =====
        if path == "/msg":
            mid = qs.get("id", ["1"])[0]
            try:
                mid_i = int(mid)
            except ValueError:
                return self._json({"error": "bad id"}, 400)
            if mid_i not in MESSAGES:
                return self._json({"error": "not found"}, 404)
            ct = b64e(xor_encrypt(MESSAGES[mid_i], XOR_KEY))
            return self._json({
                "id": mid_i, "ciphertext": ct,
                "note": "所有訊息使用**同一個金鑰**（XOR 重用）",
            })

        # ===== X3：可預測 token =====
        if path == "/token":
            # ★ 漏洞：前綴固定 + 時間戳 + 小範圍隨機
            ts = int(time.time() * 1000)
            rnd = secrets.randbelow(1000)
            token = "%s%d_%03d" % (TOKEN_PREFIX, ts, rnd)
            return self._json({
                "token": token,
                "format": "<prefix><unix_ms>_<3-digit random>",
                "note": "★ 時間戳可預測、隨機範圍只有 1000",
                "flag": "FLAG{predictable_token_timestamp}",
            })

        # ===== X4：加密但無完整性（接受任意密文）=====
        if path == "/echo":
            data = qs.get("d", [""])[0]
            if not data:
                return self._json({"error": "缺少 d"}, 400)
            try:
                pt = xor_decrypt(b64d(data), XOR_KEY)
                return self._json({
                    "decrypted": pt.decode("utf-8", "replace"),
                    "note": "★ 沒有完整性驗證：改動密文後仍被解密接受",
                    "flag": "FLAG{crypto_no_integrity}",
                })
            except Exception as e:                           # noqa: BLE001
                return self._json({"error": str(e)}, 400)

        # ===== 安全對照 1：HMAC 簽章 =====
        if path == "/safe/profile":
            settings = dict(DEFAULT_SETTINGS)
            m = None
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("sprofile="):
                    m = part[len("sprofile="):]
            if m:
                try:
                    raw, sig = m.rsplit(".", 1)
                    expected = hmac.new(HMAC_KEY,
                                        b64d(raw), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(sig, expected):
                        return self._json({
                            "ok": False,
                            "error": "簽章驗證失敗（內容被竄改）",
                            "safe": True,
                        }, 403)
                    settings = json.loads(b64d(raw).decode())
                except Exception:                            # noqa: BLE001
                    return self._json({"error": "格式錯誤"}, 400)
            raw = b64e(json.dumps(settings, separators=(",", ":")).encode())
            sig = hmac.new(HMAC_KEY, b64d(raw), hashlib.sha256).hexdigest()
            val = raw + "." + sig
            return self._json({
                "settings": settings,
                "cookie_raw": val,
                "note": "✓ HMAC-SHA256 簽章：任何竄改都會被偵測",
                "flag": ("FLAG{safe_hmac_verified}" if settings.get("showflag") else None),
            }, extra={"Set-Cookie": "sprofile=" + val + "; Path=/"})

        # ===== 安全對照 2：CSPRNG token =====
        if path == "/safe/token":
            token = secrets.token_urlsafe(32)      # 256-bit 熵
            return self._json({
                "token": token,
                "entropy_bits": 256,
                "note": "✓ secrets.token_urlsafe()：無法預測、無時間戳",
            })

        return self._json({"error": "not found"}, 404)


def main():
    if HOST not in ("127.0.0.1", "localhost"):
        print("⛔ 僅允許綁定 127.0.0.1")
        sys.exit(2)
    print("=" * 78)
    print(" CryptoLab — XOR / known-plaintext 加密學攻擊")
    print(" 僅限本機教育用途")
    print("=" * 78)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print()
    print(" 練習：")
    print("   X1 固定 XOR 金鑰 : GET /profile（觀察 cookie）")
    print("   X2 金鑰重用      : GET /msg?id=1 與 /msg?id=2")
    print("   X3 可預測 token  : GET /token")
    print("   X4 無完整性驗證  : GET /echo?d=<base64>")
    print("   安全對照         : GET /safe/profile、/safe/token")
    print("=" * 78)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
