#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 frontendlab.py — 前端邏輯暴露靶場（補足「讀 JS / 看前端」能力缺口）
=============================================================================

 對應研究報告 CH06 S1（學習路徑缺口）與 CH02.1（可觀察性）。

 為什麼需要這個靶場？
   本專案先前的靶場都是「後端漏洞」——我能直接讀自己寫的 Python。
   但真實系統的**業務邏輯寫在前端**：隱藏欄位、未公開 API、參數規則、
   甚至前端硬編碼的加解密金鑰。**不讀 JS，就只看得到表層。**

   本靶場刻意把「可觀察性」當成主題：
   頁面上看到的 ≠ 系統實際支援的。

 ⚠ 刻意含漏洞，僅供本機教育用途。

 包含的問題：
   J1  JS 註解洩漏內部 API 路徑 ................ CWE-540
   J2  前端硬編碼加密金鑰 ...................... CWE-321 / CWE-798
   J3  隱藏參數（UI 沒有，後端接受） ........... CWE-472
   J4  未授權的隱藏 API 端點 ................... A01 / CWE-862
   J5  前端解密邏輯可被逆向（可偽造請求） ....... CWE-602
   J6  前端原始碼洩漏測試環境資訊 ............... CWE-489

 用法：
   python frontendlab.py 8920
   然後用瀏覽器開啟 http://127.0.0.1:8920/
   按 F12 → Sources / Network，練習從 JS 找線索
=============================================================================
"""

import base64
import hashlib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8920
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ★ J2：前端硬編碼的「加密金鑰」（真實系統常見的錯誤）
FRONTEND_KEY = "s3cr3t-frontend-key-2026"

PRICE_TABLE = {1: 1000, 2: 100, 3: 5000}
USERS = {"alice": {"password": "alice123", "role": "user", "id": 1},
         "admin": {"password": "Adm1n!Str0ng#2026", "role": "admin", "id": 99}}


def simple_encrypt(plain: str) -> str:
    """★ J5：與前端對稱的「加密」（教學用，非真加密）。

    前端有完全相同的實作——所以能被逆向。
    """
    raw = plain.encode("utf-8")
    key = FRONTEND_KEY.encode("utf-8")
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode()


def simple_decrypt(cipher_b64: str) -> str:
    try:
        data = base64.b64decode(cipher_b64)
    except Exception:                                        # noqa: BLE001
        raise ValueError("bad base64")
    key = FRONTEND_KEY.encode("utf-8")
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return out.decode("utf-8")


# ---------------------------------------------------------------------------
# ★ 前端 JavaScript（刻意包含可被觀察的線索）
# ---------------------------------------------------------------------------
FRONTEND_JS = r"""
/* ===========================================================================
 * app.js — 購物車前端邏輯
 * ===========================================================================
 * ⚠ 這個檔案「刻意」示範真實系統常見的前端問題。
 *   練習：按 F12 → Sources，找出下面六類線索。
 * ===========================================================================
 */

// ★ J2：「加密金鑰」硬編碼在前端（真實系統最常見的錯誤之一）
var ENC_KEY = "%(key)s";

// ★ J1：開發者註解洩漏了未公開的 API 路徑
// TODO: 結帳流程改走 /api/v2/checkout，舊的 /api/checkout 之後要移除
// FIXME: admin 後台端點 /api/admin/users 還沒有加權限檢查，上線前要補
// NOTE: 測試環境的 debug 端點 /api/debug/config 記得在正式環境關閉

// ★ J3：隱藏參數（UI 沒有，但後端接受）
var PRODUCT_META = {
  1: {name: "限量商品", price: 1000, internal_cost: 350, hidden_discount: "VIP50"},
  2: {name: "普通商品", price: 100,  internal_cost: 30,  hidden_discount: null},
  3: {name: "豪華組合", price: 5000, internal_cost: 1200, hidden_discount: "STAFF90"}
};

// ★ J5：前端「加密」函式（與後端對稱 → 可被逆向）
function encryptPayload(obj) {
  var plain = JSON.stringify(obj);
  var key = ENC_KEY;
  var bytes = [];
  for (var i = 0; i < plain.length; i++) {
    bytes.push(plain.charCodeAt(i) ^ key.charCodeAt(i %% key.length));
  }
  return btoa(String.fromCharCode.apply(null, bytes));
}

function decryptPayload(b64) {
  var raw = atob(b64);
  var out = "";
  for (var i = 0; i < raw.length; i++) {
    out += String.fromCharCode(raw.charCodeAt(i) ^ ENC_KEY.charCodeAt(i %% ENC_KEY.length));
  }
  return JSON.parse(out);
}

// ★ J6：洩漏測試環境資訊
var APP_CONFIG = {
  env: "staging",
  apiBase: "/api",
  adminBase: "/api/admin",
  debugBase: "/api/debug",
  version: "2.4.1-beta",
  buildDate: "2026-04-10",
  featureFlags: {newCheckout: true, allowPriceOverride: true, betaAdmin: true}
};

function addToCart(pid, qty) {
  var meta = PRODUCT_META[pid];
  var payload = {
    product_id: pid,
    qty: qty,
    price: meta.price * qty,
    // ★ J3：前端偷偷送出內部欄位
    internal_cost: meta.internal_cost,
    discount_code: meta.hidden_discount
  };
  // 打成「加密」形式送出（示範：前端加密完全無法保護邏輯）
  var enc = encryptPayload(payload);
  fetch("/api/cart/encrypted", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({data: enc})
  }).then(function (r) { return r.json(); })
    .then(function (j) { console.log("cart:", j); });
}

window.FrontendLab = {
  config: APP_CONFIG,
  products: PRODUCT_META,
  encrypt: encryptPayload,
  decrypt: decryptPayload,
  addToCart: addToCart
};
""" % {"key": FRONTEND_KEY}


# ---------------------------------------------------------------------------
# ★ 後端 API（刻意有未授權端點與隱藏參數）
# ---------------------------------------------------------------------------
CART = []


def init_nothing():
    pass


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>FrontendLab — 前端邏輯觀察練習</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:900px;
      margin:32px auto;line-height:1.7;color:#1b2430}}
 .warn{{background:#fdecea;border-left:5px solid #c0392b;padding:12px 16px;
       border-radius:8px;font-size:14px;margin-bottom:18px}}
 .hint{{background:#fff8e6;border-left:5px solid #d99b00;padding:12px 16px;
       border-radius:8px;font-size:14px;margin:14px 0}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
 .card{{border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;margin:12px 0;background:#f8fafc}}
 button{{padding:8px 16px;border-radius:8px;border:1px solid #c9d4e0;
        background:#fff;cursor:pointer;font-size:14px}}
</style></head><body>
<div class="warn"><b>⚠ 教學靶場：刻意在前端 JS 中留下六類線索。</b>
請按 <b>F12</b> → <b>Sources</b> 找 <code>/static/app.js</code>，
或到 <b>Network</b> 觀察請求。僅限本機使用。</div>
<h1>FrontendLab</h1>
<p>表面上，這只是一個購物車頁面。實際上，前端原始碼裡有六類線索：</p>
{{body}}
<h2>練習方式</h2>
<ol>
  <li>按 <b>F12</b>，切到 <b>Sources</b> 分頁，找到 <code>app.js</code></li>
  <li>閱讀註解（<code>// TODO</code>、<code>// FIXME</code>、<code>// NOTE</code>）</li>
  <li>尋找硬編碼的常數（金鑰、端點、feature flags）</li>
  <li>切到 <b>Network</b>，按下下方按鈕，觀察實際送出的請求</li>
  <li>試著用找到的線索，呼叫那些「畫面上看不到」的 API</li>
</ol>
<div class="hint"><b>核心觀念：</b>前端的一切都可被使用者看見與修改。
所以<b>前端的加密、驗證、隱藏欄位都不是安全機制</b>——
它們只是「讓事情看起來比較難」。</div>
<script src="/static/app.js"></script>
<script>
function doAdd(pid){{
  window.FrontendLab.addToCart(pid, 1);
  alert("已送出 pid=" + pid + "（請看 Network 分頁的請求內容）");
}}
</script>
</body></html>"""

INDEX_BODY = """
<div class="card"><h3>商品</h3>
<p>限量商品（id=1，1000 元）　<button onclick="doAdd(1)">加入購物車</button></p>
<p>普通商品（id=2，100 元）　<button onclick="doAdd(2)">加入購物車</button></p>
<p>豪華組合（id=3，5000 元）　<button onclick="doAdd(3)">加入購物車</button></p>
</div>
<p>觀察提示：按下按鈕後，Network 分頁會出現一個
<code>/api/cart/encrypted</code> 的 POST 請求，body 是 base64。
你能解開它嗎？（提示：金鑰就在 <code>app.js</code> 裡）</p>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "FrontendLab/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        # 刻意不加 CSP（方便教學觀察；安全版應加）
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8")

    def log_message(self, fmt, *args):
        sys.stderr.write("[FrontendLab] %s\n" % (fmt % args))

    # ---------------- GET ----------------
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._send(200, PAGE.format(body=INDEX_BODY))

        if path == "/static/app.js":
            return self._send(200, FRONTEND_JS, "application/javascript; charset=utf-8")

        # ★ J4：未授權的 admin API（前端註解已洩漏路徑）
        if path == "/api/admin/users":
            # 完全沒有權限檢查
            return self._json({
                "flag": "FLAG{frontend_lab_hidden_admin_api}",
                "note": "此端點無任何授權檢查——路徑是從 JS 註解找到的",
                "users": [{"id": 1, "username": "alice", "role": "user"},
                          {"id": 99, "username": "admin", "role": "admin"}],
            })

        # ★ J6：debug 端點（前端註解提到）
        if path == "/api/debug/config":
            return self._json({
                "flag": "FLAG{frontend_lab_debug_endpoint}",
                "env": "staging",
                "frontend_key": FRONTEND_KEY,       # ★ J2：洩漏金鑰
                "features": {"allowPriceOverride": True, "betaAdmin": True},
                "db": {"host": "localhost", "port": 5432, "user": "app"},
            })

        # ★ J3：隱藏參數生效的端點
        if path == "/api/product":
            pid = qs.get("id", ["1"])[0]
            if not pid.isdigit() or int(pid) not in PRICE_TABLE:
                return self._json({"error": "bad id"}, 400)
            p = int(pid)
            # ★ 隱藏參數：internal=1 會回傳內部成本（UI 從未顯示）
            if qs.get("internal", ["0"])[0] == "1":
                return self._json({
                    "flag": "FLAG{frontend_lab_hidden_parameter}",
                    "id": p, "price": PRICE_TABLE[p],
                    "internal_cost": {"1": 350, "2": 30, "3": 1200}[str(p)],
                    "note": "internal 參數未在 UI 出現，由 JS 的 PRODUCT_META 洩漏",
                })
            return self._json({"id": p, "price": PRICE_TABLE[p]})

        if path == "/api/cart":
            return self._json({"cart": CART})

        return self._json({"error": "not found"}, 404)

    # ---------------- POST ----------------
    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        if u.path == "/api/cart/encrypted":
            # ★ J5：後端接受「前端加密」的內容 → 可被逆向偽造
            try:
                body = json.loads(raw)
                plain = simple_decrypt(body.get("data", ""))
                item = json.loads(plain)
            except Exception as e:                            # noqa: BLE001
                return self._json({"error": "decrypt failed: %s" % e}, 400)

            # ★ J3：即使前端送了 internal_cost，後端也照單全收
            CART.append(item)
            return self._json({
                "ok": True,
                "received": item,
                "note": "此請求是前端加密的，但金鑰在前端 → 可自行偽造",
            })

        # ★ J4：未授權的價格覆寫端點
        if u.path == "/api/admin/price":
            try:
                body = json.loads(raw)
            except Exception:                                # noqa: BLE001
                return self._json({"error": "bad json"}, 400)
            return self._json({
                "ok": True,
                "flag": "FLAG{frontend_lab_price_override}",
                "note": "允許任意覆寫價格（featureFlags.allowPriceOverride）",
                "applied": body,
            })

        return self._json({"error": "not found"}, 404)


def main():
    print("=" * 76)
    print(" FrontendLab — 前端邏輯觀察靶場")
    print(" 補足「讀 JS / 看前端」能力缺口")
    print("=" * 76)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print()
    print(" 六類線索（請用 F12 自行尋找，不要先看原始碼）：")
    print("   J1 JS 註解洩漏內部 API 路徑")
    print("   J2 前端硬編碼加密金鑰")
    print("   J3 隱藏參數（UI 沒有、後端接受）")
    print("   J4 未授權的隱藏 API 端點")
    print("   J5 前端加密邏輯可被逆向")
    print("   J6 前端原始碼洩漏測試環境資訊")
    print("=" * 76)
    init_nothing()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
