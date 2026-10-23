#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 buyLab.py — A06 不安全設計 + A04 加密失效 練習靶場
=============================================================================

 對應研究報告 CH06 S1（OWASP Top 10:2025 A04 / A06）。

 補足前兩個靶場未涵蓋的部分：
   A04 Cryptographic Failures —— 原本完全沒有專門靶場
   A06 Insecure Design        —— 原本完全沒有設計層缺陷靶場

 ⚠ 刻意含漏洞，僅供本機教育用途。

 包含的漏洞：
   B1  限購可繞過（先檢查後寫入，無鎖） ...... A06 / CWE-799 / CWE-362
   B2  TOCTOU 競態（餘額檢查與扣款分離） ..... A06 / CWE-367
   B3  價格由客戶端提供（信任邊界錯誤） ...... A06 / CWE-472
   B4  MD5 儲存密碼（無 salt） ............... A04 / CWE-916
   B5  弱隨機 token（可預測） ................ A04 / CWE-338
   B6  敏感資料以明文儲存與傳輸 .............. A04 / CWE-311

 用法：
   python buyLab.py 8906
=============================================================================
"""

import hashlib
import json
import os
import random
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8906
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "buylab.db")

LOCK = threading.Lock()          # 存在但 B1/B2 刻意不使用
RACE_LOG = []


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS products")
    cur.execute("DROP TABLE IF EXISTS orders")
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS cards")

    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, "
                "price INTEGER, stock INTEGER, limit_per_user INTEGER)")
    cur.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "user_id INTEGER, product_id INTEGER, qty INTEGER, paid INTEGER)")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
                "password_hash TEXT, role TEXT)")
    cur.execute("CREATE TABLE cards (id INTEGER PRIMARY KEY, user_id INTEGER, "
                "card_no TEXT, balance INTEGER)")

    cur.executemany("INSERT INTO products VALUES (?,?,?,?,?)", [
        (1, "限量商品", 1000, 10, 1),        # 每人限購 1 件
        (2, "普通商品", 100, 999, 0),        # 不限購
    ])
    # B4：MD5 無 salt
    cur.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "alice", hashlib.md5(b"123456").hexdigest(), "user"),
        (2, "bob", hashlib.md5(b"password").hexdigest(), "user"),
    ])
    # B6：卡號與餘額明文儲存
    cur.executemany("INSERT INTO cards VALUES (?,?,?,?)", [
        (1, 1, "4111111111111111", 5000),
        (2, 2, "5500000000000004", 5000),
    ])
    con.commit()
    con.close()


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>BuyLab — A06 設計缺陷 + A04 加密失效</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:940px;
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
<div class="warn"><b>⚠ 刻意含漏洞的教學靶場（A06 不安全設計 + A04 加密失效）。</b>
僅限本機使用。帳號 alice/123456。</div>
<h1>BuyLab</h1>
{body}
</body></html>"""

INDEX = """
<div class="ep"><h3>B1 · 限購可繞過 — A06 / CWE-799</h3>
<pre>GET /buy?uid=1&amp;pid=1&amp;qty=1     # 重複呼叫，繞過「每人限購 1 件」</pre></div>
<div class="ep"><h3>B2 · TOCTOU 競態 — A06 / CWE-367</h3>
<pre>GET /pay?uid=1&amp;amount=4000      # 餘額檢查與扣款分離，併發可重複扣</pre></div>
<div class="ep"><h3>B3 · 價格由客戶端提供 — A06 / CWE-472</h3>
<pre>GET /buy?uid=1&amp;pid=2&amp;qty=1&amp;price=1   # 客戶端可自訂價格</pre></div>
<div class="ep"><h3>B4 · MD5 無 salt 密碼 — A04 / CWE-916</h3>
<pre>GET /users                            # 檢視雜湊</pre></div>
<div class="ep"><h3>B5 · 弱隨機 token — A04 / CWE-338</h3>
<pre>GET /reset_token?uid=1&amp;seed=42       # 可預測</pre></div>
<div class="ep"><h3>B6 · 明文儲存敏感資料 — A04 / CWE-311</h3>
<pre>GET /cards                            # 卡號與餘額明文</pre></div>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "BuyLab/1.0"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[BuyLab] %s\n" % (fmt % args))

    def _db(self):
        return sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._respond(200, INDEX)

        # ---------------- B1：限購可繞過（check-then-act，無鎖）-------
        if path == "/buy":
            uid = qs.get("uid", [""])[0]
            pid = qs.get("pid", [""])[0]
            qty = qs.get("qty", ["1"])[0]
            cli_price = qs.get("price", [None])[0]
            if not (uid.isdigit() and pid.isdigit() and qty.isdigit()):
                return self._respond(400, "<h2>參數錯誤</h2>")
            uid, pid, qty = int(uid), int(pid), int(qty)

            con = self._db()
            cur = con.cursor()
            # 步驟 1：檢查（read）
            cur.execute("SELECT stock, limit_per_user, price FROM products WHERE id=?",
                        (pid,))
            row = cur.fetchone()
            if row is None:
                con.close()
                return self._respond(404, "<h2>商品不存在</h2>")
            stock, limit, db_price = row

            if stock < qty:
                con.close()
                return self._respond(400, "<h2>庫存不足</h2>")

            # ★ B1：限購檢查只查「已付款訂單數」，且與寫入之間無鎖
            if limit > 0:
                cur.execute("SELECT COALESCE(SUM(qty),0) FROM orders "
                            "WHERE user_id=? AND product_id=? AND paid=1", (uid, pid))
                bought = cur.fetchone()[0]
                if bought + qty > limit:
                    con.close()
                    return self._respond(403,
                        "<h2>超過限購</h2><p>已購 %d，限購 %d</p>" % (bought, limit))

            # ★ B3：價格由客戶端提供，且未驗證
            price = int(cli_price) if cli_price and cli_price.lstrip("-").isdigit() else db_price

            # 步驟 2：寫入（act）—— 中間沒有鎖，可被併發穿插
            time.sleep(0.02)                      # 放大競態視窗（教學用）
            cur.execute("UPDATE products SET stock = stock - ? WHERE id=?", (qty, pid))
            cur.execute("INSERT INTO orders (user_id, product_id, qty, paid) "
                        "VALUES (?,?,?,0)", (uid, pid, qty))
            con.commit()
            oid = cur.lastrowid
            con.close()
            return self._respond(200,
                "<h2>下單成功</h2><pre>order_id=%s\nqty=%s\n單價=%s（DB 原價 %s）</pre>"
                "<p>FLAG{a06_limit_bypass}</p><p>付款：<code>/pay_order?oid=%s</code></p>"
                % (oid, qty, price, db_price, oid))

        # ---------------- 付款（供 B1 限購檢查使用）------------------
        if path == "/pay_order":
            oid = qs.get("oid", [""])[0]
            if not oid.isdigit():
                return self._respond(400, "<h2>參數錯誤</h2>")
            con = self._db()
            cur = con.cursor()
            cur.execute("UPDATE orders SET paid=1 WHERE id=?", (int(oid),))
            con.commit()
            con.close()
            return self._respond(200, "<h2>訂單 %s 已付款</h2>" % oid)

        # ---------------- B2：TOCTOU 競態（餘額） -------------------
        if path == "/pay":
            uid = qs.get("uid", [""])[0]
            amount = qs.get("amount", [""])[0]
            if not (uid.isdigit() and amount.isdigit()):
                return self._respond(400, "<h2>參數錯誤</h2>")
            uid, amount = int(uid), int(amount)

            con = self._db()
            cur = con.cursor()
            # ★ B2：檢查與扣款分離，中間沒有交易鎖
            cur.execute("SELECT balance FROM cards WHERE user_id=?", (uid,))
            row = cur.fetchone()
            if row is None:
                con.close()
                return self._respond(404, "<h2>無卡片</h2>")
            balance = row[0]
            if balance < amount:
                con.close()
                return self._respond(400,
                    "<h2>餘額不足</h2><p>餘額 %d，欲扣 %d</p>" % (balance, amount))

            time.sleep(0.05)          # ★ 放大 TOCTOU 視窗
            cur.execute("UPDATE cards SET balance = balance - ? WHERE user_id=?",
                        (amount, uid))
            con.commit()
            cur.execute("SELECT balance FROM cards WHERE user_id=?", (uid,))
            new_balance = cur.fetchone()[0]
            con.close()
            return self._respond(200,
                "<h2>扣款成功</h2><pre>扣款 %d，餘額 %d</pre><p>FLAG{a06_toctou}</p>"
                % (amount, new_balance))

        # ---------------- B2 觀察：重設餘額（測試用）----------------
        if path == "/reset":
            con = self._db()
            cur = con.cursor()
            cur.execute("UPDATE cards SET balance=5000 WHERE user_id=1")
            cur.execute("DELETE FROM orders")
            cur.execute("UPDATE products SET stock=10 WHERE id=1")
            con.commit()
            con.close()
            return self._respond(200, "<h2>已重設</h2>")

        # ---------------- B4 觀察：使用者雜湊 -----------------------
        if path == "/users":
            con = self._db()
            cur = con.cursor()
            cur.execute("SELECT id, username, password_hash FROM users")
            rows = cur.fetchall()
            con.close()
            body = "<h2>users</h2><pre>%s</pre><p>md5('123456')=%s</p>" % (
                "\n".join("%s | %s | %s" % r for r in rows),
                hashlib.md5(b"123456").hexdigest())
            return self._respond(200, body)

        # ---------------- B5：弱隨機 token -------------------------
        if path == "/reset_token":
            uid = qs.get("uid", ["1"])[0]
            seed = qs.get("seed", [None])[0]
            # ★ B5：可注入 seed / 使用 Mersenne Twister（可從輸出推回狀態）
            if seed and seed.lstrip("-").isdigit():
                random.seed(int(seed))
            token = "%06d" % random.randint(1, 999999)
            # ★ B5：token 也存成 md5（無 salt）
            return self._respond(200,
                "<h2>重設 token</h2><pre>uid=%s\ntoken=%s\ntoken_md5=%s</pre>"
                "<p>FLAG{a04_weak_random}</p>"
                % (uid, token, hashlib.md5(token.encode()).hexdigest()))

        # ---------------- B6 觀察：明文卡號 -------------------------
        if path == "/cards":
            con = self._db()
            cur = con.cursor()
            cur.execute("SELECT id, user_id, card_no, balance FROM cards")
            rows = cur.fetchall()
            con.close()
            body = "<h2>cards（明文儲存）</h2><pre>%s</pre>" % "\n".join(
                "%s | uid=%s | %s | balance=%s" % r for r in rows)
            return self._respond(200, body)

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    print("=" * 74)
    print(" BuyLab — A06 不安全設計 + A04 加密失效")
    print(" 僅限本機教育用途")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 端點: /buy /pay_order /pay /reset /users /reset_token /cards")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
