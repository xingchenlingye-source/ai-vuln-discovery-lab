#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 buyLab_patched.py — A06 + A04 修補版
=============================================================================

 對應研究報告 CH02.4（修補驗證）與 CH06 S1。

 修補策略的核心差異（值得注意）：
   A06 的缺陷是**設計層**的，不是實作層的 ——
   所以修補不是「加檢查」，而是**改變設計**：

   B1 限購繞過   → 限購以「所有訂單」計算 + 資料庫唯一約束（原子性）
   B2 TOCTOU     → 改為**單一原子 UPDATE**（WHERE balance >= ?）並檢查受影響列數
   B3 客戶端價格 → **移除**價格參數，一律由伺服器從資料庫查
   B4 MD5        → PBKDF2-HMAC-SHA256 + per-user salt（標準庫可用）
   B5 弱隨機     → secrets.token_urlsafe()（CSPRNG），不允許 seed 注入
   B6 明文儲存   → 卡號加密（Fernet 式：HMAC 驗證 + XOR 混淆示範）＋ 只回末四碼

 註：B4 用 PBKDF2 是因為標準庫沒有 Argon2/bcrypt。
     實務上應使用 Argon2id（OWASP 現行建議），PBKDF2 是「可用但次佳」的選擇。

 用法：
   python buyLab_patched.py 8907
=============================================================================
"""

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8907
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "buylab_patched.db")

PBKDF2_ROUNDS = 200_000
_SECRET_FILE = os.path.join(BASE_DIR, ".buylab_secret")


def get_secret():
    """取得加密用密鑰（示範用；實務應由 KMS 管理）。"""
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(_SECRET_FILE, "wb") as f:
        f.write(key)
    return key


SECRET = get_secret()


def hash_password(password, salt=None):
    """B4 修補：PBKDF2-HMAC-SHA256 + per-user salt。"""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return salt.hex() + "$" + dk.hex()


def verify_password(stored, password):
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), PBKDF2_ROUNDS)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:                                        # noqa: BLE001
        return False


def encrypt_card(card_no):
    """B6 修補：卡號加密（示範用串流混淆 + HMAC 完整性）。

    真實系統應使用 AES-GCM（具認證的加密）。此處示範「不以明文儲存」的原則。
    """
    key = SECRET[:16]
    data = card_no.encode()
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    tag = hmac.new(SECRET, data, hashlib.sha256).digest()[:8]
    return base64.urlsafe_b64encode(out + tag).decode()


def decrypt_card(blob):
    raw = base64.urlsafe_b64decode(blob.encode())
    body, tag = raw[:-8], raw[-8:]
    key = SECRET[:16]
    data = bytes(b ^ key[i % len(key)] for i, b in enumerate(body))
    if not hmac.compare_digest(hmac.new(SECRET, data, hashlib.sha256).digest()[:8], tag):
        raise ValueError("integrity check failed")
    return data.decode()


def mask_card(card_no):
    return "**** **** **** " + card_no[-4:]


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS products")
    cur.execute("DROP TABLE IF EXISTS orders")
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS cards")

    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, "
                "price INTEGER, stock INTEGER, limit_per_user INTEGER)")
    # B1 修補：用唯一約束保證「每人每商品一筆」（資料庫層的原子性）
    cur.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "user_id INTEGER, product_id INTEGER, qty INTEGER, paid INTEGER, "
                "UNIQUE(user_id, product_id))")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
                "password_hash TEXT, role TEXT)")
    # B6 修補：卡號以密文儲存
    cur.execute("CREATE TABLE cards (id INTEGER PRIMARY KEY, user_id INTEGER, "
                "card_enc TEXT, balance INTEGER)")

    cur.executemany("INSERT INTO products VALUES (?,?,?,?,?)", [
        (1, "限量商品", 1000, 10, 1),
        (2, "普通商品", 100, 999, 0),
    ])
    cur.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "alice", hash_password("123456"), "user"),
        (2, "bob", hash_password("password"), "user"),
    ])
    cur.executemany("INSERT INTO cards VALUES (?,?,?,?)", [
        (1, 1, encrypt_card("4111111111111111"), 5000),
        (2, 2, encrypt_card("5500000000000004"), 5000),
    ])
    con.commit()
    con.close()


PAGE = """<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>BuyLab (PATCHED)</title>
<style>
 body{{font-family:"Microsoft JhengHei",system-ui,sans-serif;max-width:940px;
      margin:36px auto;line-height:1.7;color:#1b2430}}
 .ok{{background:#eefaf1;border-left:5px solid #2e9e5b;padding:12px 16px;
     border-radius:8px;font-size:14px;margin-bottom:20px}}
 code{{background:#eef2f7;padding:2px 6px;border-radius:4px;
      font-family:Consolas,monospace;font-size:13px}}
 pre{{background:#1e2733;color:#e6edf3;padding:12px 16px;border-radius:8px;
     overflow-x:auto;font-size:13px}}
</style></head><body>
<div class="ok"><b>✓ 這是修補版。</b>
A06 的設計缺陷以「改變設計」修正（原子操作、唯一約束、移除客戶端價格）；
A04 的加密缺陷以 PBKDF2 + CSPRNG + 加密儲存修正。</div>
<h1>BuyLab (PATCHED)</h1>
{body}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "BuyLab/2.0-patched"

    def _respond(self, code, body):
        payload = PAGE.format(body=body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[BuyLab-patched] %s\n" % (fmt % args))

    def _db(self):
        return sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._respond(200,
                "<p>端點：/buy /pay /reset /users /reset_token /cards</p>")

        # ---------------- B1 + B3 修補：下單 -------------------------
        if path == "/buy":
            uid = qs.get("uid", [""])[0]
            pid = qs.get("pid", [""])[0]
            qty = qs.get("qty", ["1"])[0]
            if not (uid.isdigit() and pid.isdigit() and qty.isdigit()):
                return self._respond(400, "<h2>參數錯誤</h2>")
            uid, pid, qty = int(uid), int(pid), int(qty)
            if qty <= 0 or qty > 100:
                return self._respond(400, "<h2>數量不合法</h2>")

            # B3 修補：完全忽略任何客戶端提供的 price（不再讀取該參數）

            con = self._db()
            cur = con.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")          # 取得寫入鎖
                # 價格由伺服器查詢（B3 修補）
                cur.execute("SELECT price, stock, limit_per_user FROM products WHERE id=?",
                            (pid,))
                row = cur.fetchone()
                if row is None:
                    cur.execute("ROLLBACK")
                    return self._respond(404, "<h2>商品不存在</h2>")
                price, stock, limit = row

                # B1 修補：限購以「所有訂單」計算（不再只看 paid=1）
                if limit > 0:
                    cur.execute("SELECT COALESCE(SUM(qty),0) FROM orders "
                                "WHERE user_id=? AND product_id=?", (uid, pid))
                    bought = cur.fetchone()[0]
                    if bought + qty > limit:
                        cur.execute("ROLLBACK")
                        return self._respond(403,
                            "<h2>超過限購</h2><p>已購 %d，限購 %d</p>"
                            % (bought, limit))

                # 原子扣庫存（B1 修補：WHERE stock >= ? 避免超賣）
                cur.execute("UPDATE products SET stock = stock - ? "
                            "WHERE id=? AND stock >= ?", (qty, pid, qty))
                if cur.rowcount != 1:
                    cur.execute("ROLLBACK")
                    return self._respond(400, "<h2>庫存不足</h2>")

                # 唯一約束提供資料庫層的最後防線
                try:
                    cur.execute("INSERT INTO orders (user_id, product_id, qty, paid) "
                                "VALUES (?,?,?,1)", (uid, pid, qty))
                except sqlite3.IntegrityError:
                    cur.execute("ROLLBACK")
                    return self._respond(403,
                        "<h2>超過限購</h2><p>資料庫唯一約束阻止了重複下單</p>")
                oid = cur.lastrowid
                cur.execute("COMMIT")
            except Exception:                                # noqa: BLE001
                try:
                    cur.execute("ROLLBACK")
                except Exception:                            # noqa: BLE001
                    pass
                con.close()
                return self._respond(500, "<h2>系統錯誤</h2>")
            con.close()
            return self._respond(200,
                "<h2>下單成功</h2><pre>order_id=%s\nqty=%s\n單價=%s（伺服器決定）</pre>"
                % (oid, qty, price))

        # ---------------- B2 修補：原子扣款 -------------------------
        if path == "/pay":
            uid = qs.get("uid", [""])[0]
            amount = qs.get("amount", [""])[0]
            if not (uid.isdigit() and amount.isdigit()):
                return self._respond(400, "<h2>參數錯誤</h2>")
            uid, amount = int(uid), int(amount)
            if amount <= 0:
                return self._respond(400, "<h2>金額不合法</h2>")

            con = self._db()
            cur = con.cursor()
            # B2 修補：檢查與扣款合為**單一原子 UPDATE**，
            # 由資料庫的 WHERE 條件保證「餘額足夠」與「扣款」不可分割
            cur.execute("UPDATE cards SET balance = balance - ? "
                        "WHERE user_id = ? AND balance >= ?", (amount, uid, amount))
            affected = cur.rowcount
            if affected != 1:
                con.close()
                return self._respond(400,
                    "<h2>餘額不足</h2><p>（原子檢查失敗：餘額不足或不存在的帳號）</p>")
            cur.execute("SELECT balance FROM cards WHERE user_id=?", (uid,))
            new_balance = cur.fetchone()[0]
            con.commit()
            con.close()
            return self._respond(200,
                "<h2>扣款成功</h2><pre>扣款 %d，餘額 %d</pre>" % (amount, new_balance))

        if path == "/reset":
            con = self._db()
            cur = con.cursor()
            cur.execute("UPDATE cards SET balance=5000 WHERE user_id=1")
            cur.execute("DELETE FROM orders")
            cur.execute("UPDATE products SET stock=10 WHERE id=1")
            con.commit()
            con.close()
            return self._respond(200, "<h2>已重設</h2>")

        # ---------------- B4 修補：PBKDF2 雜湊 ----------------------
        if path == "/users":
            con = self._db()
            cur = con.cursor()
            cur.execute("SELECT id, username, password_hash FROM users")
            rows = cur.fetchall()
            con.close()
            body = "<h2>users（PBKDF2 + per-user salt）</h2><pre>%s</pre>" % "\n".join(
                "%s | %s | %s..." % (r[0], r[1], r[2][:40]) for r in rows)
            return self._respond(200, body)

        # ---------------- B5 修補：CSPRNG token ---------------------
        if path == "/reset_token":
            uid = qs.get("uid", ["1"])[0]
            if "seed" in qs:
                # B5 修補：拒絕任何 seed 注入
                return self._respond(400,
                    "<h2>拒絕</h2><p>不接受 seed 參數（token 必須不可預測）</p>")
            token = secrets.token_urlsafe(32)          # CSPRNG
            return self._respond(200,
                "<h2>重設 token</h2><pre>uid=%s\ntoken=%s</pre>"
                "<p>（由 secrets 模組產生，無法預測）</p>" % (uid, token))

        # ---------------- B6 修補：只回末四碼 -----------------------
        if path == "/cards":
            con = self._db()
            cur = con.cursor()
            cur.execute("SELECT id, user_id, card_enc, balance FROM cards")
            rows = cur.fetchall()
            con.close()
            out = []
            for cid, uid_, enc, bal in rows:
                try:
                    last4 = mask_card(decrypt_card(enc))
                except Exception:                            # noqa: BLE001
                    last4 = "（解密失敗）"
                out.append("%s | uid=%s | %s | balance=%s\n    密文=%s..."
                           % (cid, uid_, last4, bal, enc[:40]))
            body = ("<h2>cards（卡號加密儲存）</h2><pre>%s</pre>"
                    "<p>僅顯示末四碼；完整卡號不以明文落地。</p>" % "\n".join(out))
            return self._respond(200, body)

        return self._respond(404, "<h2>404</h2>")


def main():
    init_db()
    print("=" * 74)
    print(" BuyLab (PATCHED) — A06 / A04 修補版")
    print("=" * 74)
    print(" 監聽: http://%s:%d/" % (HOST, PORT))
    print(" 修正: 原子操作、唯一約束、伺服器定價、PBKDF2、CSPRNG、加密儲存")
    print("=" * 74)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止]")
        httpd.server_close()


if __name__ == "__main__":
    main()
