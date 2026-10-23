#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_buylab_patched.py — A06 / A04 修補版驗證
=============================================================================
 對應研究報告 CH02.4：① 攻擊失效　② 功能保留

 競態類修補（B2）的驗證必須同樣用**並發**測試——
 否則「單次成功」看起來沒問題，但實際仍可被併發繞過。

 用法：
   python verify_buylab_patched.py 8907
=============================================================================
"""

import concurrent.futures
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8907
BASE = "http://127.0.0.1:%d" % PORT
fix_results = []
func_results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=30) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def check(kind, name, passed, evidence):
    (fix_results if kind == "fix" else func_results).append((name, passed, evidence))


def show(kind, title):
    rows = fix_results if kind == "fix" else func_results
    print("\n" + "=" * 74)
    print(" %s" % title)
    print("=" * 74)
    for name, passed, ev in rows:
        print("\n[%s] %s" % ("OK  " if passed else "FAIL", name))
        for line in ev.splitlines():
            print("       " + line)
    ok = sum(1 for _, p, _ in rows if p)
    print("\n  → %d/%d" % (ok, len(rows)))
    return ok, len(rows)


def main():
    print("=" * 74)
    print(" A06 / A04 修補版驗證")
    print(" 目標：%s" % BASE)
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        sys.exit(1)

    # ---------- B1 修補：限購無法繞過 ----------
    get("/reset")
    ok_count = 0
    for i in range(3):
        st_i, body_i = get("/buy?uid=1&pid=1&qty=1")
        if st_i == 200 and "下單成功" in body_i:
            ok_count += 1
    check("fix", "B1 限購無法繞過",
          ok_count == 1,
          "請求   : 連續 3 次 GET /buy?uid=1&pid=1&qty=1（限購 1 件）\n"
          "預期   : 僅 1 次成功（第 2、3 次應被唯一約束/限購規則拒絕）\n"
          "實際   : 成功 %d/3 次" % ok_count)

    # ---------- B2 修補：併發扣款不會超額 ----------
    get("/reset")                       # 餘額 5000
    def pay(_):
        return get("/pay?uid=1&amount=4000")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        res = list(ex.map(pay, range(3)))
    ok_pay = sum(1 for s, b in res if s == 200 and "扣款成功" in b)
    # 讀取最終餘額：用一次小額扣款探測（會被記錄）
    st_f, body_f = get("/pay?uid=1&amount=1000")
    check("fix", "B2 併發扣款不超額（原子性）",
          ok_pay == 1,
          "請求   : 併發 3 筆 GET /pay?uid=1&amount=4000（餘額 5000）\n"
          "預期   : 僅 1 筆成功（原子 UPDATE 的 WHERE balance >= ? 保證）\n"
          "實際   : 成功 %d/3 筆；後續 1000 元扣款回應 HTTP %s" % (ok_pay, st_f))

    # ---------- B3 修補：忽略客戶端價格 ----------
    get("/reset")
    st3, b3 = get("/buy?uid=1&pid=2&qty=1&price=1")
    m = re.search(r"單價=(\d+)", b3)
    server_price = int(m.group(1)) if m else -1
    check("fix", "B3 價格由伺服器決定",
          server_price == 100,
          "請求   : GET /buy?uid=1&pid=2&qty=1&price=1（DB 原價 100）\n"
          "預期   : 採用 DB 價格 100（忽略客戶端 price=1）\n"
          "實際   : 單價 = %s" % server_price)

    # ---------- B4 修補：不再使用 MD5 ----------
    st4, b4 = get("/users")
    md5_123456 = hashlib.md5(b"123456").hexdigest()
    no_md5 = md5_123456 not in b4.lower()
    has_salt = "$" in b4
    check("fix", "B4 密碼改用 PBKDF2 + salt",
          no_md5 and has_salt,
          "請求   : GET /users\n"
          "預期   : 不再出現 md5('123456')，且雜湊含 salt 分隔符\n"
          "實際   : md5 未出現 = %s；含 salt = %s" % (no_md5, has_salt))

    # ---------- B5 修補：token 不可預測、拒絕 seed ----------
    st5a, b5a = get("/reset_token?uid=1&seed=12345")
    st5b, b5b = get("/reset_token?uid=1")
    st5c, b5c = get("/reset_token?uid=1")
    seed_rejected = (st5a == 400)
    t1 = re.search(r"token=([A-Za-z0-9_\-]+)", b5b)
    t2 = re.search(r"token=([A-Za-z0-9_\-]+)", b5c)
    differs = bool(t1 and t2 and t1.group(1) != t2.group(1))
    long_enough = bool(t1 and len(t1.group(1)) >= 32)
    check("fix", "B5 token 不可預測（CSPRNG）",
          seed_rejected and differs and long_enough,
          "請求 A : GET /reset_token?uid=1&seed=12345 → HTTP %s（預期 400 拒絕）\n"
          "請求 B : GET /reset_token?uid=1 → token 長度 %s\n"
          "請求 C : GET /reset_token?uid=1 → 與 B 不同 = %s\n"
          "預期   : 拒絕 seed；兩次 token 不同；長度 >= 32\n"
          "實際   : 拒絕 seed=%s；不同=%s；足夠長=%s"
          % (st5a, len(t1.group(1)) if t1 else 0, differs,
             seed_rejected, differs, long_enough))

    # ---------- B6 修補：卡號不以明文儲存 ----------
    st6, b6 = get("/cards")
    plain_card = bool(re.search(r"4111111111111111", b6))
    only_last4 = bool(re.search(r"\*{4} \*{4} \*{4} \d{4}", b6))
    check("fix", "B6 卡號加密儲存，僅顯示末四碼",
          (not plain_card) and only_last4,
          "請求   : GET /cards\n"
          "預期   : 不出現完整卡號；只顯示末四碼\n"
          "實際   : 出現完整卡號 = %s；僅末四碼 = %s" % (plain_card, only_last4))

    # ================= 條件 ②：功能保留 =================
    get("/reset")
    st_f1, b_f1 = get("/buy?uid=1&pid=2&qty=2")
    check("func", "正常下單仍成功（不限購商品）",
          st_f1 == 200 and "下單成功" in b_f1,
          "請求   : GET /buy?uid=1&pid=2&qty=2\n預期   : 200\n實際   : HTTP %s" % st_f1)

    get("/reset")
    st_f2, b_f2 = get("/pay?uid=1&amount=1000")
    check("func", "正常扣款仍成功（餘額足夠）",
          st_f2 == 200 and "扣款成功" in b_f2,
          "請求   : GET /pay?uid=1&amount=1000（餘額 5000）\n預期   : 200\n實際   : HTTP %s" % st_f2)

    st_f3, b_f3 = get("/reset_token?uid=1")
    check("func", "可正常產生 token",
          st_f3 == 200 and "token=" in b_f3,
          "請求   : GET /reset_token?uid=1\n預期   : 200 並附 token\n實際   : HTTP %s" % st_f3)

    st_f4, b_f4 = get("/users")
    check("func", "使用者清單仍可查詢",
          st_f4 == 200 and "alice" in b_f4,
          "請求   : GET /users\n預期   : 200\n實際   : HTTP %s" % st_f4)

    f_ok, f_tot = show("fix", "設計/加密缺陷修補（6 項）")
    g_ok, g_tot = show("func", "功能保留（4 項）")

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    print("  攻擊失效 : %d/%d %s" % (f_ok, f_tot, "✓" if f_ok == f_tot else "✗"))
    print("  功能保留 : %d/%d %s" % (g_ok, g_tot, "✓" if g_ok == g_tot else "✗"))
    if f_ok == f_tot and g_ok == g_tot:
        print("\n  ✓ 修補驗證通過：設計缺陷與加密缺陷皆已修正，功能未受影響。")
    else:
        print("\n  ✗ 未通過，請檢查上列 FAIL 項目。")
    print("=" * 74)


if __name__ == "__main__":
    main()
