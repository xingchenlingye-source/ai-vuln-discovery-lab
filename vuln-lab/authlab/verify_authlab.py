#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_authlab.py — A01 / A10 漏洞驗證（確定性裁判）
=============================================================================
 對應研究報告 CH02.1「發現與驗證分離」與 CH06 S1。

 每個測試都以「可觀察的證據」判定，不依賴閱讀程式碼的推論。

 用法：
   python verify_authlab.py [port]
=============================================================================
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path):
    """回傳 (status, body)。4xx/5xx 也正常回傳，不拋例外。"""
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
# V1 · IDOR 水平越權 — A01 / CWE-639
# 假設：uid=1（alice）能讀取 doc=201（bob 的文件）
# ---------------------------------------------------------------------------
def v1_idor():
    st, body = get("/doc?uid=1&doc=201")
    leaked = "FLAG{idor_read_bob_private_document}" in body
    ev = [
        "請求      : GET /doc?uid=1&doc=201   （alice 讀 bob 的文件）",
        "預期漏洞  : 回傳 200 且包含 bob 的私人內容",
        "實際      : HTTP %s，機密外洩=%s" % (st, leaked),
        "根因      : 只查詢文件、未驗證 `documents.owner_id` 是否等於當前 uid",
        "修補方向  : 查詢時加入 owner_id 條件；或先取文件再比對 owner_id，不符回 404（非 403，避免洩漏存在性）",
    ]
    check("V1 IDOR 水平越權", "A01 / CWE-639", leaked and st == 200, "\n".join(ev))


# ---------------------------------------------------------------------------
# V2 · 缺省允許（文件不存在卻回 200）— A01 / CWE-862
# ---------------------------------------------------------------------------
def v2_default_allow():
    st, body = get("/doc?uid=1&doc=999999")
    ev = [
        "請求      : GET /doc?uid=1&doc=999999   （不存在的文件）",
        "預期漏洞  : 回 200 而非 404（暴露「查詢邏輯」並混淆狀態）",
        "實際      : HTTP %s" % st,
        "根因      : 查無資料時沒有明確拒絕，而是走「正常回應」分支",
        "修補方向  : 查無資料一律 404；授權失敗與資源不存在回應應一致（避免 enumeration）",
    ]
    check("V2 缺省允許（CWE-862）", "A01 / CWE-862", st == 200, "\n".join(ev))


# ---------------------------------------------------------------------------
# V3 · 錯誤訊息洩漏 — A10 / CWE-209
# ---------------------------------------------------------------------------
def v3_error_leak():
    st, body = get("/doc?uid=1&doc=abc")
    leaked = ("ValueError" in body) or ("invalid literal" in body)
    ev = [
        "請求      : GET /doc?uid=1&doc=abc   （非數字參數）",
        "預期漏洞  : 回應包含原始例外文字（型別、函式名、參數值）",
        "實際      : HTTP %s，例外外洩=%s" % (st, leaked),
        "根因      : 直接把例外字串放進回應，未改用通用錯誤頁",
        "修補方向  : 對外只回通用訊息 + 錯誤識別碼；詳細例外寫入內部日誌（見 A09）",
        "OWASP 對照: A10 官方 Scenario #2 明確描述此情境——攻擊者藉錯誤訊息進行偵察",
    ]
    check("V3 錯誤訊息洩漏", "A10 / CWE-209", leaked, "\n".join(ev))


# ---------------------------------------------------------------------------
# V4 · 資源未釋放（例外路徑）— A10 / CWE-460
# ---------------------------------------------------------------------------
def v4_resource_leak():
    st1, _ = get("/process?doc=101&mode=ok")
    st2, body2 = get("/process?doc=101&mode=bad")
    leaked = "未釋放" in body2 and "Traceback" in body2
    ev = [
        "請求 A    : GET /process?doc=101&mode=ok   → HTTP %s（正常路徑會關閉資源）" % st1,
        "請求 B    : GET /process?doc=101&mode=bad  → HTTP %s" % st2,
        "預期漏洞  : 例外路徑上資源未關閉，且回應顯示未釋放數量",
        "實際      : 回應含「未釋放」與 Traceback = %s" % leaked,
        "根因      : 開啟資源後沒有 try/finally，例外時略過 close()",
        "修補方向  : 用 try/finally 或 with 陳述式，確保所有路徑都釋放資源",
        "危害      : 長期累積將耗盡檔案描述子 → 服務不可用（DoS）",
    ]
    check("V4 資源未釋放", "A10 / CWE-460", leaked, "\n".join(ev))


# ---------------------------------------------------------------------------
# V5 · 未檢查回傳值導致「靜默失敗」— A10 / CWE-252 / CWE-391
# ---------------------------------------------------------------------------
def v5_unchecked_return():
    st_ok, body_ok = get("/profile?uid=1")
    st_bad, body_bad = get("/profile?uid=999")
    silent = (st_bad == 200) and ("無資料" in body_bad)
    ev = [
        "請求 A    : GET /profile?uid=1    → HTTP %s（正常回傳資料）" % st_ok,
        "請求 B    : GET /profile?uid=999  → HTTP %s" % st_bad,
        "預期漏洞  : 查詢失敗卻回 200 並顯示「無資料」——呼叫端無法區分「失敗」與「空資料」",
        "實際      : 靜默失敗 = %s" % silent,
        "根因      : render_profile 未檢查 load_user_profile 的 None 回傳值，",
        "            上層又以寬鬆的 except 吞掉 TypeError（CWE-391 Unchecked Error Condition）",
        "修補方向  : 檢查回傳值並明確區分錯誤；不要用寬鬆 except 吞掉例外",
    ]
    check("V5 未檢查回傳值（靜默失敗）", "A10 / CWE-252 / CWE-391", silent, "\n".join(ev))


# ---------------------------------------------------------------------------
# V6 · fail-open 認證 — A10 / CWE-636
# 說明：需要「權限檢查發生例外」才會觸發。本靶場以程式碼審計 + 單元級
#       驗證證明該分支存在且會回傳 True。
# ---------------------------------------------------------------------------
def v6_fail_open():
    # 直接呼叫該函式的邏輯：例外時回傳 True（fail open）
    src_ok = True
    try:
        sys.path.insert(0, ".")
        import authlab                                        # noqa: PLC0415
        authlab.init_db()
        # 模擬「權限來源故障」：把 DB_PATH 指向不存在的檔案
        orig = authlab.DB_PATH
        authlab.DB_PATH = "/nonexistent/path/does-not-exist.db"
        allowed = authlab.check_permission_fail_open(1, 301)   # alice, admin 專屬文件
        authlab.DB_PATH = orig
        leaked = (allowed is True)
    except Exception as e:                                    # noqa: BLE001
        leaked = False
        src_ok = False
        print("   （呼叫時發生例外：%s）" % e)

    ev = [
        "情境      : 權限檢查所需的資料來源故障（DB 無法連線）",
        "呼叫      : check_permission_fail_open(uid=1, doc=301)  # alice 讀 admin 專屬文件",
        "預期漏洞  : 例外時回傳 True（fail open）→ 未授權者放行",
        "實際      : 回傳 True = %s" % leaked,
        "根因      : except 分支回傳 True，而非 False",
        "修補方向  : fail closed —— 例外時一律拒絕；並在日誌/警報中記錄（A09）",
        "OWASP 對照: A10 明確列出 CWE-636 Not Failing Securely ('Failing Open')；",
        "            官方原則為 'fail closed'，並強調交易中途不可嘗試部分恢復",
    ]
    check("V6 fail-open 認證", "A10 / CWE-636", leaked, "\n".join(ev))


def main():
    print("=" * 74)
    print(" AuthLab 漏洞驗證 — A01 IDOR / A10 fail-open")
    print(" 目標：%s" % BASE)
    print(" 方法：每個判定都以可觀察證據確認，不依賴閱讀程式碼")
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        print("       請先啟動靶場：python authlab.py %d" % PORT)
        sys.exit(1)

    for fn in (v1_idor, v2_default_allow, v3_error_leak, v4_resource_leak,
               v5_unchecked_return, v6_fail_open):
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
    with open("authlab_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 authlab_result.json）")


if __name__ == "__main__":
    main()
