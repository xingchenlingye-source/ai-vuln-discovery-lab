#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_patched.py — 修補版驗證（攻擊失效 + 功能保留）
=============================================================================
 對應研究報告 CH02.4「修補驗證」的兩個必要條件：

   條件 ①：原攻擊輸入不再觸發漏洞
   條件 ②：正常功能仍然可用（不是用「關掉功能」假裝修好）

 用法：
   python verify_patched.py            # 預設 8902（修補版）
   python verify_patched.py 8902
=============================================================================
"""

import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8902
BASE = "http://127.0.0.1:%d" % PORT

attack_results = []      # 條件 ①
func_results = []        # 條件 ②


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def check(kind, name, passed, evidence):
    target = attack_results if kind == "attack" else func_results
    target.append((name, passed, evidence))


def show(kind, title):
    rows = attack_results if kind == "attack" else func_results
    print("\n" + "=" * 74)
    print(" %s" % title)
    print("=" * 74)
    for name, passed, ev in rows:
        mark = "OK  " if passed else "FAIL"
        print("\n[%s] %s" % (mark, name))
        for line in ev.splitlines():
            print("       " + line)
    ok = sum(1 for _, p, _ in rows if p)
    print("\n  → %d/%d" % (ok, len(rows)))
    return ok, len(rows)


def main():
    print("=" * 74)
    print(" 修補版驗證：攻擊失效 + 功能保留")
    print(" 目標：%s" % BASE)
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        print("       請先啟動：python authlab_patched.py %d" % PORT)
        sys.exit(1)

    # ================= 條件 ①：攻擊失效 =================

    # V1 IDOR：alice 讀 bob 的文件 → 應回 404
    st1, b1 = get("/doc?uid=1&doc=201")
    check("attack", "V1 IDOR（alice 讀 bob 文件）",
          st1 == 404 and "bob 的私人內容" not in b1,
          "請求   : GET /doc?uid=1&doc=201\n預期   : 404（無權存取）\n實際   : HTTP %s，內容外洩=%s"
          % (st1, "bob 的私人內容" in b1))

    # V2 缺省允許：不存在的文件 → 應回 404
    st2, _ = get("/doc?uid=1&doc=999999")
    check("attack", "V2 缺省允許（不存在的文件）",
          st2 == 404,
          "請求   : GET /doc?uid=1&doc=999999\n預期   : 404\n實際   : HTTP %s" % st2)

    # V3 錯誤訊息洩漏 → 不含原始例外
    st3, b3 = get("/doc?uid=1&doc=abc")
    leaked3 = ("ValueError" in b3) or ("invalid literal" in b3)
    check("attack", "V3 錯誤訊息洩漏",
          not leaked3,
          "請求   : GET /doc?uid=1&doc=abc\n預期   : 不含 ValueError / invalid literal\n實際   : HTTP %s，例外外洩=%s"
          % (st3, leaked3))

    # V4 資源未釋放 → 未釋放計數應為 0
    get("/process?doc=101&mode=ok")
    st4, b4 = get("/process?doc=101&mode=bad")
    unreleased = "未釋放" in b4
    check("attack", "V4 資源未釋放（例外路徑）",
          not unreleased,
          "請求   : GET /process?doc=101&mode=bad\n預期   : 不含「未釋放」字樣（資源已由 try/finally 釋放）\n實際   : HTTP %s，顯示未釋放=%s"
          % (st4, unreleased))

    # V5 未檢查回傳值 → 應回 404 而非 200 靜默失敗
    st5a, b5a = get("/profile?uid=1")
    st5b, b5b = get("/profile?uid=999")
    check("attack", "V5 未檢查回傳值（靜默失敗）",
          st5b == 404 and "找不到使用者" in b5b,
          "請求   : GET /profile?uid=999\n預期   : 404「找不到使用者」（明確區分錯誤）\n實際   : HTTP %s，靜默失敗=%s"
          % (st5b, ("無資料" in b5b)))

    # V6 fail-open → 服務故障時應拒絕（503），而非放行
    st6, b6 = get("/admin?uid=1")
    is_admin_area = ("管理區" in b6) and ("已進入" in b6)
    check("attack", "V6 fail-open（非 admin 進入管理區）",
          st6 == 404 and not is_admin_area,
          "請求   : GET /admin?uid=1（alice 非 admin）\n預期   : 404（拒絕）\n實際   : HTTP %s，進入管理區=%s"
          % (st6, is_admin_area))

    # ================= 條件 ②：功能保留 =================

    # bob 讀自己的文件 → 應成功
    stf1, bf1 = get("/doc?uid=2&doc=201")
    check("func", "bob 讀自己的文件（doc=201）",
          stf1 == 200 and "bob 的私人內容" in bf1,
          "請求   : GET /doc?uid=2&doc=201\n預期   : 200 + 內容\n實際   : HTTP %s" % stf1)

    # alice 讀自己的文件 → 應成功
    stf2, bf2 = get("/doc?uid=1&doc=101")
    check("func", "alice 讀自己的文件（doc=101）",
          stf2 == 200 and "alice 的私人筆記" in bf2,
          "請求   : GET /doc?uid=1&doc=101\n預期   : 200 + 內容\n實際   : HTTP %s" % stf2)

    # admin 讀 classified 文件 → 應成功（垂直權限保留）
    stf3, bf3 = get("/doc?uid=3&doc=301")
    check("func", "admin 讀 classified 文件（doc=301）",
          stf3 == 200 and "admin 專屬內容" in bf3,
          "請求   : GET /doc?uid=3&doc=301\n預期   : 200 + 內容（admin 有權）\n實際   : HTTP %s" % stf3)

    # admin 進入管理區 → 應成功
    stf4, bf4 = get("/admin?uid=3")
    check("func", "admin 進入管理區",
          stf4 == 200 and "已進入" in bf4,
          "請求   : GET /admin?uid=3\n預期   : 200\n實際   : HTTP %s" % stf4)

    # 正常 profile 查詢 → 應成功
    stf5, bf5 = get("/profile?uid=1")
    check("func", "查詢存在的使用者（uid=1）",
          stf5 == 200 and "alice" in bf5,
          "請求   : GET /profile?uid=1\n預期   : 200 + username=alice\n實際   : HTTP %s" % stf5)

    # 正常 process 流程 → 應成功
    stf6, bf6 = get("/process?doc=101&mode=ok")
    check("func", "正常處理流程（mode=ok）",
          stf6 == 200 and "處理完成" in bf6,
          "請求   : GET /process?doc=101&mode=ok\n預期   : 200\n實際   : HTTP %s" % stf6)

    # ================= 結果 =================
    a_ok, a_tot = show("attack", "條件 ①：攻擊失效（6 項）")
    f_ok, f_tot = show("func", "條件 ②：功能保留（6 項）")

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    print("  條件 ① 攻擊失效 : %d/%d %s" % (a_ok, a_tot, "✓ 通過" if a_ok == a_tot else "✗ 未通過"))
    print("  條件 ② 功能保留 : %d/%d %s" % (f_ok, f_tot, "✓ 通過" if f_ok == f_tot else "✗ 未通過"))
    if a_ok == a_tot and f_ok == f_tot:
        print("\n  ✓ 修補驗證通過：全部攻擊輸入失效，且正常功能完整保留。")
        print("    （這證明修補是「真的修好」，而不是「把功能關掉」）")
    else:
        print("\n  ✗ 修補驗證未通過，請檢查上列 FAIL 項目。")
    print("=" * 74)


if __name__ == "__main__":
    main()
