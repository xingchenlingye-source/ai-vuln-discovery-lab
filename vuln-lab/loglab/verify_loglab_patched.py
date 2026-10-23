#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_loglab_patched.py — A09 修補版驗證
=============================================================================
 對應研究報告 CH02.4：修補驗證的兩個必要條件
   ① 攻擊（或缺口）失效
   ② 正常功能保留

 對 A09 而言，「攻擊失效」的意思是「缺口被補上」——例如
 「日誌確實記下來了」、「告警確實發出了」、「敏感資料被遮罩了」。

 用法：
   python verify_loglab_patched.py 8905
=============================================================================
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8905
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "loglab_patched.jsonl")
ALERT_PATH = os.path.join(HERE, "loglab_patched_alerts.jsonl")

fix_results = []
func_results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:                            # noqa: BLE001
                    pass
    return out


def clear_logs():
    for p in (LOG_PATH, ALERT_PATH):
        if os.path.exists(p):
            open(p, "w", encoding="utf-8").close()


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
    print(" A09 修補版驗證")
    print(" 目標：%s" % BASE)
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        sys.exit(1)

    # ---------- 修補 1（L1）：登入失敗有記錄 ----------
    clear_logs()
    get("/login?u=alice&p=wrong_password_xyz")
    logs = read_jsonl(LOG_PATH)
    failure_logged = any(e.get("event") == "login" and e.get("result") == "failure"
                         for e in logs)
    check("fix", "L1 登入失敗有記錄",
          failure_logged,
          "請求   : GET /login?u=alice&p=wrong_password_xyz → 401\n"
          "預期   : 日誌出現 event=login result=failure\n"
          "實際   : 找到失敗記錄 = %s（日誌共 %d 筆）" % (failure_logged, len(logs)))

    # ---------- 修補 2（L2）：關鍵操作有審計 ----------
    get("/change_role?actor=alice&target=bob&role=user")
    st2, b2 = get("/audit")
    m = re.search(r"記錄數：<b>(\d+)</b>", b2)
    n = int(m.group(1)) if m else -1
    check("fix", "L2 關鍵操作有審計軌跡",
          n > 0,
          "請求   : GET /change_role?actor=alice&target=bob&role=user\n"
          "預期   : 審計表記錄數 > 0（含 actor/action/target/result）\n"
          "實際   : 審計記錄數 = %d" % n)

    # ---------- 修補 3（L3）：敏感資料遮罩 ----------
    clear_logs()
    get("/login?u=alice&p=123456")
    logs = read_jsonl(LOG_PATH)
    raw_leak = any("password" in json.dumps(e).lower() and "123456" in json.dumps(e)
                   for e in logs)
    masked = any("password_masked" in e for e in logs)
    check("fix", "L3 敏感資料遮罩",
          masked and not raw_leak,
          "請求   : GET /login?u=alice&p=123456（成功）\n"
          "預期   : 日誌含 password_masked 欄位，且不含明文密碼\n"
          "實際   : 有遮罩欄位 = %s；出現明文 = %s\n"
          "日誌範例: %s" % (
              masked, raw_leak,
              json.dumps(logs[-1], ensure_ascii=False) if logs else "（空）"))

    # ---------- 修補 4（L4）：暴力破解會告警 ----------
    clear_logs()
    if os.path.exists(ALERT_PATH):
        os.remove(ALERT_PATH)
    for i in range(7):                                   # 超過門檻 5
        get("/login?u=admin&p=guess%02d" % i)
    alerts = read_jsonl(ALERT_PATH)
    got_alert = any(a.get("alert") == "possible_brute_force" for a in alerts)
    no_count_leak = "失敗次數" not in get("/login?u=admin&p=x")[1]
    check("fix", "L4 暴力破解產生告警",
          got_alert and no_count_leak,
          "請求   : 連續 7 次 GET /login?u=admin&p=guess00..06\n"
          "預期   : 產生 possible_brute_force 告警；且回應不再顯示失敗次數\n"
          "實際   : 告警產生 = %s；回應洩漏次數 = %s\n"
          "告警範例: %s" % (
              got_alert, not no_count_leak,
              json.dumps(alerts[-1], ensure_ascii=False) if alerts else "（無）"))

    # ---------- 修補 5（L5）：日誌不可被清除 ----------
    get("/login?u=alice&p=123456")
    before = os.path.getsize(LOG_PATH) if os.path.exists(LOG_PATH) else 0
    st5, _ = get("/log?clear=1")
    after = os.path.getsize(LOG_PATH) if os.path.exists(LOG_PATH) else 0
    mode = oct(os.stat(LOG_PATH).st_mode & 0o777) if os.path.exists(LOG_PATH) else "N/A"
    # 注意：斷言只檢查「HTTP 拒絕 + 日誌未遺失」。
    # 檔案權限「不列入斷言」——因為 Windows NTFS 只有唯讀位元，
    # os.chmod(0o600) 實際上不會生效（實測仍為 0o666）。
    # 這是平台限制，不該用一個永遠「看似通過」的檢查來假裝已達成。
    protected = (st5 == 403) and (after > 0) and (after >= before)
    check("fix", "L5 日誌受保護（不可透過 API 清除）",
          protected,
          "請求   : GET /log?clear=1 → HTTP %s（預期 403）\n"
          "預期   : 拒絕清除；日誌內容不因請求而消失\n"
          "實際   : HTTP %s；清除前 %d bytes → 清除後 %d bytes\n"
          "權限實測: %s\n"
          "⚠ 平台限制說明：本機為 Windows，NTFS 僅支援唯讀位元，"
          "os.chmod(0o600) 不會生效（實測 0o600/0o644 皆顯示 0o666，"
          "僅 0o444 有效）。\n"
          "  因此「檔案權限」不列入本項斷言；在 Linux 上需另行驗證權限位，"
          "Windows 上則應改用 ACL（icacls）或集中式日誌。"
          % (st5, st5, before, after, mode))

    # ---------- 修補 6（L6）：request_id 貫穿 ----------
    logs = read_jsonl(LOG_PATH)
    has_rid = all("request_id" in e for e in logs) if logs else False
    events_with_rid = len({e.get("request_id") for e in logs if e.get("request_id")})
    structured = all(isinstance(e, dict) for e in logs) if logs else False
    check("fix", "L6 結構化日誌與 request_id",
          has_rid and structured and events_with_rid > 0,
          "預期   : 每筆日誌皆為 JSON 且含 request_id\n"
          "實際   : 全部含 request_id = %s；不同 request_id 數 = %d；結構化 = %s"
          % (has_rid, events_with_rid, structured))

    # ---------- 條件 ②：功能保留 ----------
    st_f1, b_f1 = get("/login?u=alice&p=123456")
    check("func", "正常登入仍成功",
          st_f1 == 200 and "登入成功" in b_f1,
          "請求   : GET /login?u=alice&p=123456\n預期   : 200\n實際   : HTTP %s" % st_f1)

    st_f2, _ = get("/change_role?actor=admin&target=bob&role=user")
    check("func", "正常角色變更仍成功",
          st_f2 == 200,
          "請求   : GET /change_role?actor=admin&target=bob&role=user\n預期   : 200\n實際   : HTTP %s" % st_f2)

    st_f3, b_f3 = get("/log")
    check("func", "日誌仍可讀取（只是不可清除）",
          st_f3 == 200 and "結構化日誌" in b_f3,
          "請求   : GET /log\n預期   : 200（可讀）\n實際   : HTTP %s" % st_f3)

    st_f4, b_f4 = get("/audit")
    check("func", "審計表仍可查詢",
          st_f4 == 200 and "審計表" in b_f4,
          "請求   : GET /audit\n預期   : 200\n實際   : HTTP %s" % st_f4)

    f_ok, f_tot = show("fix", "缺口補上（6 項）")
    g_ok, g_tot = show("func", "功能保留（4 項）")

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    print("  缺口補上 : %d/%d %s" % (f_ok, f_tot, "✓" if f_ok == f_tot else "✗"))
    print("  功能保留 : %d/%d %s" % (g_ok, g_tot, "✓" if g_ok == g_tot else "✗"))
    if f_ok == f_tot and g_ok == g_tot:
        print("\n  ✓ A09 修補驗證通過：6 個缺口全部補上，且功能未受影響。")
    else:
        print("\n  ✗ 未通過，請檢查上列 FAIL 項目。")
    print("=" * 74)


if __name__ == "__main__":
    main()
