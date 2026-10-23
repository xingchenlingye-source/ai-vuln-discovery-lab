#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_loglab.py — A09 日誌與警報失效 驗證
=============================================================================
 對應研究報告 CH02.1「發現與驗證分離」與 CH06 S1（A09）。

 驗證方式的特色（與先前靶場不同）：
   注入類漏洞用「回應內容」判定；A09 漏洞必須檢查
   **「日誌與告警檔案的內容」**——也就是系統「有沒有留下證據」。
   這正是 A09 的本質：漏洞不在回應裡，而在「看不到的地方」。

 用法：
   python verify_loglab.py [port]
=============================================================================
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8904
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "loglab.log")
ALERT_PATH = os.path.join(HERE, "loglab_alerts.log")
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def read_log():
    if not os.path.exists(LOG_PATH):
        return ""
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def read_alerts():
    if not os.path.exists(ALERT_PATH):
        return ""
    with open(ALERT_PATH, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def check(name, cwe, passed, evidence):
    results.append((name, cwe, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 74)
    print("[%s] %s  —  %s" % (mark, name, cwe))
    print("-" * 74)
    for line in evidence.splitlines():
        print("   " + line)


# ---------------------------------------------------------------------------
def l1_login_failure_not_logged():
    """L1：登入失敗完全不寫日誌。"""
    # 先清空日誌，確保觀測乾淨
    get("/log?clear=1")
    before = read_log()
    st, _ = get("/login?u=alice&p=definitely_wrong_password")
    after = read_log()
    not_logged = (before == after)
    ev = [
        "步驟 1    : GET /log?clear=1（清空日誌）",
        "步驟 2    : GET /login?u=alice&p=definitely_wrong_password → HTTP %s" % st,
        "步驟 3    : 比對日誌變化",
        "預期漏洞  : 登入失敗**完全沒有**寫入日誌（防禦方看不到攻擊）",
        "實際      : 日誌無變化 = %s（清空前 %d 字元，清空後 %d 字元）" % (
            not_logged, len(before), len(after)),
        "根因      : 失敗分支沒有呼叫任何日誌函式",
        "危害      : 攻擊者可以無限次嘗試，防禦方毫無察覺",
        "修補方向  : 所有認證事件（成功與失敗）都必須記錄：時間、來源、帳號、結果",
        "OWASP 對照: A09 官方描述『無法偵測入侵』——沒有日誌就沒有偵測",
    ]
    check("L1 登入失敗不記錄", "A09 / CWE-778", not_logged, "\n".join(ev))


def l2_no_audit_trail():
    """L2：關鍵操作（改角色）無審計日誌。"""
    # 觸發一次角色變更
    st1, b1 = get("/change_role?actor=alice&target=bob&role=admin")
    st2, b2 = get("/audit")
    m = re.search(r"記錄數：<b>(\d+)</b>", b2)
    n = int(m.group(1)) if m else -1
    no_audit = (n == 0)
    ev = [
        "步驟 1    : GET /change_role?actor=alice&target=bob&role=admin → HTTP %s" % st1,
        "步驟 2    : GET /audit 檢查審計表",
        "預期漏洞  : 審計表記錄數為 0（誰在何時改了什麼，完全沒有留下）",
        "實際      : 審計表記錄數 = %d" % n,
        "根因      : 權限變更端點未寫入 audit 表",
        "危害      : 無法歸責（non-repudiation）——提權後查不出是誰做的",
        "修補方向  : 所有關鍵操作寫入不可竄改的審計日誌（actor/action/target/result/時間）",
        "OWASP 對照: A09 官方描述『缺乏審計日誌與監控』；此項同時關聯 A01（提權）",
    ]
    check("L2 關鍵操作無審計日誌", "A09 / CWE-778", no_audit, "\n".join(ev))


def l3_sensitive_data_in_log():
    """L3：日誌含明文密碼（CWE-532）。

    兩個實作陷阱（都實際踩到過，值得記錄）：

    陷阱 1（順序污染）：本項讀取日誌檔內容，若在其他「會清空日誌」的測試之前
      執行，會讀到空檔案而誤判為「漏洞不存在」（false negative）。
      → 因此本項排在最後執行。

    陷阱 2（測試設計錯誤）：第一版用 `MySecretPassword123` 當登入密碼，
      但那是**錯誤的密碼**！靶場的邏輯是「登入成功才記錄密碼」，
      所以登入失敗（401）當然不會寫日誌 —— 我誤把「想驗證的敏感字串」
      當成「有效的憑證」。
      → 必須用**正確的密碼**（alice 的密碼是 123456）讓登入成功。

    → 這正是 CH05「量測方式決定你看見什麼」：兩次 false negative 都來自
      測試腳本，而不是目標本身。
    """
    get("/log?clear=1")
    real_password = "123456"          # alice 的真實密碼（必須正確才會記錄）
    st, _ = get("/login?u=alice&p=%s" % real_password)
    content = read_log()
    leaked = real_password in content and "password=" in content
    ev = [
        "步驟 1    : GET /log?clear=1",
        "步驟 2    : GET /login?u=alice&p=%s（正確密碼 → 登入成功）→ HTTP %s"
        % (real_password, st),
        "步驟 3    : 立即檢查日誌內容",
        "預期漏洞  : 日誌中出現**明文密碼**",
        "實際      : 明文密碼出現在日誌 = %s" % leaked,
        "日誌片段  : %s" % (content.strip().splitlines()[-1] if content.strip() else "（空）"),
        "根因      : 日誌訊息直接串接了 password 參數（log_write_vulnerable）",
        "危害      : 日誌常被集中收集與長期保存 → 成為憑證外洩的大水庫",
        "            （攻擊者一旦取得日誌，就取得所有人的密碼）",
        "修補方向  : 永不記錄密碼/金鑰/token；必要時只記雜湊前幾碼或遮罩",
        "OWASP 對照: A09 涵蓋『日誌本身不安全』；CWE-532 即此類",
    ]
    check("L3 日誌含明文敏感資料", "A09 / CWE-532", leaked, "\n".join(ev))


def l4_no_alerting():
    """L4：暴力破解無告警。"""
    get("/log?clear=1")
    if os.path.exists(ALERT_PATH):
        os.remove(ALERT_PATH)
    # 模擬暴力破解：對 admin 嘗試 12 次
    codes = []
    for i in range(12):
        st, _ = get("/login?u=admin&p=guess%02d" % i)
        codes.append(st)
    alerts = read_alerts()
    no_alert = (alerts.strip() == "")
    ev = [
        "步驟 1    : 連續 12 次 GET /login?u=admin&p=guess00..11",
        "           回應碼：%s" % set(codes),
        "步驟 2    : GET /alerts 檢查告警",
        "預期漏洞  : 完全沒有產生任何告警（12 次失敗被當成 12 次普通請求）",
        "實際      : 告警內容為空 = %s" % no_alert,
        "根因      : 回應中雖顯示『失敗次數』（給攻擊者看），但沒有任何門檻或告警",
        "危害      : 攻擊者取得進度資訊，防禦方零資訊——完全反了",
        "修補方向  : 失敗次數達門檻時產生告警（含來源 IP、帳號、時間窗）；",
        "            並且**不要**把嘗試次數顯示在回應中",
        "OWASP 對照: A09 2025 版更名為 'Logging and **Alerting** Failures'——",
        "            強調『記錄』不等於『通報』，這是 2025 版的核心變化",
    ]
    check("L4 暴力破解無告警", "A09 / CWE-778", no_alert, "\n".join(ev))


def l5_log_file_unprotected():
    """L5：日誌檔無保護，任何請求都能清除。"""
    get("/login?u=alice&p=123456")             # 先產生一些日誌
    before = read_log()
    st, body = get("/log?clear=1")             # 攻擊者清除日誌
    after = read_log()
    cleared = (len(before) > 0) and (len(after) == 0)
    # 檢查檔案權限
    mode = oct(os.stat(LOG_PATH).st_mode & 0o777) if os.path.exists(LOG_PATH) else "N/A"
    ev = [
        "步驟 1    : GET /login?u=alice&p=123456 → 產生日誌（%d 字元）" % len(before),
        "步驟 2    : GET /log?clear=1 → HTTP %s（無任何授權檢查）" % st,
        "步驟 3    : 檢查日誌",
        "預期漏洞  : 攻擊者可透過 HTTP 清除日誌，且檔案權限過寬",
        "實際      : 日誌被清除 = %s；檔案權限 = %s" % (cleared, mode),
        "根因      : 兩個問題疊加 —— (a) 提供清除端點且無授權",
        "            (b) 日誌檔權限 644（同機其他使用者可讀）",
        "危害      : 攻擊者做完事後清除痕跡 → 事件無法回溯",
        "修補方向  : 日誌只能由服務帳號寫入（不可刪除）；",
        "            集中式日誌（遠端 syslog/ELK），本機副本被刪也不影響調查",
        "OWASP 對照: A09 官方原則『日誌必須受到保護，避免未授權存取與竄改』",
    ]
    check("L5 日誌檔無保護（可被清除）", "A09 / CWE-732", cleared, "\n".join(ev))


def l6_no_correlation_id():
    """L6：事件之間無關聯 ID，無法串連攻擊鏈。"""
    get("/log?clear=1")
    get("/login?u=alice&p=123456")             # 事件 1
    get("/change_role?actor=alice&target=bob&role=admin")   # 事件 2
    content = read_log()
    # 檢查是否有任何關聯 ID 樣式（req_id/trace_id/correlation）
    has_corr = bool(re.search(r"(req[_-]?id|trace[_-]?id|correlation|request_id)",
                              content, re.I))
    # 檢查日誌結構化程度（是否為 JSON 或含 actor/action/result 欄位）
    structured = content.strip().startswith("{") or ("actor=" in content and "result=" in content)
    ev = [
        "步驟 1    : GET /log?clear=1",
        "步驟 2    : 觸發兩個相關事件（登入 + 改角色）",
        "步驟 3    : 檢查日誌是否有關聯 ID 或結構化欄位",
        "預期漏洞  : 每個事件都是獨立純文字行，無 request id、無結構化欄位",
        "實際      : 含關聯 ID = %s；結構化 = %s" % (has_corr, structured),
        "日誌內容  : %s" % (content.strip() or "（空）")[:200],
        "根因      : 日誌格式為非結構化純文字，且未貫穿請求脈絡",
        "危害      : 無法把『登入 → 改角色』串成一次攻擊；",
        "            大量日誌下無法有效調查（這也是 SIEM 難以發揮的原因）",
        "修補方向  : 採用結構化日誌（JSON），每個請求帶唯一 request_id 並貫穿所有記錄",
    ]
    check("L6 無關聯 ID（無法串連事件）", "A09 / CWE-778",
          (not has_corr) and (not structured), "\n".join(ev))


def main():
    print("=" * 74)
    print(" LogLab 漏洞驗證 — A09 日誌與警報失效")
    print(" 目標：%s" % BASE)
    print("=" * 74)
    print(" 注意：A09 的漏洞不在回應裡，而在『日誌與告警檔案』中")
    print("=" * 74)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        print("       請先啟動：python loglab.py %d" % PORT)
        sys.exit(1)

    # 執行順序有講究：L3（讀取日誌內容）必須放在「會清空日誌」的測試之後，
    # 否則會被其他測試的 /log?clear=1 清掉，造成 false negative。
    # 這是測試之間的狀態污染問題 —— 實際踩到過，故明確寫在這裡。
    for fn in (l1_login_failure_not_logged, l2_no_audit_trail,
               l4_no_alerting, l5_log_file_unprotected,
               l6_no_correlation_id, l3_sensitive_data_in_log):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            check(fn.__name__, "-", False, "執行時例外：%s" % e)

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-34s %-22s %s" % (name, cwe, "漏洞存在" if passed else "未觸發"))
    print("-" * 74)
    print("  共 %d/%d 個 A09 漏洞被驗證存在" % (found, len(results)))
    print("=" * 74)

    out = [{"name": n, "cwe": c, "present": p} for n, c, p, _ in results]
    with open("loglab_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 loglab_result.json）")


if __name__ == "__main__":
    main()
