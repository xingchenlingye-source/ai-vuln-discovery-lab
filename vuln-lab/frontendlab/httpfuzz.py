#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 httpfuzz.py — HTTP 層 fuzzer（補足「HTTP 層工具鏈」缺口）
=============================================================================

 對應研究報告 CH06 S2（工具鏈）與 CH03（fuzzing 的訊號問題）。

 為什麼需要這個？—— 兩類 fuzzing 的根本差異
   本專案已有 `fuzz_v2`（C/C++ 記憶體安全 fuzzer），但那是**白箱 + 覆蓋率**：

   ┌──────────────┬─────────────────────┬─────────────────────┐
   │              │ fuzz_v2（本專案）    │ httpfuzz（本檔）     │
   ├──────────────┼─────────────────────┼─────────────────────┤
   │ 目標         │ C/C++ 記憶體安全     │ Web 應用邏輯         │
   │ 觀測方式     │ 白箱（插樁）         │ **黑箱**（只看回應） │
   │ 訊號         │ **crash**（ASan）    │ **回應差異**         │
   │ 覆蓋率回饋   │ ✅ trace-pc-guard    │ ❌ 無法取得          │
   │ 速度         │ 14 萬 exec/s         │ 每秒數十個請求       │
   │ 需要人工判斷 │ 低（crash 很明確）   │ **高**（差異要解讀） │
   └──────────────┴─────────────────────┴─────────────────────┘

 核心挑戰（本檔要示範的）：
   **黑箱 fuzzing 沒有可靠的「新穎性」訊號。**
   沒有覆蓋率可依賴，只能比較回應的：
     · 狀態碼      · 回應長度      · 回應內容
   而這些訊號充滿雜訊——這正是為什麼 HTTP fuzzing 更依賴人工判斷。

 三種模式：
   1. `scan`     — 端點探索（用路徑字典）
   2. `params`   — 參數 fuzzing（找隱藏參數）
   3. `methods`  — HTTP 方法探測

 ⚠ 僅對本機靶場或已授權目標使用。
    本工具預設只允許 127.0.0.1 / localhost，避免誤用於未授權目標。

 用法：
   python httpfuzz.py scan    http://127.0.0.1:8920
   python httpfuzz.py params  http://127.0.0.1:8920/api/product?id=1
   python httpfuzz.py methods http://127.0.0.1:8920/api/product?id=1
   python httpfuzz.py all     http://127.0.0.1:8920
=============================================================================
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

# 安全閘門：預設只允許本機
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

# 認證後 fuzzing 用的 session 標頭（由 --cookie / --header 設定）
SESSION = None

# 路徑字典（教學用，刻意精簡；實務上用 SecLists 等大型字典）
PATH_WORDLIST = [
    "api", "api/v1", "api/v2", "api/admin", "api/admin/users", "api/admin/price",
    "api/debug", "api/debug/config", "api/config", "api/product", "api/cart",
    "api/user", "api/users", "api/me", "api/health", "api/status",
    "admin", "admin/users", "debug", "config", "env", "health",
    "static", "static/app.js", "robots.txt", "sitemap.xml",
    ".git/config", ".env", "backup", "test", "dev",
]

# 參數字典（找隱藏參數）
PARAM_WORDLIST = [
    "internal", "debug", "test", "admin", "verbose", "trace",
    "price", "cost", "discount", "role", "is_admin", "bypass",
    "format", "raw", "full", "expand", "include", "fields",
    "callback", "redirect", "next", "url", "file", "path",
    "token", "key", "secret", "apikey", "api_key",
]

# 參數值字典
VALUE_WORDLIST = ["1", "true", "yes", "on", "admin", "all", "*", "0", "-1", "null"]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]


def check_target(url):
    """安全閘門。"""
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        print("=" * 78)
        print(" ⛔ 拒絕執行")
        print("=" * 78)
        print("  目標主機：%s" % host)
        print("  本工具僅允許：%s" % ", ".join(sorted(ALLOWED_HOSTS)))
        print()
        print("  為什麼有這個限制：")
        print("    HTTP fuzzing 會送出大量請求。對未授權的目標執行，")
        print("    可能構成騷擾、服務中斷，且在法律上屬未授權存取。")
        print("    → 請對自己擁有或已取得書面授權的目標執行。")
        print("=" * 78)
        sys.exit(2)


def http_request(url, method="GET", timeout=8, body=None, session=None):
    """送出請求，回傳 (status, length, body_text, elapsed)。

    補強：支援「認證後 fuzzing」——可帶上 Cookie 或自訂標頭。
    為什麼重要：真實目標的漏洞常位在**登入之後**，
    未認證的掃描只看得到登入頁。
    """
    data = body.encode() if body else None
    headers = {"User-Agent": "vuln-lab-httpfuzz/1.0"}
    if session:
        headers.update(session)
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, len(raw), raw.decode("utf-8", errors="replace"), time.time() - t0
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, len(raw), raw.decode("utf-8", errors="replace"), time.time() - t0
    except Exception as e:                                   # noqa: BLE001
        return -1, 0, str(e), time.time() - t0


def build_session(args):
    """從命令列參數組出 session 標頭（認證後 fuzzing 用）。"""
    s = {}
    if getattr(args, "cookie", None):
        s["Cookie"] = args.cookie
    if getattr(args, "header", None):
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                s[k.strip()] = v.strip()
    return s or None


def fingerprint(status, length, body):
    """產生回應指紋（用於比對差異）。"""
    return {
        "status": status,
        "length": length,
        "hash": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16],
        "has_flag": "FLAG{" in body,
        "looks_error": bool(re.search(r"(traceback|stack trace|error|exception)",
                                      body, re.I)),
    }


def print_fp(label, fp, extra=""):
    print("  %-44s %3s  %6d bytes  %s %s"
          % (label, fp["status"], fp["length"], fp["hash"],
             ("★FLAG " if fp["has_flag"] else "") + extra))


# ---------------------------------------------------------------------------
# 模式 1：端點探索
# ---------------------------------------------------------------------------
def mode_scan(base):
    print("=" * 78)
    print(" 模式 1：端點探索（路徑字典掃描）")
    print("=" * 78)
    print(" 目標     : %s" % base)
    print(" 字典大小 : %d 條" % len(PATH_WORDLIST))
    print("=" * 78)

    # 基準線：一個確定「不存在」的路徑
    st0, len0, _, _ = http_request(urljoin(base + "/", "this-path-should-not-exist-9x8y7z"), session=SESSION)
    baseline = fingerprint(st0, len0, "")
    print("\n 基準線（不存在的路徑）：")
    print_fp("GET /this-path-should-not-exist-9x8y7z", baseline)

    print("\n 掃描結果：")
    hits = []
    for p in PATH_WORDLIST:
        url = base.rstrip("/") + "/" + p
        st, ln, body, el = http_request(url, session=SESSION)
        fp = fingerprint(st, ln, body)
        # 判定「有東西」：狀態碼不同、或長度與基準線差異明顯
        interesting = (fp["status"] != baseline["status"]) or \
                      (abs(fp["length"] - baseline["length"]) > 30)
        if interesting:
            hits.append((p, fp, body))
            print_fp("/%s" % p, fp)

    print("\n" + "-" * 78)
    print(" 黑箱 fuzzing 的困難（本模式要示範的重點）")
    print("-" * 78)
    print("""
  沒有覆蓋率回饋，只能靠「狀態碼 + 長度」判斷是否有東西。
  但這兩者充滿雜訊：
    · 200 可能是真實端點，也可能是 SPA 的 catch-all 回首頁
    · 404 頁面長度各不相同 → 長度差異不代表有新內容
    · 重導向、壓縮、快取都會改變長度

  → 所以 HTTP fuzzing 的「新穎性判斷」遠比覆蓋率引導不可靠。
    這正是它更依賴**人工解讀**的原因（對比：本專案的 fuzz_v2
    有 ASan crash 這個明確訊號，誤判率極低）。
""")
    return hits


# ---------------------------------------------------------------------------
# 模式 2：參數 fuzzing
# ---------------------------------------------------------------------------
def mode_params(base_url):
    print("=" * 78)
    print(" 模式 2：參數 fuzzing（找隱藏參數）")
    print("=" * 78)
    print(" 目標 URL : %s" % base_url)
    print(" 參數字典 : %d 條 × 值字典 %d 條" % (len(PARAM_WORDLIST), len(VALUE_WORDLIST)))
    print("=" * 78)

    st0, len0, body0, _ = http_request(base_url, session=SESSION)
    baseline = fingerprint(st0, len0, body0)
    print("\n 基準線（原始 URL）：")
    print_fp(base_url, baseline)

    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query)

    print("\n 測試隱藏參數：")
    found = []
    for p in PARAM_WORDLIST:
        if p in existing:
            continue
        best = None
        for v in VALUE_WORDLIST:
            q = dict(existing)
            q[p] = [v]
            url = parsed._replace(query=urlencode(q, doseq=True)).geturl()
            st, ln, body, _ = http_request(url, session=SESSION)
            fp = fingerprint(st, ln, body)
            # 有差異就有興趣
            diff = (fp["status"] != baseline["status"]) or \
                   (abs(fp["length"] - baseline["length"]) > 20) or \
                   (fp["hash"] != baseline["hash"])
            if diff:
                if best is None or abs(fp["length"] - baseline["length"]) > \
                        abs(best[2]["length"] - baseline["length"]):
                    best = (p, v, fp, body)
        if best:
            p, v, fp, body = best
            delta = fp["length"] - baseline["length"]
            found.append((p, v))
            print_fp("%s=%s" % (p, v), fp, "  (Δ%+d)" % delta)

    print("\n" + "-" * 78)
    print(" 判定邏輯說明（黑箱的難處）")
    print("-" * 78)
    print("""
  這裡用「與基準線的差異」當訊號。但要注意：
    · 回應長度變化可能來自動態內容（時間戳、隨機值）→ 誤報
    · 有些參數無效但不報錯（靜默忽略）→ 漏報
    · 真正的隱藏參數需要「語意線索」（例如 JS 中的欄位名稱）

  → 這正是為什麼「讀前端」與「HTTP fuzzing」應該合併使用：
    **前端提供假設，fuzzing 負責驗證**。
""")
    return found


# ---------------------------------------------------------------------------
# 模式 3：HTTP 方法探測
# ---------------------------------------------------------------------------
def mode_methods(base_url):
    print("=" * 78)
    print(" 模式 3：HTTP 方法探測")
    print("=" * 78)
    print(" 目標 URL : %s" % base_url)
    print("=" * 78)

    print("\n 各方法回應：")
    results = {}
    for m in HTTP_METHODS:
        st, ln, body, _ = http_request(base_url, method=m,
                                       body='{"test":1}' if m in ("POST", "PUT", "PATCH") else None,
                                       session=SESSION)
        fp = fingerprint(st, ln, body)
        results[m] = fp
        risky = ""
        if m in ("PUT", "DELETE", "PATCH") and st in (200, 201, 204):
            risky = "  ★ 危險方法被接受"
        if m == "TRACE" and st == 200:
            risky = "  ★ TRACE 開啟（可被 XST 利用）"
        print_fp(m, fp, risky)

    print("\n" + "-" * 78)
    print(" 判讀")
    print("-" * 78)
    print("""
  · 若 PUT/DELETE 回 200/204 → 未限制危險方法（A02）
  · 若只用 GET 就回 200，其他方法 405 → 正確設定
  · OPTIONS 回應的 Allow 標頭可看出支援的方法（需讀標頭，非 body）
  · TRACE 開啟屬歷史風險（XST），現代伺服器預設關閉
""")
    return results


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="HTTP 層 fuzzer（黑箱）")
    ap.add_argument("mode", choices=["scan", "params", "methods", "all"])
    ap.add_argument("url")
    ap.add_argument("--cookie", help="認證後 fuzzing：Cookie 標頭內容")
    ap.add_argument("--header", action="append",
                    help="自訂標頭，可重複（例如 --header 'Authorization: Bearer xxx'）")
    args = ap.parse_args()

    global SESSION
    SESSION = build_session(args)
    check_target(args.url)
    if SESSION:
        print("=" * 78)
        print(" ★ 認證後模式（已帶上 session）")
        print("=" * 78)
        for k, v in SESSION.items():
            print("   %s: %s" % (k, (v[:60] + "...") if len(v) > 60 else v))
        print()
    base = args.url.rstrip("/")

    print("\n" + "#" * 78)
    print("# HTTP 層 Fuzzer — 黑箱模式")
    print("# 對比本專案 fuzz_v2：那是白箱 + 覆蓋率 + crash 訊號")
    print("#" * 78 + "\n")

    summary = {}
    if args.mode in ("scan", "all"):
        summary["scan"] = len(mode_scan(base))
        print()
    if args.mode in ("params", "all"):
        tgt = base + "/api/product?id=1" if args.mode == "all" else args.url
        summary["params"] = len(mode_params(tgt))
        print()
    if args.mode in ("methods", "all"):
        tgt = base + "/api/product?id=1" if args.mode == "all" else args.url
        summary["methods"] = mode_methods(tgt)
        print()

    print("=" * 78)
    print(" 總結")
    print("=" * 78)
    if "scan" in summary:
        print("  端點探索  : 發現 %d 個有回應的路徑" % summary["scan"])
    if "params" in summary:
        print("  參數 fuzzing: 發現 %d 個造成回應差異的參數" % summary["params"])
    if "methods" in summary and isinstance(summary["methods"], dict):
        risky = [m for m, fp in summary["methods"].items()
                 if m in ("PUT", "DELETE", "PATCH") and fp["status"] in (200, 201, 204)]
        print("  方法探測  : %d 個危險方法被接受 %s"
              % (len(risky), ("（" + ", ".join(risky) + "）") if risky else ""))
    print()
    print("  最大的啟示：")
    print("    這個工具沒有「新穎性訊號」——它只能比對回應差異。")
    print("    相較之下 fuzz_v2 有 ASan crash 這種明確訊號。")
    print("    → **黑箱 fuzzing 需要更多人工判斷，也更容易誤判。**")
    print("    → 這解釋了為什麼「讀前端取假設」+「HTTP fuzzing 驗證」要合併。")
    print("=" * 78)

    with open("httpfuzz_result.json", "w", encoding="utf-8") as f:
        json.dump({"target": args.url, "mode": args.mode,
                   "summary": {k: (v if not isinstance(v, dict) else
                                   {m: fp for m, fp in v.items()})
                               for k, v in summary.items()}},
                  f, ensure_ascii=False, indent=2, default=str)
    print("\n（JSON 摘要已寫入 httpfuzz_result.json）")


if __name__ == "__main__":
    main()
