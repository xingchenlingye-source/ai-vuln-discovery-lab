#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_configlab.py — A02 安全設定錯誤 驗證
=============================================================================
 對應研究報告 CH02.1「發現與驗證分離」與 CH06 S1（A02）。

 驗證方式的特色（A02 專屬）：
   A02 的漏洞**不在回應內容裡，而在「回應標頭」與「伺服器行為」中**。
   例如缺少 CSP —— 你必須讀 header，而不是讀 body。
   這與先前四種型態都不同：
     注入類：看 body          A09：看日誌檔
     競態類：併發             A02：**看標頭 + 看允許的方法**
   → 再次印證：驗證方式必須配合漏洞類型。

 用法：
   python verify_configlab.py [port]
=============================================================================
"""

import json
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8908
BASE = "http://127.0.0.1:%d" % PORT
results = []


def request(path, method="GET", data=None, headers=None):
    """回傳 (status, headers_dict, body)。"""
    req = urllib.request.Request(BASE + path, method=method,
                                 data=data.encode() if data else None)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, {}, str(e)


def check(name, owasp, passed, evidence):
    results.append((name, owasp, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 74)
    print("[%s] %s  —  %s" % (mark, name, owasp))
    print("-" * 74)
    for line in evidence.splitlines():
        print("   " + line)


# ---------------------------------------------------------------------------
def c1_debug_mode():
    """C1：DEBUG 模式洩漏堆疊追蹤與檔案路徑。"""
    st, hdr, body = request("/boom")
    has_trace = "Traceback (most recent call last)" in body
    has_path = bool(re.search(r'File "[^"]+\.py", line \d+', body))
    has_zero = "ZeroDivisionError" in body
    ev = [
        "請求      : GET /boom",
        "預期漏洞  : 回應含完整 traceback、原始碼檔案路徑、行號",
        "實際      : HTTP %s；traceback=%s；檔案路徑+行號=%s；例外型別=%s"
        % (st, has_trace, has_path, has_zero),
        "根因      : DEBUG 模式在正式環境開啟（本靶場 DEBUG_MODE=True）",
        "危害      : 洩漏內部結構、框架版本、檔案絕對路徑 → 大幅降低攻擊成本",
        "修補方向  : 正式環境關閉 debug；錯誤對外只回通用訊息 + 錯誤代碼",
        "OWASP 對照: A02 官方明確列出「不必要的功能開啟（unnecessary features）」",
        "            —— debug 功能是其中最典型的一項",
    ]
    check("C1 DEBUG 模式洩漏堆疊追蹤", "A02 / CWE-489",
          has_trace and has_path, "\n".join(ev))


def c2_missing_headers():
    """C2：缺少安全標頭。"""
    st, hdr, body = request("/")
    # 正規化標頭名（大小寫不敏感）
    lower = {k.lower(): v for k, v in hdr.items()}
    expected = {
        "content-security-policy": "防 XSS / 注入內容",
        "x-content-type-options": "防 MIME 嗅探",
        "x-frame-options": "防點擊劫持",
        "strict-transport-security": "強制 HTTPS",
        "referrer-policy": "控制 Referer 洩漏",
        "permissions-policy": "限制瀏覽器功能",
    }
    missing = [h for h in expected if h not in lower]
    # 另外檢查是否洩漏 Server 版本
    server_hdr = lower.get("server", "")
    ev = [
        "請求      : GET /",
        "預期漏洞  : 缺少安全標頭（本項檢查 6 個常見標頭）",
        "實際      : 缺少 %d/6 個：%s" % (len(missing), ", ".join(missing)),
        "Server 標頭: %r（暴露伺服器版本='%s'）" % (server_hdr, server_hdr),
        "根因      : 回應未加入任何安全標頭（程式碼沒有錯，是設定缺失）",
        "危害      : 瀏覽器缺少防護 → XSS 與點擊劫持風險升高",
        "修補方向  : 統一在伺服器或反向代理加入安全標頭（見修補版）",
        "驗證方式  : 必須讀**回應標頭**，不是讀 body —— A02 的驗證特色",
    ]
    check("C2 缺少安全標頭（6 項全缺）", "A02 / CWE-693",
          len(missing) == len(expected), "\n".join(ev))


def c3_cors_wildcard():
    """C3：CORS 萬用字元 + credentials。"""
    st, hdr, body = request("/api/data")
    lower = {k.lower(): v for k, v in hdr.items()}
    acao = lower.get("access-control-allow-origin", "")
    acac = lower.get("access-control-allow-credentials", "")
    wildcard = (acao == "*")
    creds = (acac.lower() == "true")
    ev = [
        "請求      : GET /api/data",
        "預期漏洞  : Access-Control-Allow-Origin: * 且 Allow-Credentials: true",
        "實際      : ACAO=%r；ACAC=%r" % (acao, acac),
        "根因      : CORS 設定為萬用字元，且同時允許攜帶憑證",
        "危害      : 任何網站都能讀取此 API 的回應",
        "            （若同時允許 credentials，等於任意外站可代使用者發請求）",
        "修補方向  : 明確列出允許的來源白名單；不要用 '*'",
        "            且避免『萬用字元 + credentials』的組合",
        "OWASP 對照: A02 官方列出 CORS 設定錯誤為典型項目",
    ]
    check("C3 CORS 萬用字元 + credentials", "A02 / CWE-942",
          wildcard and creds, "\n".join(ev))


def c4_default_credentials():
    """C4：預設憑證未變更。"""
    hits = []
    for u, p in (("admin", "admin"), ("root", "root"), ("guest", "guest")):
        st, _, body = request("/login?u=%s&p=%s" % (u, p))
        if st == 200 and "登入成功" in body:
            hits.append("%s:%s" % (u, p))
    # 附帶檢查使用者列舉
    st_a, _, body_a = request("/login?u=admin&p=wrong")
    st_b, _, body_b = request("/login?u=nosuchuser&p=wrong")
    enum = ("密碼錯誤" in body_a) and ("使用者不存在" in body_b)
    ev = [
        "請求      : GET /login?u=admin&p=admin（及其他預設帳密）",
        "預期漏洞  : 預設憑證可直接登入",
        "實際      : 成功登入的預設帳密：%s" % (", ".join(hits) or "無"),
        "附帶問題  : 錯誤訊息區分帳號是否存在（可列舉使用者）= %s" % enum,
        "根因      : 預設帳號未變更、預設密碼未強制更換",
        "危害      : 攻擊者用一組公開的預設值即可取得高權限",
        "修補方向  : 首次啟動強制設定密碼；停用或移除預設帳號；",
        "            錯誤訊息統一（不區分帳號是否存在）",
        "OWASP 對照: A02 官方列為首要項目『預設帳號與密碼』",
    ]
    check("C4 預設憑證未變更（3 組全部可登入）", "A02 / CWE-1392",
          len(hits) == 3, "\n".join(ev))


def c5_unsafe_http_methods():
    """C5：允許危險 HTTP 方法（PUT/DELETE）。"""
    st_put, _, body_put = request("/docs/readme", method="PUT",
                                  data="已被未授權修改")
    st_del, _, _ = request("/docs/internal", method="DELETE")
    allowed = (st_put == 200 and "已覆寫" in body_put)
    ev = [
        "請求 A    : PUT /docs/readme （無任何認證）→ HTTP %s" % st_put,
        "請求 B    : DELETE /docs/internal → HTTP %s" % st_del,
        "預期漏洞  : 危險方法未被限制，可直接修改/刪除資源",
        "實際      : PUT 成功=%s；DELETE HTTP %s" % (allowed, st_del),
        "根因      : 伺服器未限制允許的 HTTP 方法（也未做授權）",
        "危害      : 未授權的資料篡改與刪除",
        "修補方向  : 只允許業務需要的方法；對寫入操作強制授權；",
        "            對未支援的方法回 405 Method Not Allowed",
        "OWASP 對照: A02 包含『不必要的 HTTP 方法開啟』",
    ]
    check("C5 允許危險 HTTP 方法", "A02 / CWE-749", allowed, "\n".join(ev))


def c6_config_leak():
    """C6：設定與密鑰洩漏。"""
    st, _, body = request("/env")
    leaked = [k for k in ("AWS_SECRET_ACCESS_KEY", "JWT_SECRET", "DATABASE_URL",
                          "STRIPE_KEY") if k in body]
    has_pw = "SuperSecret123" in body
    ev = [
        "請求      : GET /env",
        "預期漏洞  : 端點直接輸出環境變數與密鑰",
        "實際      : HTTP %s；洩漏的密鑰項目：%s" % (st, ", ".join(leaked) or "無"),
        "資料庫密碼明文出現: %s" % has_pw,
        "根因      : 提供偵錯端點且未限制存取；機密放在可被讀取的位置",
        "危害      : 雲端金鑰外洩 → 攻擊者可操作正式環境資源",
        "修補方向  : 移除偵錯端點；機密改由密鑰管理服務（KMS/Vault）提供；",
        "            輸出前做欄位過濾",
    ]
    check("C6 設定與密鑰洩漏", "A02 / CWE-200",
          len(leaked) >= 3 and has_pw, "\n".join(ev))


def main():
    print("=" * 74)
    print(" ConfigLab 漏洞驗證 — A02 安全設定錯誤")
    print(" 目標：%s" % BASE)
    print("=" * 74)
    print(" 注意：A02 的漏洞多在『回應標頭』與『伺服器行為』，不在 body")
    print("=" * 74)

    st, _, _ = request("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        print("       請先啟動：python configlab.py %d" % PORT)
        sys.exit(1)

    for fn in (c1_debug_mode, c2_missing_headers, c3_cors_wildcard,
               c4_default_credentials, c5_unsafe_http_methods, c6_config_leak):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            check(fn.__name__, "-", False, "執行時例外：%s" % e)

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    found = sum(1 for _, _, p, _ in results if p)
    for name, owasp, passed, _ in results:
        print("  %-34s %-22s %s" % (name, owasp, "漏洞存在" if passed else "未觸發"))
    print("-" * 74)
    print("  共 %d/%d 個 A02 問題被驗證存在" % (found, len(results)))
    print("=" * 74)

    out = [{"name": n, "owasp": o, "present": p} for n, o, p, _ in results]
    with open("configlab_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 configlab_result.json）")


if __name__ == "__main__":
    main()
