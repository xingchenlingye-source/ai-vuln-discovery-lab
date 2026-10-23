#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_configlab_patched.py — A02 修補版驗證
=============================================================================
 對應研究報告 CH02.4：① 攻擊失效　② 功能保留

 A02 修補驗證的特色：
   「攻擊失效」在這裡的意思是**設定已修正**——標頭出現、方法被拒、
   端點移除、預設憑證失效。這些都必須從**回應標頭與狀態碼**判定。

 用法：
   python verify_configlab_patched.py 8909
=============================================================================
"""

import json
import re
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8909
BASE = "http://127.0.0.1:%d" % PORT
fix_results = []
func_results = []


def request(path, method="GET", data=None, headers=None):
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
    print(" A02 修補版驗證")
    print(" 目標：%s" % BASE)
    print("=" * 74)

    st, _, _ = request("/")
    if st != 200:
        print("\n[錯誤] 無法連線 %s（HTTP %s）" % (BASE, st))
        sys.exit(1)

    # ---------- C1 修補：不回 traceback ----------
    st1, _, b1 = request("/boom")
    no_trace = "Traceback (most recent call last)" not in b1
    has_err_id = bool(re.search(r"[0-9a-f]{8}", b1))
    check("fix", "C1 DEBUG 已關閉（不回 traceback）",
          no_trace and has_err_id,
          "請求   : GET /boom\n"
          "預期   : 不含 traceback；含錯誤代碼供追查\n"
          "實際   : HTTP %s；含 traceback = %s；含錯誤代碼 = %s"
          % (st1, not no_trace, has_err_id))

    # ---------- C2 修補：安全標頭齊全 ----------
    st2, h2, _ = request("/")
    lower = {k.lower(): v for k, v in h2.items()}
    expected = ["content-security-policy", "x-content-type-options", "x-frame-options",
                "strict-transport-security", "referrer-policy", "permissions-policy"]
    present = [h for h in expected if h in lower]
    server_hdr = lower.get("server", "")
    no_version = ("/" not in server_hdr)
    check("fix", "C2 安全標頭齊全（6/6）",
          len(present) == len(expected),
          "請求   : GET /\n"
          "預期   : 6 個安全標頭全部存在\n"
          "實際   : 存在 %d/6：%s\n"
          "Server : %r（未暴露版本 = %s）" % (len(present), ", ".join(present),
                                              server_hdr, no_version))

    # ---------- C3 修補：CORS 白名單 ----------
    # 白名單來源 → 應回傳該來源
    st_a, ha, _ = request("/api/data", headers={"Origin": BASE})
    la = {k.lower(): v for k, v in ha.items()}
    allowed_ok = (la.get("access-control-allow-origin") == BASE)
    # 非白名單來源 → 不應回 ACAO
    st_b, hb, _ = request("/api/data", headers={"Origin": "http://evil.example.com"})
    lb = {k.lower(): v for k, v in hb.items()}
    blocked_ok = ("access-control-allow-origin" not in lb)
    no_creds_star = (lb.get("access-control-allow-credentials") != "true")
    check("fix", "C3 CORS 改用白名單",
          allowed_ok and blocked_ok and no_creds_star,
          "請求 A : GET /api/data  Origin=%s（白名單）\n"
          "         → ACAO=%r（預期等於來源）\n"
          "請求 B : GET /api/data  Origin=http://evil.example.com（非白名單）\n"
          "         → ACAO=%r（預期不存在）\n"
          "預期   : 白名單通過、非白名單被拒、無 credentials:*\n"
          "實際   : 白名單通過=%s；非白名單被拒=%s；無 credentials=%s"
          % (BASE, la.get("access-control-allow-origin"),
             lb.get("access-control-allow-origin"),
             allowed_ok, blocked_ok, no_creds_star))

    # ---------- C4 修補：無預設憑證、訊息統一 ----------
    hits = []
    for u, p in (("admin", "admin"), ("root", "root"), ("guest", "guest")):
        stx, _, bx = request("/login?u=%s&p=%s" % (u, p))
        if stx == 200 and "登入成功" in bx:
            hits.append("%s:%s" % (u, p))
    st_a, _, ba = request("/login?u=alice&p=wrongpass")
    st_b, _, bb = request("/login?u=nosuchuser&p=wrongpass")
    same_msg = ("帳號或密碼錯誤" in ba) and ("帳號或密碼錯誤" in bb)
    check("fix", "C4 預設憑證失效、訊息統一",
          (len(hits) == 0) and same_msg,
          "請求 A : GET /login?u=admin&p=admin（及其他預設帳密）\n"
          "         → 成功登入：%s（預期：無）\n"
          "請求 B : 不存在的帳號 vs 錯誤密碼\n"
          "         → 回應訊息一致 = %s（防使用者列舉）"
          % (", ".join(hits) or "無", same_msg))

    # ---------- C5 修補：危險方法被拒 ----------
    st_put, h_put, _ = request("/docs/readme", method="PUT", data="x")
    st_del, _, _ = request("/docs/internal", method="DELETE")
    allow_hdr = {k.lower(): v for k, v in h_put.items()}.get("allow", "")
    check("fix", "C5 危險 HTTP 方法被拒（405）",
          st_put == 405 and st_del == 405,
          "請求 A : PUT /docs/readme → HTTP %s（預期 405，Allow: %r）\n"
          "請求 B : DELETE /docs/internal → HTTP %s（預期 405）"
          % (st_put, allow_hdr, st_del))

    # ---------- C6 修補：洩漏端點移除 ----------
    st_env, _, b_env = request("/env")
    st_health, _, b_health = request("/health")
    env_gone = (st_env == 404)
    no_secrets = not any(k in b_health for k in
                         ("AWS_SECRET", "JWT_SECRET", "DATABASE_URL", "SuperSecret123"))
    check("fix", "C6 洩漏端點移除（改為 /health）",
          env_gone and st_health == 200 and no_secrets,
          "請求 A : GET /env → HTTP %s（預期 404 已移除）\n"
          "請求 B : GET /health → HTTP %s；含任何機密 = %s（預期 200 且無機密）"
          % (st_env, st_health, not no_secrets))

    # ================= 條件 ②：功能保留 =================
    st_f1, _, b_f1 = request("/docs/readme")
    check("func", "文件仍可讀取",
          st_f1 == 200 and "公開說明文件" in b_f1,
          "請求   : GET /docs/readme\n預期   : 200 並顯示內容\n實際   : HTTP %s" % st_f1)

    st_f2, _, b_f2 = request("/docs")
    check("func", "文件列表仍可瀏覽",
          st_f2 == 200 and "readme" in b_f2,
          "請求   : GET /docs\n預期   : 200 並列出文件\n實際   : HTTP %s" % st_f2)

    st_f3, _, b_f3 = request("/login?u=alice&p=A-strong-password-9f3k")
    check("func", "正確憑證仍可登入",
          st_f3 == 200 and "登入成功" in b_f3,
          "請求   : GET /login?u=alice&p=A-strong-password-9f3k\n"
          "預期   : 200（功能未被過度封鎖）\n實際   : HTTP %s" % st_f3)

    st_f4, _, b_f4 = request("/health")
    check("func", "健康檢查端點可用",
          st_f4 == 200 and "status" in b_f4,
          "請求   : GET /health\n預期   : 200\n實際   : HTTP %s" % st_f4)

    st_f5, _, _ = request("/api/data")
    check("func", "API 仍可用（無 Origin 時）",
          st_f5 == 200,
          "請求   : GET /api/data（不帶 Origin）\n預期   : 200\n實際   : HTTP %s" % st_f5)

    f_ok, f_tot = show("fix", "設定缺陷修補（6 項）")
    g_ok, g_tot = show("func", "功能保留（5 項）")

    print("\n" + "=" * 74)
    print(" 總結")
    print("=" * 74)
    print("  攻擊失效 : %d/%d %s" % (f_ok, f_tot, "✓" if f_ok == f_tot else "✗"))
    print("  功能保留 : %d/%d %s" % (g_ok, g_tot, "✓" if g_ok == g_tot else "✗"))
    if f_ok == f_tot and g_ok == g_tot:
        print("\n  ✓ A02 修補驗證通過：設定缺陷全數修正，功能未受影響。")
    else:
        print("\n  ✗ 未通過，請檢查上列 FAIL 項目。")
    print("=" * 74)


if __name__ == "__main__":
    main()
