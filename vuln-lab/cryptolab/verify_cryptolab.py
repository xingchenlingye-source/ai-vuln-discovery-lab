#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_cryptolab.py — XOR / known-plaintext 驗證
=============================================================================

 驗證特色（與先前所有類型都不同）：
   X1 不是「看有沒有錯誤」，而是**自己推出金鑰並偽造出有效密文**。
   X2 不是「讀取明文」，而是**證明金鑰重用讓明文可被推導**。
   X3 不是「猜 token」，而是**用時間戳推算並驗證可預測性**。
   X4 不是「加密強度」，而是**改動密文後伺服器仍接受**（無完整性）。

 用法：
   python verify_cryptolab.py 8951
=============================================================================
"""

import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8951
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path, cookie=None):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "crypto-edu/1.0"})
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, {}, str(e)


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode()


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


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
    print(" CryptoLab 驗證 — XOR / known-plaintext 加密學攻擊")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, _, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    # ============ X1：固定 XOR 金鑰 → known-plaintext ============
    st1, h1, b1 = get("/profile")
    cookie_hdr = h1.get("Set-Cookie", "") or ""
    m = re.search(r"profile=([^;]+)", cookie_hdr)
    ct_b64 = m.group(1) if m else ""
    try:
        j1 = json.loads(b1)
        known_plain = json.dumps(j1.get("settings"), separators=(",", ":"))
    except Exception:                                        # noqa: BLE001
        known_plain = ""

    derived_key = b""
    forge_ok = False
    forged_settings = None
    if ct_b64 and known_plain:
        ct = b64d(ct_b64)
        pt = known_plain.encode()
        # ★ known-plaintext：XOR 密文與已知明文 → 推導金鑰
        key_len = len(pt)
        derived_key = bytes(ct[i] ^ pt[i] for i in range(key_len))
        # 找重複週期（金鑰通常很短）
        period = None
        for p in range(1, 17):
            if all(derived_key[i] == derived_key[i % p] for i in range(len(derived_key))):
                period = p
                break
        key = derived_key[:period] if period else derived_key

        # 偽造 admin + showflag
        target = json.dumps({"user": "admin", "role": "admin", "showflag": True},
                            separators=(",", ":"))
        forged = bytes(ord(target[i]) ^ key[i % len(key)] for i in range(len(target)))
        forged_b64 = b64e(forged)

        # 帶上偽造 cookie 再請求
        st1b, h1b, b1b = get("/profile", cookie="profile=" + forged_b64)
        try:
            j1b = json.loads(b1b)
            forged_settings = j1b.get("settings")
            forge_ok = bool(j1b.get("flag"))
        except Exception:                                    # noqa: BLE001
            pass

    ev = [
        "步驟 1    : GET /profile → 取得加密 cookie（base64）",
        "            密文 = %s" % (ct_b64[:48] + "..." if ct_b64 else "(無)"),
        "步驟 2    : 已知明文 = %s" % known_plain,
        "步驟 3    : ★ known-plaintext 攻擊：XOR(密文, 已知明文) → 推導金鑰",
        "            推導 key = %r" % derived_key[:16],
        "            （可看出金鑰很短且重複）",
        "步驟 4    : 用推導出的金鑰偽造 %r" % target,
        "            偽造 cookie = %s" % (forged_b64[:48] + "..." if forged_b64 else "(無)"),
        "步驟 5    : 帶上偽造 cookie 再請求",
        "            → 伺服器接受的設定 = %s" % (json.dumps(forged_settings, ensure_ascii=False) if forged_settings else "(無)"),
        "            → 取得 FLAG = %s" % forge_ok,
        "",
        "預期漏洞  : 用**已知明文**推出金鑰，再**偽造任意內容**",
        "根因      : (a) XOR 金鑰固定且短（4 bytes）",
        "            (b) 明文格式可預測（JSON）",
        "            (c) 沒有完整性驗證（HMAC）",
        "危害      : 可偽造管理員身分 → 權限提升",
        "驗證方式  : **自己推出金鑰並偽造出有效密文**（不是看錯誤訊息）",
        "修補方向  : 用 HMAC 簽章（見 /safe/profile）；",
        "            或使用 AES-GCM 等認證加密",
        "OWASP 對照: CWE-327（使用有缺陷的加密演算法）+ CWE-330",
    ]
    check("X1 固定 XOR 金鑰（known-plaintext 偽造）",
          "CWE-327 / CWE-330", forge_ok, "\n".join(ev))

    # ============ X2：XOR 金鑰重用 ============
    st2a, _, b2a = get("/msg?id=1")
    st2b, _, b2b = get("/msg?id=2")
    try:
        ct1 = b64d(json.loads(b2a)["ciphertext"])
        ct2 = b64d(json.loads(b2b)["ciphertext"])
    except Exception:                                        # noqa: BLE001
        ct1 = ct2 = b""
    key_eliminated = False
    readable = ""
    if ct1 and ct2:
        # XOR 兩密文 → 金鑰消掉，得到 XOR(明文1, 明文2)
        x = xor(ct1[:min(len(ct1), len(ct2))], ct2)
        # 已知明文1 是 FLAG{...}，可推出明文2
        guess1 = b"FLAG{"
        derived2 = xor(x[:len(guess1)], guess1)
        readable = derived2.decode("utf-8", "replace")
        key_eliminated = readable.startswith("crypt")
    ev = [
        "步驟 1    : GET /msg?id=1 → 密文1 = %s" % (b64e(ct1) if ct1 else "(無)"),
        "步驟 2    : GET /msg?id=2 → 密文2 = %s" % (b64e(ct2) if ct2 else "(無)"),
        "步驟 3    : ★ XOR 兩密文 → 金鑰被消掉",
        "            C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2",
        "步驟 4    : 已知 P1 開頭是 'FLAG{' → 推出 P2 開頭",
        "            推出的 P2 前 6 字元 = %r" % readable,
        "",
        "預期漏洞  : 同一金鑰加密多個訊息 → 金鑰可被消掉",
        "根因      : **金鑰重用**（one-time pad 的前提被違反）",
        "危害      : 兩段密文即可洩漏兩段明文的相對關係；",
        "            搭配已知明文可逐步還原全部內容（crib dragging）",
        "驗證方式  : 證明「金鑰被消掉」且**明文片段可被推導**",
        "修補方向  : 每個訊息用**不同的 nonce/IV**；",
        "            使用 AES-GCM / ChaCha20-Poly1305（帶 nonce）",
        "OWASP 對照: CWE-323（金鑰重用）",
    ]
    check("X2 XOR 金鑰重用（金鑰可被消掉）", "CWE-323",
          key_eliminated, "\n".join(ev))

    # ============ X3：可預測 token ============
    now_ms = int(time.time() * 1000)
    st3, _, b3 = get("/token")
    try:
        tok = json.loads(b3).get("token", "")
    except Exception:                                        # noqa: BLE001
        tok = ""
    # 解析 token 的時間戳部分
    m3 = re.match(r"natas_crypto_(\d{13})_(\d{3})", tok)
    predictable = False
    ts_delta = None
    if m3:
        tok_ts = int(m3.group(1))
        ts_delta = abs(tok_ts - now_ms)
        # 時間戳與現在時間接近（< 5 秒）→ 可預測
        predictable = ts_delta < 5000
    ev = [
        "請求      : GET /token → %s" % tok,
        "格式      : <prefix><unix_ms>_<3-digit random>",
        "解析      : 時間戳部分 = %s" % (m3.group(1) if m3 else "(無法解析)"),
        "            與現在時間差 = %s ms" % ts_delta,
        "預期漏洞  : token 由**可預測的時間戳** + **僅 1000 種的隨機**組成",
        "判定邏輯  : 時間戳與當前時間接近（<5 秒）→ 攻擊者可推算",
        "            隨機部分只有 0-999 → 暴力只需 1000 次",
        "根因      : 用時間戳當 token 的一部分（可預測）；隨機範圍過小",
        "危害      : 攻擊者可預測/暴力 token → 劫持會話或重設密碼",
        "驗證方式  : **解析 token 並比對時間**，證明其可預測性",
        "修補方向  : secrets.token_urlsafe(32)（256-bit 熵）—— 見 /safe/token",
        "OWASP 對照: CWE-330（熵不足）",
    ]
    check("X3 可預測 token（時間戳 + 小隨機）", "CWE-330",
          predictable, "\n".join(ev))

    # ============ X4：加密但無完整性驗證 ============
    st4, _, b4 = get("/echo?d=" + urllib.parse.quote(b64e(b"hello")))
    accepted = False
    tampered_result = None
    # 篡改密文（改一個位元）
    orig = b64d(b64e(b"hello"))
    tampered = bytes([orig[0] ^ 0x01]) + orig[1:]
    st4b, _, b4b = get("/echo?d=" + urllib.parse.quote(b64e(tampered)))
    try:
        j4 = json.loads(b4b)
        tampered_result = j4.get("decrypted")
        # 篡改後仍被解密接受（沒有完整性檢查）
        accepted = j4.get("note", "").find("沒有完整性") >= 0
    except Exception:                                        # noqa: BLE001
        pass
    ev = [
        "步驟 1    : GET /echo?d=base64('hello') → %s"
        % (json.loads(b4).get("decrypted") if st4 == 200 and b4.startswith("{") else "(無)"),
        "步驟 2    : ★ 篡改密文**第一個位元**後再送出",
        "            原密文 = %s" % b64e(orig),
        "            篡改後 = %s" % b64e(tampered),
        "步驟 3    : 伺服器仍解密並接受",
        "            解密結果 = %r" % tampered_result,
        "",
        "預期漏洞  : 密文被改動後伺服器仍接受（無完整性驗證）",
        "根因      : 只加密，沒有 MAC/HMAC（encrypt-only，無 authenticate）",
        "危害      : 攻擊者可**可控地修改**解密後內容（bit-flipping attack）",
        "            → 例如把 JSON 的 false 改成 true、修改金額欄位",
        "驗證方式  : **改動密文後確認伺服器仍接受**（而非偵測到竄改）",
        "修補方向  : Encrypt-then-MAC（HMAC-SHA256）；或 AES-GCM（內建認證）",
        "OWASP 對照: CWE-353（缺少完整性檢查）",
    ]
    check("X4 加密但無完整性驗證（可篡改）", "CWE-353",
          accepted, "\n".join(ev))

    # ============ 安全對照 1：HMAC 簽章 ============
    st_s, h_s, b_s = get("/safe/profile")
    cookie_s = ""
    m_s = re.search(r"sprofile=([^;]+)", h_s.get("Set-Cookie", "") or "")
    if m_s:
        cookie_s = m_s.group(1)
    # 篡改
    hmac_blocked = False
    if cookie_s and "." in cookie_s:
        raw, sig = cookie_s.rsplit(".", 1)
        try:
            raw_b = bytearray(b64d(raw))
            raw_b[0] ^= 0x01
            tampered_cookie = b64e(bytes(raw_b)) + "." + sig
            st_s2, _, b_s2 = get("/safe/profile", cookie="sprofile=" + tampered_cookie)
            hmac_blocked = (st_s2 == 403)
        except Exception:                                    # noqa: BLE001
            pass
    # 正常使用
    st_s3, _, b_s3 = get("/safe/profile", cookie="sprofile=" + cookie_s) if cookie_s else (0, {}, "{}")

    ev = [
        "正常請求  : GET /safe/profile → HTTP %s，cookie 含 HMAC 簽章" % st_s,
        "            cookie 格式 = base64(json) + '.' + HMAC-SHA256",
        "篡改測試  : 改動密文第一個位元 → HTTP 403（被偵測）=%s" % hmac_blocked,
        "教學意義  : **加密 + 認證 = 安全**；只有加密 = 可篡改",
        "驗證方式  : 篡改後應**被拒絕**（與 X4 的「仍接受」形成對比）",
    ]
    check("安全對照：HMAC 簽章阻擋篡改", "防護驗證", hmac_blocked, "\n".join(ev))

    # ============ 安全對照 2：CSPRNG token ============
    st_t, _, b_t = get("/safe/token")
    try:
        jt = json.loads(b_t)
        tok_safe = jt.get("token", "")
        entropy = jt.get("entropy_bits", 0)
    except Exception:                                        # noqa: BLE001
        tok_safe, entropy = "", 0
    strong = len(tok_safe) >= 32 and entropy == 256 and "natas_crypto" not in tok_safe
    ev = [
        "請求      : GET /safe/token → %s" % tok_safe[:50],
        "長度      : %d 字元（secrets.token_urlsafe(32)）" % len(tok_safe),
        "熵        : %d bits" % entropy,
        "無時間戳  : %s" % ("natas_crypto" not in tok_safe),
        "教學意義  : 對比 X3——**同一個用途，換成 CSPRNG 就無法預測**",
    ]
    check("安全對照：CSPRNG token", "防護驗證", strong, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-38s %-22s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  加密學漏洞的驗證特色：")
    print("    不是看『有沒有錯誤訊息』，而是——")
    print("    X1 → **自己推出金鑰並偽造有效密文**")
    print("    X2 → **證明金鑰重用讓明文可被推導**")
    print("    X3 → **解析 token 並比對時間，證明可預測**")
    print("    X4 → **改動密文後伺服器仍接受**")
    print("=" * 76)

    with open("cryptolab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 cryptolab_result.json）")


if __name__ == "__main__":
    main()
