#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 rsa_sign.py — 非對稱簽章與信任鏈（A03 缺口修補）
=============================================================================

 對應研究報告 CH06 S1（OWASP A03 Software Supply Chain Failures）。

 為什麼需要這個？—— 補上 HMAC 的根本限制
   sbom.py 用 HMAC-SHA256 簽章，但 HMAC 是**對稱式**：
   驗證者必須持有同一把密鑰 → 也就有能力**偽造簽章**。
   這在供應鏈場景下是致命的：

     你要證明「這個 SBOM 是我發的」，但驗證者拿到密鑰後
     也能產出一模一樣的簽章 —— 「來源可信」根本無法成立。

   非對稱簽章解決這個問題：**私鑰簽、公鑰驗**。
   驗證者只有公鑰，無法偽造；而任何人只要有公鑰都能驗證。

 本工具實作（只用標準庫，無外部密碼學套件）：
   1. RSA-2048 金鑰生成（Miller-Rabin 質數測試）
   2. PKCS#1 v1.5 + SHA-256 簽章與驗證
   3. 信任鏈示範：根 CA 簽發發佈者憑證（公鑰 + 身分），
      發佈者用私鑰簽 SBOM，用戶用根 CA 公鑰驗證整條鏈

 ⚠ 重要聲明（誠實邊界）
   本實作為**教育示範**，未經密碼學審查，也**不是常數時間**實作。
   真實系統請使用 libsodium / OpenSSL / cryptography / Sigstore，
   並使用 Ed25519 或 ECDSA 等現代演算法。
   本工具的目的是讓你**親手理解**「非對稱簽章」與「信任鏈」的機制。

 用法：
   python rsa_sign.py keygen                      # 產生 CA 與發佈者金鑰
   python rsa_sign.py issue-cert                  # CA 簽發發佈者憑證
   python rsa_sign.py sign sbom.json              # 發佈者簽章
   python rsa_sign.py verify sbom.json sbom.asc   # 驗證（含信任鏈）
   python rsa_sign.py demo                        # 一鍵完整流程
=============================================================================
"""

import base64
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CA_PRIV = os.path.join(HERE, "keys", "ca_private.json")
CA_PUB = os.path.join(HERE, "keys", "ca_public.json")
PUB_PRIV = os.path.join(HERE, "keys", "publisher_private.json")
PUB_PUB = os.path.join(HERE, "keys", "publisher_public.json")
CERT = os.path.join(HERE, "keys", "publisher_cert.json")
KEYS_DIR = os.path.join(HERE, "keys")


# ---------------------------------------------------------------------------
# 大數工具
# ---------------------------------------------------------------------------
def is_probable_prime(n, rounds=40):
    """Miller-Rabin 質數測試。"""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """產生指定位數的質數。"""
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def modinv(a, m):
    """模反元素（擴展歐幾里得）。"""
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def _egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def int_to_b64(i, size=None):
    b = i.to_bytes(size or ((i.bit_length() + 7) // 8), "big")
    return base64.b64encode(b).decode()


def b64_to_int(s):
    return int.from_bytes(base64.b64decode(s), "big")


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------
E = 65537


def rsa_keygen(bits=2048):
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % E == 0:
            continue
        d = modinv(E, phi)
        return {"n": n, "e": E, "d": d}


# PKCS#1 v1.5 的 DigestInfo 前置（SHA-256）
SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

# 已知測試向量：用於自我檢驗實作是否正確
# RFC 8017 附錄 A.2.4？無——改用「簽章後自我驗證 + 交叉檢查填充」的方式


def pkcs1v15_pad_sha256(msg_hash: bytes, k: int) -> bytes:
    """PKCS#1 v1.5 EMSA-PKCS1-v1_5 padding（k = 模數位元組長）。"""
    t = SHA256_DIGESTINFO_PREFIX + msg_hash
    if k < len(t) + 11:
        raise ValueError("key too short")
    ps = b"\xff" * (k - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def rsa_sign(key, data: bytes) -> bytes:
    k = (key["n"].bit_length() + 7) // 8
    h = hashlib.sha256(data).digest()
    em = pkcs1v15_pad_sha256(h, k)
    m = int.from_bytes(em, "big")
    s = pow(m, key["d"], key["n"])
    return s.to_bytes(k, "big")


def rsa_verify(pub, data: bytes, sig: bytes) -> bool:
    k = (pub["n"].bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), pub["e"], pub["n"])
    em = m.to_bytes(k, "big")
    h = hashlib.sha256(data).digest()
    try:
        expected = pkcs1v15_pad_sha256(h, k)
    except ValueError:
        return False
    return secrets.compare_digest(em, expected)


def save_key(path, key):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({k: int_to_b64(v) if isinstance(v, int) else v
                   for k, v in key.items()}, f, indent=2)


def load_key(path):
    """載入金鑰。

    注意（實際踩到的坑）：save_key 會把**所有整數**（含 e）以 base64 儲存，
    所以讀取時必須一致地解碼——不能只解 n/d 而把 e 當十進位字串。
    這裡同時容忍兩種格式，避免舊檔造成 ValueError。
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    out = {}
    for k, v in raw.items():
        if k in ("n", "d", "e"):
            if isinstance(v, str):
                try:
                    out[k] = b64_to_int(v)      # base64 大數（save_key 的格式）
                except Exception:               # noqa: BLE001
                    out[k] = int(v)             # 後備：十進位字串
            else:
                out[k] = int(v)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# 命令
# ---------------------------------------------------------------------------
def cmd_keygen():
    print("=" * 78)
    print(" 產生金鑰（RSA-2048）")
    print("=" * 78)
    print(" 正在產生根 CA 金鑰（質數搜尋可能需要數秒）...")
    ca = rsa_keygen(2048)
    save_key(CA_PRIV, ca)
    save_key(CA_PUB, {"n": ca["n"], "e": ca["e"]})
    print("  ✓ 根 CA 金鑰：%s" % CA_PRIV)

    print(" 正在產生發佈者金鑰 ...")
    pub = rsa_keygen(2048)
    save_key(PUB_PRIV, pub)
    save_key(PUB_PUB, {"n": pub["n"], "e": pub["e"]})
    print("  ✓ 發佈者金鑰：%s" % PUB_PRIV)
    print("=" * 78)
    print("""
 非對稱簽章的核心：
   私鑰（*_private.json）→ 只有發佈者持有，用來「簽」
   公鑰（*_public.json） → 公開給所有人，用來「驗」
   驗證者**無法**用公鑰產出有效簽章 → 這正是 HMAC 做不到的。
""")
    return 0


def cmd_issue_cert():
    """CA 用私鑰簽發發佈者憑證（把公鑰與身分綁定）。"""
    ca_priv = load_key(CA_PRIV)
    pub_pub = load_key(PUB_PUB)

    cert_body = {
        "version": 1,
        "subject": "vuln-lab supplychain-lab publisher",
        "issuer": "vuln-lab root CA",
        "public_key": {"n": int_to_b64(pub_pub["n"]), "e": pub_pub["e"]},
        "not_before": datetime.now(timezone.utc).isoformat(),
        "serial": secrets.token_hex(8),
    }
    body_bytes = json.dumps(cert_body, sort_keys=True,
                            ensure_ascii=False).encode("utf-8")
    sig = rsa_sign(ca_priv, body_bytes)

    cert = {"body": cert_body, "signature": base64.b64encode(sig).decode()}
    with open(CERT, "w", encoding="utf-8") as f:
        json.dump(cert, f, ensure_ascii=False, indent=2)

    print("=" * 78)
    print(" 憑證簽發（信任鏈的第一環）")
    print("=" * 78)
    print(" 主旨      : %s" % cert_body["subject"])
    print(" 簽發者    : %s" % cert_body["issuer"])
    print(" 序號      : %s" % cert_body["serial"])
    print(" 簽章長度  : %d bytes" % len(sig))
    print(" 輸出      : %s" % CERT)
    print("=" * 78)
    print("""
 這份憑證的意義：
   CA 用自己的**私鑰**簽了「發佈者公鑰 + 身分」的組合。
   任何人只要有 **CA 公鑰**，就能確認「這把公鑰確實屬於該發佈者」。
   → 這就是信任鏈：你把信任集中在 CA，CA 替你保證每個發佈者。
""")
    return 0


def cmd_sign(target):
    priv = load_key(PUB_PRIV)
    with open(target, "rb") as f:
        data = f.read()
    sig = rsa_sign(priv, data)
    out = target + ".rsa.asc"
    payload = {
        "file": os.path.basename(target),
        "algorithm": "RSA-2048/PKCS1v15/SHA-256",
        "sha256": hashlib.sha256(data).hexdigest(),
        "signature": base64.b64encode(sig).decode(),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print("=" * 78)
    print(" 非對稱簽章（RSA-2048 / PKCS#1 v1.5 / SHA-256）")
    print("=" * 78)
    print(" 檔案      : %s" % target)
    print(" SHA-256   : %s" % payload["sha256"])
    print(" 簽章長度  : %d bytes" % len(sig))
    print(" 輸出      : %s" % out)
    print("=" * 78)
    return 0


def cmd_verify(target, sigfile):
    ca_pub = load_key(CA_PUB)
    with open(CERT, "r", encoding="utf-8") as f:
        cert = json.load(f)
    with open(sigfile, "r", encoding="utf-8") as f:
        sig_data = json.load(f)
    with open(target, "rb") as f:
        data = f.read()

    print("=" * 78)
    print(" 驗證（信任鏈 + 簽章）")
    print("=" * 78)

    # 步驟 1：用 CA 公鑰驗證「發佈者憑證」
    cert_body_bytes = json.dumps(cert["body"], sort_keys=True,
                                 ensure_ascii=False).encode("utf-8")
    cert_sig = base64.b64decode(cert["signature"])
    cert_ok = rsa_verify(ca_pub, cert_body_bytes, cert_sig)
    print(" 步驟 1  憑證是否由根 CA 簽發 : %s" % ("✓ 是" if cert_ok else "✗ 否"))
    print("         主旨：%s" % cert["body"]["subject"])

    # 步驟 2：從憑證取出發佈者公鑰
    pub = {"n": b64_to_int(cert["body"]["public_key"]["n"]),
           "e": cert["body"]["public_key"]["e"]}
    print(" 步驟 2  從憑證取得發佈者公鑰 : ✓（n 為 %d bits）" % pub["n"].bit_length())

    # 步驟 3：用發佈者公鑰驗證 SBOM 簽章
    sig = base64.b64decode(sig_data["signature"])
    file_ok = rsa_verify(pub, data, sig)
    hash_ok = hashlib.sha256(data).hexdigest() == sig_data["sha256"]
    print(" 步驟 3  檔案簽章驗證         : %s" % ("✓ 通過" if file_ok else "✗ 失敗"))
    print("         檔案雜湊一致         : %s" % ("✓" if hash_ok else "✗"))

    print("-" * 78)
    if cert_ok and file_ok and hash_ok:
        print(" ✓ 完整信任鏈驗證通過：")
        print("     根 CA（信任錨） → 發佈者憑證 → SBOM 簽章 → 檔案內容")
        print("""
 為什麼這比 HMAC 強？
   HMAC：驗證者必須持有密鑰 → 也能偽造簽章 → 無法證明「誰發的」
   RSA ：驗證者只有公鑰 → 無法偽造 → 能證明「只有私鑰持有者能發這個」

 這正是 OWASP A03 所說的「驗證元件的來源與完整性」。

 ⚠ 誠實邊界（本實作 vs 真實系統）：
   本工具未經密碼學審查、非常數時間、無金鑰撤銷機制。
   真實系統請用 Sigstore/cosign（含透明度日誌 Rekor）、
   OpenSSL、或 libsodium，並使用 Ed25519/ECDSA。
   信任鏈還需要：憑證到期與撤銷（CRL/OCSP）、時間戳。
""")
        return 0
    print(" ✗ 驗證失敗：來源不可信或檔案已被篡改")
    return 1


def cmd_demo():
    print("\n" + "#" * 78)
    print("# 非對稱簽章與信任鏈 — 完整示範")
    print("#" * 78 + "\n")
    cmd_keygen()
    print()
    cmd_issue_cert()
    print()
    sbom = os.path.join(HERE, "sbom.json")
    if not os.path.exists(sbom):
        print("（找不到 sbom.json，請先執行 sbom.py generate）")
        return 1
    cmd_sign(sbom)
    print()
    rc = cmd_verify(sbom, sbom + ".rsa.asc")

    # 篡改測試
    print("\n" + "#" * 78)
    print("# 篡改測試：改一個位元組後再驗證")
    print("#" * 78 + "\n")
    with open(sbom, "rb") as f:
        orig = f.read()
    tampered = orig.replace(b'"version": 1', b'"version": 2', 1)
    if tampered == orig:
        tampered = orig[:-2] + b' \n}'
    with open(sbom, "wb") as f:
        f.write(tampered)
    rc2 = cmd_verify(sbom, sbom + ".rsa.asc")
    with open(sbom, "wb") as f:
        f.write(orig)
    print("\n（已還原 sbom.json）")
    if rc == 0 and rc2 != 0:
        print("\n✓ 示範成功：正常檔案通過驗證，篡改後驗證失敗。")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "keygen":
        return cmd_keygen()
    if cmd == "issue-cert":
        return cmd_issue_cert()
    if cmd == "sign":
        return cmd_sign(sys.argv[2])
    if cmd == "verify":
        return cmd_verify(sys.argv[2], sys.argv[3])
    if cmd == "demo":
        return cmd_demo()
    print("未知指令：%s" % cmd)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
