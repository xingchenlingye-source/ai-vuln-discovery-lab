#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 run_all.py — 統一驗證管線（整合五種驗證型態）
=============================================================================

 對應研究報告 CH06 S1 與 CH02.1。

 為什麼需要這個？（補上最後的缺口）
   本專案有 6 個靶場、5 種驗證型態，但先前都是「各跑各的」。
   真實的 CI 需要一鍵執行全部並回報結果。

 五種驗證型態（本管線會各自正確處理）：
   ① 注入類（authlab）      → 看 HTTP 回應內容
   ② 日誌類（loglab）       → 檢查日誌與告警檔案
   ③ 競態類（buyLab）       → 必須**併發**請求
   ④ 加密類（buyLab/authlab2）→ 已知值反查／重現性
   ⑤ 設定類（configlab）    → 讀**回應標頭**與允許的方法

 本管線的工作：
   1. 自動選擇空閒埠並啟動靶場
   2. 執行對應的驗證腳本
   3. 收集結果（漏洞版應全部「存在」，修補版應全部「失效」）
   4. 產生彙總報告，必要時以非零碼結束（供 CI 判斷）

 用法：
   python run_all.py                 # 全部執行
   python run_all.py --only authlab  # 只跑特定靶場
   python run_all.py --quick         # 跳過 C 編譯類（fuzzer）
=============================================================================
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
# 本檔位於 vuln-lab/ 之下，所以 HERE 就是 lab 根目錄。
# （先前的版本誤把 LAB 設成父目錄，導致所有靶場都被判定為「檔案不存在」。）
LAB = HERE

# 靶場定義：(名稱, 目錄, 啟動檔, 驗證腳本, 埠, 期望, 型態)
TARGETS = [
    {
        "name": "authlab",
        "dir": os.path.join(LAB, "authlab"),
        "server": "authlab.py",
        "verify": "verify_authlab.py",
        "port": 8910,
        "expect": "vulnerable",          # 漏洞版：全部應存在
        "kind": "注入類（看回應內容）",
    },
    {
        "name": "authlab2",
        "dir": os.path.join(LAB, "authlab"),
        "server": "authlab2.py",
        "verify": "verify_authlab2.py",
        "port": 8911,
        "expect": "vulnerable",
        "kind": "認證類（看回應與資料庫狀態）",
    },
    {
        "name": "loglab",
        "dir": os.path.join(LAB, "loglab"),
        "server": "loglab.py",
        "verify": "verify_loglab.py",
        "port": 8912,
        "expect": "vulnerable",
        "kind": "日誌類（看日誌與告警檔案）",
    },
    {
        "name": "buyLab",
        "dir": os.path.join(LAB, "buyLab"),
        "server": "buyLab.py",
        "verify": "verify_buylab.py",
        "port": 8913,
        "expect": "vulnerable",
        "kind": "競態類（必須併發）+ 加密類",
    },
    {
        "name": "configlab",
        "dir": os.path.join(LAB, "configlab"),
        "server": "configlab.py",
        "verify": "verify_configlab.py",
        "port": 8914,
        "expect": "vulnerable",
        "kind": "設定類（看回應標頭）",
    },
    # ---- 修補版：期望「0 個漏洞存在」----
    {
        "name": "authlab-patched",
        "dir": os.path.join(LAB, "authlab"),
        "server": "authlab_patched.py",
        "verify": "verify_patched.py",
        "port": 8915,
        "expect": "fixed",
        "kind": "修補驗證（攻擊失效 + 功能保留）",
    },
    {
        "name": "loglab-patched",
        "dir": os.path.join(LAB, "loglab"),
        "server": "loglab_patched.py",
        "verify": "verify_loglab_patched.py",
        "port": 8916,
        "expect": "fixed",
        "kind": "修補驗證（缺口補上 + 功能保留）",
    },
    {
        "name": "buyLab-patched",
        "dir": os.path.join(LAB, "buyLab"),
        "server": "buyLab_patched.py",
        "verify": "verify_buylab_patched.py",
        "port": 8917,
        "expect": "fixed",
        "kind": "修補驗證（攻擊失效 + 功能保留）",
    },
    {
        "name": "configlab-patched",
        "dir": os.path.join(LAB, "configlab"),
        "server": "configlab_patched.py",
        "verify": "verify_configlab_patched.py",
        "port": 8918,
        "expect": "fixed",
        "kind": "修補驗證（攻擊失效 + 功能保留）",
    },
]


def free_port(start):
    """從 start 開始找一個空閒埠。"""
    p = start
    for _ in range(200):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
        p += 1
    return start


def wait_ready(port, timeout=30):
    """等待靶場就緒（能連上即視為就緒）。"""
    t0 = time.time()
    while time.time() - t0 < timeout:
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.4)
    return False


def parse_result(output):
    """從驗證腳本輸出解析結果。

    支援兩種格式：
      「共 N/M 個...被驗證存在」    （漏洞版）
      「攻擊失效 : N/M」「缺口補上 : N/M」「功能保留 : N/M」
    """
    found = passed = total = None
    m = re.search(r"共\s*(\d+)/(\d+)\s*個", output)
    if m:
        found, total = int(m.group(1)), int(m.group(2))
        return {"found": found, "total": total}
    # 修補版
    pairs = re.findall(r"(?:攻擊失效|缺口補上|功能保留)\s*:\s*(\d+)/(\d+)", output)
    if pairs:
        ok = sum(int(a) for a, _ in pairs)
        tot = sum(int(b) for _, b in pairs)
        return {"fixed_ok": ok, "fixed_total": tot, "groups": len(pairs)}
    return {}


def run_target(t, keep=False, verbose=False):
    """啟動靶場 → 驗證 → 關閉。回傳結果 dict。"""
    exe = sys.executable
    server_path = os.path.join(t["dir"], t["server"])
    verify_path = os.path.join(t["dir"], t["verify"])

    if not os.path.exists(server_path) or not os.path.exists(verify_path):
        return {"name": t["name"], "ok": False, "error": "檔案不存在"}

    port = free_port(t["port"])
    env = dict(os.environ, PYTHONIOENCODING="utf-8", ASAN_OPTIONS="detect_leaks=0")

    proc = subprocess.Popen(
        [exe, t["server"], str(port)],
        cwd=t["dir"], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_ready(port):
            return {"name": t["name"], "ok": False, "error": "靶場啟動逾時"}

        p = subprocess.run([exe, t["verify"], str(port)],
                           cwd=t["dir"], env=env,
                           capture_output=True, timeout=300)
        out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
        res = parse_result(out)

        # 判定
        if t["expect"] == "vulnerable":
            ok = res.get("found") is not None and res["found"] == res["total"]
            detail = res
        else:
            ok = (res.get("fixed_ok") is not None
                  and res["fixed_ok"] == res["fixed_total"])
            detail = res

        if verbose and not ok:
            print("        --- 輸出尾部 ---")
            for line in out.strip().splitlines()[-12:]:
                print("        " + line)

        return {"name": t["name"], "ok": ok, "kind": t["kind"],
                "port": port, "detail": detail}
    except subprocess.TimeoutExpired:
        return {"name": t["name"], "ok": False, "error": "驗證逾時"}
    except Exception as e:                                   # noqa: BLE001
        return {"name": t["name"], "ok": False, "error": str(e)}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


def run_fuzzer_check():
    """額外檢查：fuzzer 對照實驗（比較慢，--quick 可跳過）。"""
    exe = os.path.join(LAB, "fuzz_v2", "work", "fuzz_main.exe")
    if not os.path.exists(exe):
        return {"name": "fuzzer", "ok": None, "error": "未建置（需先執行 benchmark.py）"}
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    w = os.path.join(LAB, "fuzz_v2", "work")
    for f in ("crash.bin", "coverage_at_crash.txt"):
        try:
            os.remove(os.path.join(w, f))
        except OSError:
            pass
    try:
        p = subprocess.run([exe, "guided", "200000", "0x1"], cwd=w, env=env,
                           capture_output=True, timeout=300)
        out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
        crashed = "AddressSanitizer" in out
        cov = "?"
        cpath = os.path.join(w, "coverage_at_crash.txt")
        if os.path.exists(cpath):
            with open(cpath, encoding="utf-8") as f:
                m = re.search(r"coverage_at_crash=(\d+)", f.read())
                if m:
                    cov = m.group(1)
        return {"name": "fuzzer", "ok": crashed,
                "kind": "覆蓋率引導 fuzzing", "detail": {"coverage_at_crash": cov}}
    except Exception as e:                                   # noqa: BLE001
        return {"name": "fuzzer", "ok": False, "error": str(e)}


def main():
    ap = argparse.ArgumentParser(description="統一驗證管線")
    ap.add_argument("--only", help="只跑指定靶場（名稱子字串）")
    ap.add_argument("--quick", action="store_true", help="跳過 fuzzer 檢查")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    targets = TARGETS
    if args.only:
        targets = [t for t in targets if args.only.lower() in t["name"].lower()]

    print("=" * 78)
    print(" 統一驗證管線（整合五種驗證型態）")
    print("=" * 78)
    print(" 時間   : %s" % datetime.now(timezone.utc).astimezone().isoformat())
    print(" 靶場數 : %d" % len(targets))
    print("=" * 78)

    results = []
    for t in targets:
        label = "%-22s %-16s" % (t["name"], "（漏洞版）" if t["expect"] == "vulnerable"
                                 else "（修補版）")
        print("\n▶ %s %s" % (label, t["kind"]))
        r = run_target(t, verbose=args.verbose)
        results.append(r)
        if r.get("error"):
            print("   ✗ 錯誤：%s" % r["error"])
        else:
            d = r.get("detail", {})
            if t["expect"] == "vulnerable":
                print("   %s 漏洞存在 %s/%s"
                      % ("✓" if r["ok"] else "✗", d.get("found"), d.get("total")))
            else:
                print("   %s 修補驗證 %s/%s（%d 組條件）"
                      % ("✓" if r["ok"] else "✗", d.get("fixed_ok"),
                         d.get("fixed_total"), d.get("groups", 0)))

    if not args.quick:
        print("\n▶ %-22s %s" % ("fuzzer", "覆蓋率引導（200k 迭代）"))
        fr = run_fuzzer_check()
        results.append(fr)
        if fr.get("error"):
            print("   ⚠ %s" % fr["error"])
        else:
            print("   %s 找到 crash（崩潰時覆蓋率 %s）"
                  % ("✓" if fr["ok"] else "✗",
                     fr.get("detail", {}).get("coverage_at_crash", "?")))

    # ---------------- 彙總 ----------------
    checked = [r for r in results if r.get("ok") is not None]
    passed = [r for r in checked if r["ok"]]
    failed = [r for r in checked if not r["ok"]]

    print("\n" + "=" * 78)
    print(" 彙總")
    print("=" * 78)
    for r in results:
        if r.get("ok") is None:
            mark, note = "⚠", r.get("error", "略過")
        else:
            mark = "✓" if r["ok"] else "✗"
            note = ""
        print("  %s %-24s %s" % (mark, r["name"], note))
    print("-" * 78)
    print("  通過 %d / %d" % (len(passed), len(checked)))
    print("=" * 78)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "passed": len(passed),
        "checked": len(checked),
        "results": results,
    }
    out_path = os.path.join(LAB, "findings", "pipeline_report.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print("\n（報告已寫入 findings/pipeline_report.json）")

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
