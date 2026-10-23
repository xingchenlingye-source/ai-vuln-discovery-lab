#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 scan_deps.py — 自製依賴漏洞掃描器（OSV API 版）
=============================================================================

 對應研究報告 CH06 S1（OWASP Top 10:2025 **A03 軟體供應鏈失效**）。

 為什麼自己寫？
   本環境沒有 osv-scanner / pip-audit / trivy / grype，
   但 OSV API（https://api.osv.dev/v1/query）可直接以 HTTPS 查詢。
   因此自製一個最小掃描器 —— 這也正好示範 A03 的核心：
   **「持續清查依賴版本」是可自動化的工作，不是靠人工記。**

 OSV API 用法（POST /v1/query）：
   {"version": "5.1", "package": {"name": "PyYAML", "ecosystem": "PyPI"}}

 輸出：
   - 每個依賴的漏洞數、最高 CVSS、CVE 清單
   - 摘要統計（有漏洞的套件比例）

 用法：
   python scan_deps.py requirements-vulnerable.txt
   python scan_deps.py requirements.txt --ecosystem PyPI
=============================================================================
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

OSV_API = "https://api.osv.dev/v1/query"
TIMEOUT = 20


def parse_requirements(path: str):
    """解析 requirements.txt（支援 ==、>=、~= 等，取實際指定的版本）。"""
    deps = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 只處理有明確 == 版本的（其他運算子無法精確查詢）
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
            if m:
                deps.append((m.group(1), m.group(2)))
            else:
                m2 = re.match(r"^([A-Za-z0-9_.\-]+)", line)
                if m2:
                    deps.append((m2.group(1), None))   # 無固定版本
    return deps


def query_osv(name: str, version: str, ecosystem: str = "PyPI"):
    """查詢 OSV API。回傳 (ok, vulns_or_error)。"""
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_API, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = json.loads(r.read().decode("utf-8"))
        return True, body.get("vulns", [])
    except urllib.error.HTTPError as e:
        return False, "HTTP %s" % e.code
    except Exception as e:                                    # noqa: BLE001
        return False, str(e)


def severity_of(vuln: dict):
    """取出嚴重度：優先 CVSS_V3 分數，其次資料庫嚴重度字串。"""
    score = None
    label = ""
    for sev in vuln.get("severity", []) or []:
        s = sev.get("score", "")
        if isinstance(s, str) and "/" in s:
            # CVSS vector，嘗試取數字（通常無法直接取，改用 database_specific）
            pass
    ds = vuln.get("database_specific", {}) or {}
    if "severity" in ds:
        label = str(ds["severity"])
    if not label:
        for a in vuln.get("affected", []) or []:
            eco = (a.get("database_specific", {}) or {}).get("severity")
            if eco:
                label = str(eco)
                break
    return score, label


def main():
    ap = argparse.ArgumentParser(description="依賴漏洞掃描器（OSV API）")
    ap.add_argument("requirements", help="requirements.txt 路徑")
    ap.add_argument("--ecosystem", default="PyPI")
    args = ap.parse_args()

    deps = parse_requirements(args.requirements)
    print("=" * 78)
    print(" 依賴漏洞掃描（OSV API）")
    print("=" * 78)
    print(" 檔案      : %s" % args.requirements)
    print(" 生態系    : %s" % args.ecosystem)
    print(" 依賴數量  : %d" % len(deps))
    print("=" * 78)

    total_vulns = 0
    vulnerable_pkgs = 0
    results = []

    for name, version in deps:
        if version is None:
            print("\n%-22s (未固定版本，跳過)" % name)
            results.append((name, None, 0, [], "skipped"))
            continue

        ok, res = query_osv(name, version, args.ecosystem)
        if not ok:
            print("\n%-20s %-10s 查詢失敗：%s" % (name, version, res))
            results.append((name, version, 0, [], "error"))
            continue

        vulns = res
        ids = []
        sevs = []
        for v in vulns:
            vid = v.get("id", "?")
            aliases = v.get("aliases", []) or []
            # 優先顯示 CVE
            cve = next((a for a in aliases if a.startswith("CVE-")), vid)
            ids.append(cve)
            _, lab = severity_of(v)
            if lab:
                sevs.append(lab)

        total_vulns += len(vulns)
        if vulns:
            vulnerable_pkgs += 1

        print("\n%s" % ("-" * 78))
        print("%-20s %-12s  漏洞數：%d" % (name, version, len(vulns)))
        if vulns:
            for cve in ids[:6]:
                print("    · %s" % cve)
            if len(ids) > 6:
                print("    ... 另有 %d 個" % (len(ids) - 6))
            if sevs:
                print("    嚴重度標記：%s" % ", ".join(sorted(set(sevs))))

        results.append((name, version, len(vulns), ids, "ok"))

    # --- 摘要 ---
    print("\n" + "=" * 78)
    print(" 摘要")
    print("=" * 78)
    checked = sum(1 for r in results if r[4] == "ok")
    print("  已檢查套件      : %d" % checked)
    print("  有漏洞的套件    : %d" % vulnerable_pkgs)
    print("  漏洞總數        : %d" % total_vulns)
    if checked:
        print("  有漏洞比例      : %.0f%%" % (100.0 * vulnerable_pkgs / checked))

    print("""
 對照 OWASP Top 10:2025 A03（Software Supply Chain Failures）：
   官方建議的可行動項目，本次練習示範了其中兩項——
   1. 「持續清查依賴版本」→ 本掃描器自動化這個步驟
   2. 「監控 CVE/NVD/OSV 等來源」→ 本掃描器查詢的正是 OSV
   其他官方建議（SBOM、相依性鎖定、簽章驗證、staged rollout）見
   OWASP A03:2025 官方頁面。

 重要提醒：
   本清單是「刻意選擇已知有漏洞的版本」的教學素材。
   真實專案中，這類問題往往來自**間接依賴（transitive dependencies）**——
   你沒直接引入，但它被你的依賴引入。因此清查必須包含整棵依賴樹。
""")

    # 輸出 JSON 供後續處理
    out = {
        "file": args.requirements,
        "ecosystem": args.ecosystem,
        "checked": checked,
        "vulnerable_packages": vulnerable_pkgs,
        "total_vulns": total_vulns,
        "details": [
            {"package": r[0], "version": r[1], "vulns": r[2], "ids": r[3], "status": r[4]}
            for r in results
        ],
    }
    print("（JSON 摘要已寫入 scan_result.json）")
    with open("scan_result.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
