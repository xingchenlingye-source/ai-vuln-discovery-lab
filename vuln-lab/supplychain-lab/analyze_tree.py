#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 analyze_tree.py — 間接依賴樹分析（A03 缺口修補）
=============================================================================

 對應研究報告 CH06 S1（OWASP A03 Software Supply Chain Failures）。

 為什麼需要這個？（補上先前的缺口）
   scan_deps.py 只掃 requirements.txt 的**直接依賴**。
   但真實世界的供應鏈風險主要來自**間接依賴（transitive dependencies）**——
   你沒直接引入的套件，被你的依賴引入，而它可能才是那個有漏洞的。

 典型例子：
   Log4Shell（CVE-2021-44228）影響的是 log4j-core，但很多專案從未
   直接引入它——是透過 spring-boot-starter-logging 進來的。

 本工具做法：
   1. 用 `pip download --no-deps` 取得每個套件的 metadata（不實際安裝）
   2. 解析 Requires-Dist 遞迴展開整棵依賴樹
   3. 對**所有節點**（不只直接依賴）查詢 OSV API

 用法：
   python analyze_tree.py requirements-vulnerable.txt
   python analyze_tree.py requirements-vulnerable.txt --no-vuln   # 只看樹
=============================================================================
"""

import argparse
import email
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import deque

OSV_API = "https://api.osv.dev/v1/query"
TIMEOUT = 25


def parse_requirements(path):
    deps = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
            if m:
                deps.append((m.group(1), m.group(2)))
    return deps


def download_metadata(name, version, workdir):
    """用 pip download 取得 wheel/sdist，回傳檔案路徑（或 None）。"""
    cmd = [sys.executable, "-m", "pip", "download", "--no-deps", "--no-binary", ":all:",
           "--no-build-isolation", "-d", workdir,
           "%s==%s" % (name, version)]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=180,
                           cwd=workdir, text=True)
        if p.returncode != 0:
            # sdist 可能因 setup.py 失敗，改抓 wheel
            cmd2 = [sys.executable, "-m", "pip", "download", "--no-deps",
                    "--only-binary", ":all:", "-d", workdir,
                    "%s==%s" % (name, version)]
            p = subprocess.run(cmd2, capture_output=True, timeout=180,
                               cwd=workdir, text=True)
            if p.returncode != 0:
                return None, p.stderr.strip().splitlines()[-1] if p.stderr else "unknown"
    except subprocess.TimeoutExpired:
        return None, "timeout"

    files = [f for f in os.listdir(workdir)
             if f.lower().startswith(name.lower().replace("-", "_"))
             or f.lower().startswith(name.lower())]
    if not files:
        files = [f for f in os.listdir(workdir)]
    return (os.path.join(workdir, files[0]) if files else None), ""


def extract_requires(archive_path):
    """從 wheel 或 sdist 取出 Requires-Dist 清單。"""
    if not archive_path or not os.path.exists(archive_path):
        return []
    try:
        if archive_path.endswith(".whl") or archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as z:
                meta_name = next((n for n in z.namelist()
                                  if n.endswith("METADATA") or n.endswith("PKG-INFO")), None)
                if not meta_name:
                    return []
                raw = z.read(meta_name).decode("utf-8", errors="replace")
        else:
            # sdist：tar.gz 內含 PKG-INFO
            import tarfile
            with tarfile.open(archive_path) as t:
                member = next((m for m in t.getmembers()
                               if m.name.endswith("PKG-INFO")), None)
                if not member:
                    return []
                raw = t.extractfile(member).read().decode("utf-8", errors="replace")
    except Exception:                                        # noqa: BLE001
        return []

    msg = email.message_from_string(raw)
    requires = msg.get_all("Requires-Dist") or []
    out = []
    for r in requires:
        # 只取名稱；略過環境標記中明顯不適用者（簡化處理）
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)", r)
        if not m:
            continue
        # 略過 extras-only 條件（例如 `; extra == "dev"`）
        if "extra ==" in r:
            continue
        out.append(m.group(1))
    return out


def query_osv(name, version):
    payload = {"version": version, "package": {"name": name, "ecosystem": "PyPI"}}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(OSV_API, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode()).get("vulns", [])
    except Exception:                                        # noqa: BLE001
        return None


def main():
    ap = argparse.ArgumentParser(description="間接依賴樹分析")
    ap.add_argument("requirements")
    ap.add_argument("--no-vuln", action="store_true", help="只展開樹，不查漏洞")
    ap.add_argument("--max-nodes", type=int, default=60)
    args = ap.parse_args()

    direct = parse_requirements(args.requirements)
    print("=" * 78)
    print(" 間接依賴樹分析")
    print("=" * 78)
    print(" 檔案      : %s" % args.requirements)
    print(" 直接依賴  : %d 個：%s" % (len(direct),
                                     ", ".join("%s==%s" % d for d in direct)))
    print("=" * 78)
    print("\n 正在展開依賴樹（pip download 取得 metadata，不實際安裝）...\n")

    workroot = tempfile.mkdtemp(prefix="deptree_")
    # BFS 展開
    nodes = {}                      # (name_lower) -> {"name","version","deps","depth","parents"}
    queue = deque()
    for name, ver in direct:
        queue.append((name, ver, 0, "（直接）"))

    visited = set()
    while queue and len(visited) < args.max_nodes:
        name, ver, depth, parent = queue.popleft()
        key = name.lower()
        if key in visited:
            # 已展開過：只補記錄 parent（用於呈現路徑）
            nodes[key]["parents"].add(parent)
            continue
        visited.add(key)

        wd = os.path.join(workroot, key)
        os.makedirs(wd, exist_ok=True)
        path, err = download_metadata(name, ver, wd)
        deps = extract_requires(path) if path else []

        nodes[key] = {"name": name, "version": ver, "deps": deps,
                      "depth": depth, "parents": {parent}, "error": err}

        indent = "  " * (depth + 1)
        print("%s%-24s %-12s %s" % (indent, name, ver,
                                    "（%d 個間接依賴）" % len(deps) if deps else "（無依賴）"))
        if err and not deps:
            print("%s  ⚠ metadata 取得失敗：%s" % (indent, err))

        for d in deps:
            queue.append((d, "", depth + 1, name))

    # 統計
    direct_keys = {n.lower() for n, _ in direct}
    transitive = [v for k, v in nodes.items() if k not in direct_keys]

    print("\n" + "=" * 78)
    print(" 依賴樹統計")
    print("=" * 78)
    print("  展開節點總數    : %d" % len(nodes))
    print("  直接依賴        : %d" % len(direct_keys))
    print("  間接依賴        : %d" % len(transitive))
    if direct_keys:
        print("  爆炸倍數        : %.1f 倍" % (len(nodes) / len(direct_keys)))
    print("-" * 78)
    if transitive:
        print("  間接依賴清單（這些是你『沒有直接引入』的套件）：")
        for v in sorted(transitive, key=lambda x: x["name"].lower()):
            print("    · %-24s (由 %s 引入，深度 %d)"
                  % (v["name"], ", ".join(sorted(v["parents"])), v["depth"]))
    else:
        print("  （無間接依賴，或 metadata 取得失敗）")

    # 漏洞查詢（對所有節點）
    result = {"file": args.requirements, "nodes": {}, "transitive": []}
    for k, v in nodes.items():
        result["nodes"][k] = {"name": v["name"], "version": v["version"],
                              "depth": v["depth"], "deps": v["deps"],
                              "parents": sorted(v["parents"])}
    result["transitive"] = sorted(v["name"] for v in transitive)

    if not args.no_vuln:
        print("\n" + "=" * 78)
        print(" 對所有節點查詢 OSV（含間接依賴）")
        print("=" * 78)
        total = 0
        vuln_nodes = []
        for k, v in sorted(nodes.items()):
            if not v["version"]:
                continue                 # 間接依賴版本未知，跳過（誠實記錄）
            vulns = query_osv(v["name"], v["version"])
            if vulns is None:
                print("  %-24s %-12s 查詢失敗" % (v["name"], v["version"]))
                continue
            if vulns:
                total += len(vulns)
                vuln_nodes.append(v["name"])
                kind = "直接" if k in direct_keys else "★間接"
                print("  %-8s %-22s %-12s %d 個漏洞"
                      % (kind, v["name"], v["version"], len(vulns)))
        print("-" * 78)
        print("  有漏洞的節點 : %d" % len(vuln_nodes))
        print("  漏洞總數     : %d" % total)
        result["vuln_nodes"] = vuln_nodes
        result["total_vulns"] = total

        # 限制說明
        unknown = [v["name"] for v in nodes.values() if not v["version"]]
        if unknown:
            print("\n  ⚠ 版本未知而無法查詢的間接依賴：%d 個" % len(unknown))
            print("     （真實工具（pip-audit/osv-scanner）會解析已安裝環境的實際版本；")
            print("      本工具以 pip download 取 metadata，故部分間接依賴版本未定）")

    print("\n" + "=" * 78)
    print(" 為什麼這比只掃 requirements.txt 重要？")
    print("=" * 78)
    print("""
  你的 requirements.txt 只有 %d 行，但實際依賴樹有 %d 個節點。
  攻擊者只需要**其中一個**間接依賴有漏洞即可。

  Log4Shell（CVE-2021-44228）就是典型案例：
  許多專案從未直接引入 log4j-core，而是透過 spring-boot-starter-logging 進來。

  → 這正是為什麼 OWASP A03 把「SBOM（含完整依賴樹）」列為核心措施：
    你必須先知道「自己用了什麼」，才能回答「這次風暴我受不受影響」。
""" % (len(direct), len(nodes)))

    with open("dependency_tree.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("（JSON 摘要已寫入 dependency_tree.json）")

    shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    main()
