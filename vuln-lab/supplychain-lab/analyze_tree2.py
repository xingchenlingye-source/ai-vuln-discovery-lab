#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 analyze_tree2.py — 依賴樹分析（PyPI JSON API 版，精確解析版本）
=============================================================================

 對應研究報告 CH06 S1（OWASP A03）。

 為什麼要重寫？（修補 analyze_tree.py 的已知限制）
   analyze_tree.py 用 `pip download` 取 metadata，有兩個問題：
     1. 舊版本若已從 PyPI 下架 / 無對應 wheel → 取得失敗
     2. **間接依賴的版本未定** → 無法查詢 OSV → 漏洞偵測有缺口

 本版改用 **PyPI JSON API**（https://pypi.org/pypi/<pkg>/json）：
     · 不需下載任何檔案，速度快
     · `requires_dist` 直接給出依賴與版本約束（PEP 508）
     · 可用 `releases` 取得所有版本 → **精確解析出每個間接依賴的版本**

  版本解析策略（輕量 Resolver）：
     解析 `>=`、`>`、`<=`、`<`、`==`、`~=`、`!=` 等運算子，
     在候選版本中挑選「滿足全部約束的最大版本」。
     這是**簡化版**（不做完整的 backtracking），但足以應付教學與多數情境。

 用法：
   python analyze_tree2.py requirements-vulnerable.txt
   python analyze_tree2.py requirements-vulnerable.txt --no-vuln
   python analyze_tree2.py requirements-vulnerable.txt --ignore-bounds   # 用最新版
=============================================================================
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import deque

PYPI_API = "https://pypi.org/pypi/%s/json"
OSV_API = "https://api.osv.dev/v1/query"
TIMEOUT = 20


# ---------------------------------------------------------------------------
# 版本處理（輕量實作，不依賴 packaging 套件）
# ---------------------------------------------------------------------------
def version_key(v):
    """把版本字串轉為可比較的 tuple。"""
    parts = []
    for p in re.split(r"[.\-_+]", v):
        if p.isdigit():
            parts.append((1, int(p)))
        else:
            parts.append((0, p))
    # 補齊長度，避免比較時長度不同出錯
    return tuple(parts)


def _valid(v):
    """只保留可由 version_key 解析的版本（排除 'unknown' 等字串）。"""
    try:
        version_key(v)
        return True
    except Exception:                                        # noqa: BLE001
        return False


def cmp_version(a, b):
    """比較版本。

    ⚠ 關鍵細節（實際踩到的 bug）：
      version_key('2.2')   = ((1,2),(1,2))
      version_key('2.2.0') = ((1,2),(1,2),(1,0))   ← 長度不同，tuple 比較會說它們「不相等」
      若直接比較，`satisfies("2.2.1", [("==","2.2.0")])` 會誤判為 True
      （因為 2.2.1 與 2.2.0 在前兩段相同，而長度差異被忽略）。

      → 必須先「補零對齊」再做比較，這才是 PEP 440 的語意。
    """
    ka, kb = version_key(a), version_key(b)
    n = max(len(ka), len(kb))
    ka = ka + ((1, 0),) * (n - len(ka))
    kb = kb + ((1, 0),) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def parse_constraints(spec):
    """解析 PEP 508 的版本約束字串，例如 '>=1.0,<2.0'。"""
    out = []
    for part in spec.split(","):
        part = part.strip()
        m = re.match(r"^(==|>=|<=|>|<|~=|!=)\s*(.+)$", part)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def satisfies(ver, constraints):
    for op, want in constraints:
        c = cmp_version(ver, want)
        if op == "==" and c != 0:
            return False
        if op == "!=" and c == 0:
            return False
        if op == ">=" and c < 0:
            return False
        if op == "<=" and c > 0:
            return False
        if op == ">" and c <= 0:
            return False
        if op == "<" and c >= 0:
            return False
        if op == "~=":
            # 相容釋出：~=1.4.2 表示 >=1.4.2, ==1.4.*
            base = want.split(".")
            if len(base) < 2:
                if c < 0:
                    return False
            else:
                prefix = ".".join(base[:-1])
                if c < 0 or not ver.startswith(prefix + "."):
                    return False
    return True


def best_version(versions, constraints):
    """在候選版本中挑選滿足約束的最大版本。"""
    ok = [v for v in versions if satisfies(v, constraints)]
    if not ok:
        return None
    return sorted(ok, key=version_key)[-1]


# ---------------------------------------------------------------------------
# PyPI / OSV
# ---------------------------------------------------------------------------
def fetch_pypi(name):
    url = PYPI_API % name
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-lab-edu/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"__error__": "HTTP %s" % e.code}
    except Exception as e:                                   # noqa: BLE001
        return {"__error__": str(e)}


def pick_latest_compatible(data, constraints, name=None):
    """從 PyPI 資料挑出滿足約束的最大版本。

    實作細節（實際踩到的兩個坑）：

    坑 1：版本比較需要「正規化」。
      PyPI 的 releases 可能同時有 '2.2' 與 '2.2.0'，而語意上
      version_key('2.2') == version_key('2.2.0')（都補零到 (2,2,0)）。
      若只用 max()，會取到先出現的那個（可能是 '2.2'）。
      → 先做版本正規化：把 2.2 與 2.2.0 都映射到同一個 key，
        再從該 key 的所有別名中挑「最完整」的字串（點分段數最多）。

    坑 2：`self-dependency` 與循環依賴。
      部分套件的 requires_dist 會列出自己（或用不同大小寫），
      需明確排除，否則會產生假的循環。
    """
    releases = data.get("releases") or {}
    candidates = [v for v, files in releases.items() if files]
    if not candidates:
        return (data.get("info") or {}).get("version")

    ok = [v for v in candidates if satisfies(v, constraints)]
    if not ok:
        return None

    # 1) 建立正規化 key → 別名清單
    groups = {}
    for v in ok:
        groups.setdefault(version_key(v), []).append(v)

    # 2) 取最大的正規化 key
    best_key = max(groups)
    aliases = groups[best_key]

    # 3) 在同一 key 的別名中，挑「最完整」的字串
    #    （'2.2.0' 比 '2.2' 完整；避免回傳被截短的版本號）
    def completeness(s):
        segs = [p for p in re.split(r"[.\-_+]", s) if p != ""]
        # 點分段數優先，其次總長度
        return (len(segs), len(s))

    return max(aliases, key=completeness)


def parse_requires_dist(data, ver=None):
    """取得指定版本的 requires_dist（PEP 508）。"""
    if ver and ver in (data.get("releases") or {}):
        pass
    # 若請求的是「最新版」，info.requires_dist 即為該版依賴
    info = data.get("info") or {}
    if ver is None or ver == info.get("version"):
        return info.get("requires_dist") or []
    # 其他版本：需查 /pypi/<pkg>/<ver>/json
    return None


def query_osv(name, version):
    payload = {"version": version, "package": {"name": name, "ecosystem": "PyPI"}}
    req = urllib.request.Request(
        OSV_API, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode()).get("vulns", [])
    except Exception:                                        # noqa: BLE001
        return None


def normalize_dep(req_str):
    """把 PEP 508 依賴字串轉為 (name, constraints)。"""
    if ";" in req_str:
        marker = req_str.split(";", 1)[1]
        # 略過 extras-only 標記
        if "extra" in marker:
            return None, None
        req_str = req_str.split(";", 1)[0]
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", req_str)
    if not m:
        return None, None
    name = m.group(1)
    spec = m.group(2).strip()
    if spec.startswith("(") and spec.endswith(")"):
        spec = spec[1:-1]
    return name, parse_constraints(spec)


def main():
    ap = argparse.ArgumentParser(description="依賴樹分析（PyPI JSON API 版）")
    ap.add_argument("requirements")
    ap.add_argument("--no-vuln", action="store_true")
    ap.add_argument("--ignore-bounds", action="store_true",
                    help="忽略版本約束，一律取最新版")
    ap.add_argument("--max-nodes", type=int, default=80)
    args = ap.parse_args()

    direct = {}
    with open(args.requirements, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
            if m:
                direct[m.group(1)] = m.group(2)

    print("=" * 80)
    print(" 依賴樹分析（PyPI JSON API，精確解析版本）")
    print("=" * 80)
    print(" 檔案     : %s" % args.requirements)
    print(" 直接依賴 : %d 個" % len(direct))
    print("=" * 80)
    print("\n 展開中（PyPI JSON API，不下載檔案）...\n")

    cache = {}
    nodes = {}          # key(lower) -> dict
    queue = deque()

    for name, ver in direct.items():
        queue.append((name, [( "==", ver )], 0, "（直接）", True))

    while queue and len(nodes) < args.max_nodes:
        name, constraints, depth, parent, is_direct = queue.popleft()
        key = name.lower()

        if key in nodes:
            nodes[key]["parents"].add(parent)
            continue

        if key not in cache:
            cache[key] = fetch_pypi(name)
        data = cache[key]

        if "__error__" in data:
            nodes[key] = {"name": name, "version": None, "deps": [],
                          "depth": depth, "parents": {parent},
                          "error": data["__error__"], "direct": is_direct}
            print("%s%-24s %-12s ⚠ %s" % ("  " * (depth + 1), name,
                                           "(未知)", data["__error__"]))
            continue

        ver = pick_latest_compatible(data, constraints) if not args.ignore_bounds \
            else ((data.get("info") or {}).get("version"))

        reqs = parse_requires_dist(data, ver)
        if reqs is None:
            # 需要查特定版本端點
            vdata = fetch_pypi("%s/%s" % (name, ver)) if ver else {}
            reqs = (vdata.get("info") or {}).get("requires_dist") or []

        deps = []
        for r in reqs:
            dn, dc = normalize_dep(r)
            if not dn:
                continue
            # 排除自我依賴（部分套件的 requires_dist 會列出自己）
            if dn.lower() == key:
                continue
            deps.append((dn, dc))

        nodes[key] = {"name": name, "version": ver, "deps": [d[0] for d in deps],
                      "depth": depth, "parents": {parent}, "direct": is_direct,
                      "error": None}

        tag = "（直接）" if is_direct else "★間接"
        print("%s%-22s %-14s %-8s %s" % ("  " * (depth + 1), name, ver or "(未知)",
                                         tag,
                                         "→ %d 個依賴" % len(deps) if deps else ""))

        for dn, dc in deps:
            queue.append((dn, dc or [], depth + 1, name, False))

    direct_keys = {k for k, v in nodes.items() if v.get("direct")}
    transitive = [v for k, v in nodes.items() if k not in direct_keys]
    withver = [v for v in nodes.values() if v["version"]]

    print("\n" + "=" * 80)
    print(" 依賴樹統計")
    print("=" * 80)
    print("  展開節點      : %d" % len(nodes))
    print("  直接依賴      : %d" % len(direct_keys))
    print("  間接依賴      : %d" % len(transitive))
    print("  **版本已知**  : %d / %d" % (len(withver), len(nodes)))
    if direct_keys:
        print("  爆炸倍數      : %.1f 倍" % (len(nodes) / len(direct_keys)))
    print("-" * 80)
    if transitive:
        print("  間接依賴（你沒有直接引入的套件）：")
        for v in sorted(transitive, key=lambda x: x["name"].lower()):
            print("    · %-22s %-12s (由 %s 引入，深度 %d)"
                  % (v["name"], v["version"] or "(未知)",
                     ", ".join(sorted(v["parents"])), v["depth"]))

    result = {
        "file": args.requirements,
        "nodes": {k: {"name": v["name"], "version": v["version"],
                      "depth": v["depth"], "parents": sorted(v["parents"]),
                      "direct": v.get("direct", False), "error": v.get("error")}
                  for k, v in nodes.items()},
        "stats": {"total": len(nodes), "direct": len(direct_keys),
                  "transitive": len(transitive), "with_version": len(withver)},
    }

    if not args.no_vuln:
        print("\n" + "=" * 80)
        print(" 對所有節點查詢 OSV（版本已知者）")
        print("=" * 80)
        total = 0
        vuln_nodes = []
        unknown = [v["name"] for v in nodes.values() if not v["version"]]
        for k, v in sorted(nodes.items()):
            if not v["version"]:
                continue
            vulns = query_osv(v["name"], v["version"])
            if vulns is None:
                continue
            if vulns:
                total += len(vulns)
                vuln_nodes.append(v["name"])
                kind = "直接" if v.get("direct") else "★間接"
                print("  %-8s %-22s %-12s %d 個漏洞"
                      % (kind, v["name"], v["version"], len(vulns)))
        print("-" * 80)
        print("  有漏洞的節點 : %d" % len(vuln_nodes))
        print("  漏洞總數     : %d" % total)
        if unknown:
            print("  版本未知節點 : %d（%s）" % (len(unknown), ", ".join(unknown)))
        result["vuln_nodes"] = vuln_nodes
        result["total_vulns"] = total

    print("\n" + "=" * 80)
    print(" 與 analyze_tree.py（pip download 版）的差異")
    print("=" * 80)
    print("""
   pip download 版：舊版本下架就取不到 metadata，且間接依賴版本未定。
   PyPI JSON API 版：直接讀 releases + requires_dist，
                     **所有節點都能解析出精確版本** → 可逐一查 OSV。
   → 這補上了「間接依賴漏洞偵測」的缺口。

  ⚠ 誠實限制（本工具不是完整的依賴求解器）
     1. **不做版本回溯（no backtracking）**：真實的 pip 求解器會在多個
        套件的約束互相衝突時回溯；本工具只取「第一條路徑」的約束。
     2. **間接依賴版本可能是「理論上界」**：例如 MarkupSafe 對 Jinja2 2.10.1
        的約束是 >=0.23，因此本工具會選到最新的 MarkupSafe；
        但實際上 Jinja2 2.10.1 與最新的 MarkupSafe 並不真的可搭配。
        → 真實版本請以 `pip install` 後的實際環境為準（pip-audit 的做法）。
     3. 不同路徑若對同一套件給出不同約束，本工具採用**先遇到的那條**。
     已知的 Python 版本（3.12）與環境標記（marker）也**未完整評估**。

     → 本工具的正確用途：**快速盤點「有哪些間接依賴」**，
       而不是當作可重現的建置解析結果。
""")

    with open("dependency_tree2.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("（JSON 摘要已寫入 dependency_tree2.json）")


if __name__ == "__main__":
    main()
