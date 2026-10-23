#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 benchmark.py — v1 vs v2 fuzzer 命中率對照
=============================================================================

 對應研究報告 CH06 S2（工具鏈優化）與 CH03。

 v2 的四項改進：
   1. Edge coverage（prev→cur 轉移，而非只有 block）
   2. Hit count 分桶（捕捉迴圈深度變化）
   3. 字典輔助（把關鍵位元組集中，縮小搜尋空間）
   4. 多策略 mutation（含 checksum-aware 與 declared 導向）

 量測方式（公平比較）：
   同一組 seed、同樣的迭代上限，分別跑 v1 與 v2 的 guided 模式，
   記錄「首次 crash 的迭代數」。跑多組 seed 取統計量，
   因為單次結果的變異極大（實測範圍可達 2,739 ～ 182,000）。

 用法：
   python benchmark.py --iters 200000 --seeds 8
   python benchmark.py --compare-v1 --iters 200000 --seeds 8
=============================================================================
"""

import argparse
import os
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
V1_DIR = os.path.join(LAB, "fuzz")
V2_DIR = HERE
FINDINGS = os.path.join(LAB, "findings")

ASAN_DLLS = [
    "libclang_rt.asan_dynamic-x86_64.dll",
    "libc++.dll",
    "libunwind.dll",
    "libwinpthread-1.dll",
]


def find_clang():
    base = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Packages")
    if not os.path.isdir(base):
        return None
    for d in sorted(os.listdir(base)):
        if d.startswith("MartinStorsjo.LLVM-MinGW"):
            root = os.path.join(base, d)
            for sub in sorted(os.listdir(root)):
                c = os.path.join(root, sub, "bin", "clang.exe")
                if os.path.exists(c):
                    return c
    return None


def build(src_dir, out_exe):
    clang = find_clang()
    if not clang:
        print("[錯誤] 找不到 MinGW clang")
        return False
    mingw_bin = os.path.dirname(clang)
    os.environ["PATH"] = mingw_bin + os.pathsep + os.environ.get("PATH", "")

    work = os.path.dirname(out_exe)
    os.makedirs(work, exist_ok=True)
    cmd = [
        clang,
        "-fsanitize=address",
        "-fsanitize-coverage=trace-pc-guard",
        "-g", "-O1",
        "-o", out_exe,
        os.path.join(src_dir, "fuzz_main.c"),
        os.path.join(src_dir, "fuzz_target.c"),
    ]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        print("[失敗] 編譯 %s：" % src_dir)
        print((p.stdout + p.stderr).decode("utf-8", errors="replace")[:1500])
        return False
    for dll in ASAN_DLLS:
        s = os.path.join(mingw_bin, dll)
        if os.path.exists(s):
            shutil.copy2(s, work)
    return True


def run_one(exe, work, mode, iters, seed):
    """跑一次。回傳 (crashed, iters_used, coverage_info, elapsed)。"""
    for f in ("crash.bin", "last_input.bin", "coverage_at_crash.txt"):
        p = os.path.join(work, f)
        if os.path.exists(p):
            os.remove(p)

    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"

    t0 = time.time()
    try:
        p = subprocess.run([exe, mode, str(iters), hex(seed)],
                           cwd=work, capture_output=True, timeout=600, env=env)
        out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
        code = p.returncode
    except subprocess.TimeoutExpired:
        out, code = "TIMEOUT", -1
    elapsed = time.time() - t0

    info = {}
    # 崩潰時：讀 coverage_at_crash.txt
    cpath = os.path.join(work, "coverage_at_crash.txt")
    if os.path.exists(cpath):
        with open(cpath, encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v
        return True, int(info.get("execs_at_crash", 0)), info, elapsed

    # 未崩潰：讀 RESULT 行
    for line in out.splitlines():
        if line.startswith("RESULT"):
            for kv in line.split()[1:]:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    info[k] = v
            break
    return False, iters, info, elapsed


def bench(name, exe, work, iters, seeds):
    print("=" * 82)
    print(" %s" % name)
    print("=" * 82)
    results = []
    for i, sd in enumerate(seeds):
        crashed, used, info, el = run_one(exe, work, "guided", iters, sd)
        results.append((sd, crashed, used, info, el))
        if crashed:
            print("  seed %-8s ★ 第 %7d 次迭代崩潰（%.2fs）  blocks=%s buckets=%s edges=%s"
                  % (hex(sd), used, el, info.get("coverage_at_crash", "?"),
                     info.get("bucketed_at_crash", "?"), info.get("edges_at_crash", "?")))
        else:
            print("  seed %-8s ✗ 未發現（跑滿 %d 次，%.1fs）  coverage=%s guards=%s"
                  % (hex(sd), iters, el, info.get("coverage", "?"),
                     info.get("guards", "?")))
    hits = [r for r in results if r[1]]
    used = [r[2] for r in hits]
    print("-" * 82)
    print("  命中率      : %d/%d (%.0f%%)" % (len(hits), len(results),
                                              100.0 * len(hits) / len(results)))
    if used:
        print("  命中中位迭代: %d" % statistics.median(used))
        print("  命中範圍    : %d ～ %d" % (min(used), max(used)))
    print("=" * 82)
    return results


def seeds_from(count):
    """產生分散的 seed（避免只用相近的起始值）。"""
    out = []
    x = 0x12345678
    for _ in range(count):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(x)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=200_000)
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--compare-v1", action="store_true")
    args = ap.parse_args()

    v2_exe = os.path.join(V2_DIR, "work", "fuzz_main.exe")
    v2work = os.path.join(V2_DIR, "work")

    print("=== 編譯 v2 ===")
    if not build(V2_DIR, v2_exe):
        sys.exit(1)
    print("[成功] v2: %s (%d bytes)" % (v2_exe, os.path.getsize(v2_exe)))

    seeds = seeds_from(args.seeds)
    print("\n使用 %d 組 seed，每組迭代上限 %d\n" % (len(seeds), args.iters))

    res2 = bench("v2：edge coverage + hit bucket + 字典", v2_exe, v2work,
                 args.iters, seeds)

    res1 = None
    if args.compare_v1:
        v1_exe = os.path.join(V1_DIR, "work", "fuzz_main.exe")
        v1work = os.path.join(V1_DIR, "work")
        if not os.path.exists(v1_exe):
            print("[跳過] 找不到 v1 執行檔；請先跑 fuzz/fuzzer.py 建置")
        else:
            res1 = bench("v1：block coverage + 0/1 判斷", v1_exe, v1work,
                         args.iters, seeds)

    # --- 總結 ---
    if res1 and res2:
        print("\n" + "=" * 82)
        print(" 對照總結（命中率提升）")
        print("=" * 82)
        h1 = sum(1 for r in res1 if r[1])
        h2 = sum(1 for r in res2 if r[1])
        u1 = [r[2] for r in res1 if r[1]]
        u2 = [r[2] for r in res2 if r[1]]
        print("%-46s %10s %12s" % ("版本", "命中率", "中位迭代"))
        print("-" * 82)
        print("%-46s %8.0f%% %12s" % (
            "v1  block coverage + 0/1",
            100.0 * h1 / len(res1),
            int(statistics.median(u1)) if u1 else "—"))
        print("%-46s %8.0f%% %12s" % (
            "v2  edge + bucket + dict",
            100.0 * h2 / len(res2),
            int(statistics.median(u2)) if u2 else "—"))
        print("=" * 82)
        if u1 and u2 and statistics.median(u2) > 0:
            print(" 中位迭代改善：%.1f 倍" % (statistics.median(u1) / statistics.median(u2)))
        elif u2 and not u1:
            print(" v1 完全未命中，v2 命中率 %.0f%%" % (100.0 * h2 / len(res2)))

    # 保存結果
    os.makedirs(FINDINGS, exist_ok=True)
    rep = os.path.join(FINDINGS, "fuzzer_improvement.txt")
    with open(rep, "w", encoding="utf-8") as f:
        f.write("Fuzzer 命中率改進實驗\n")
        f.write("迭代上限: %d, seed 數: %d\n" % (args.iters, len(seeds)))
        f.write("=" * 74 + "\n")
        for tag, res in (("v1", res1), ("v2", res2)):
            if res is None:
                continue
            hits = [r for r in res if r[1]]
            f.write("%s: 命中 %d/%d\n" % (tag, len(hits), len(res)))
            for sd, crashed, used, info, el in res:
                f.write("  seed %s: %s, iters=%d, blocks=%s, buckets=%s, edges=%s\n"
                        % (hex(sd), "CRASH" if crashed else "none", used,
                           info.get("coverage_at_crash", info.get("coverage", "?")),
                           info.get("bucketed_at_crash", info.get("buckets", "?")),
                           info.get("edges_at_crash", info.get("edges", "?"))))
    print("\n  → 報告: findings/fuzzer_improvement.txt")


if __name__ == "__main__":
    main()
