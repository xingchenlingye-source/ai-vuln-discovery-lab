#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 fuzzer.py — 覆蓋率引導 vs 盲目 mutation 對照實驗（Python 啟動器）
=============================================================================

 對應研究報告：
   - CH06 S2（工具鏈：fuzzer 的原理與實作）
   - CH03（Big Sleep 的 150 CPU-hours 對照實驗）

 架構（為什麼是「Python + C」兩層）：
   ┌────────────────┐         ┌──────────────────────────────┐
   │ fuzzer.py      │ 啟動    │ fuzz_main.exe (C, in-process) │
   │ (本檔，啟動器) │ ──────▶ │  · 14 萬+ exec/s              │
   │                │         │  · trace-pc-guard 覆蓋率回饋   │
   │  統計 / 重啟    │ ◀────── │  · ASan + death callback      │
   └────────────────┘  RESULT └──────────────────────────────┘
                        / crash.bin

 為什麼熱路徑要用 C？實測差距：
   Python + subprocess（每輪啟動新行程）：    約 30 exec/s
   C in-process（同一行程反覆呼叫目標）：  約 140,000 exec/s
   → 這就是 libFuzzer / AFL persistent mode 存在的理由。

 崩潰處理：
   ASan 攔到錯誤會結束進程。C 端已註冊 __sanitizer_set_death_callback，
   在死亡回呼中寫出導致崩潰的輸入（crash.bin）。本啟動器偵測非零退出碼後：
     1. 保存 crash.bin 與 ASan 報告
     2. 重新啟動 fuzzer 繼續跑（AFL fork-server 的簡化版）

 用法：
   python fuzzer.py --compare --iters 2000000 --chunk 500000
   python fuzzer.py --mode guided --iters 500000 --chunk 5000
   python fuzzer.py --mode guided --no-build
=============================================================================
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
WORK = os.path.join(HERE, "work")
FINDINGS = os.path.join(LAB, "findings")

EXE = os.path.join(WORK, "fuzz_main.exe")
ASAN_DLLS = [
    "libclang_rt.asan_dynamic-x86_64.dll",
    "libc++.dll",
    "libunwind.dll",
    "libwinpthread-1.dll",
]

# 已知答案（僅用於驗證 fuzzer 是否真的找到漏洞，不餵給 fuzzer）
#   checksum = XOR of data[0..5] = 0x46^0x5A^0x5A^0x01^0x0A^0x00 = 0x4D
KNOWN_TRIGGER = bytes([
    0x46, 0x5A, 0x5A, 0x01, 0x0A, 0x00,
    0xC0, 0x01, 0x4D,
    0x58, 0x58, 0x58, 0x58,
])


def find_clang():
    """動態尋找 MinGW clang（winget 安裝路徑含 hash）。"""
    base = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Packages")
    if not os.path.isdir(base):
        return None
    for d in sorted(os.listdir(base)):
        if d.startswith("MartinStorsjo.LLVM-MinGW"):
            root = os.path.join(base, d)
            for sub in sorted(os.listdir(root)):
                clang = os.path.join(root, sub, "bin", "clang.exe")
                if os.path.exists(clang):
                    return clang
    return None


def build():
    """編譯 in-process fuzzer。

    注意兩個環境坑（詳見 S2_c_memory_lab.md）：
      1. 中文路徑會讓 ld.lld 無法寫入輸出檔 → 輸出到 ASCII 路徑
      2. ASan runtime DLL 必須與 exe 同目錄（且它自己依賴 libc++.dll）
    """
    clang = find_clang()
    if not clang:
        print("[錯誤] 找不到 MinGW clang。請先安裝：")
        print("  winget install --id MartinStorsjo.LLVM-MinGW.UCRT --silent")
        return False

    os.makedirs(WORK, exist_ok=True)
    mingw_bin = os.path.dirname(clang)
    os.environ["PATH"] = mingw_bin + os.pathsep + os.environ.get("PATH", "")

    srcs = [os.path.join(HERE, "fuzz_main.c"), os.path.join(HERE, "fuzz_target.c")]
    cmd = [
        clang,
        "-fsanitize=address",
        "-fsanitize-coverage=trace-pc-guard",
        "-g", "-O1",
        "-o", EXE,
    ] + srcs

    print("=== 編譯 in-process fuzzer ===")
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        print("[失敗] 編譯錯誤：")
        print((p.stdout + p.stderr).decode("utf-8", errors="replace")[:2000])
        return False
    print("[成功] %s (%d bytes)" % (EXE, os.path.getsize(EXE)))

    # ASan runtime DLL（少了會得到 exit -1073741515 且無任何訊息）
    for dll in ASAN_DLLS:
        src = os.path.join(mingw_bin, dll)
        if os.path.exists(src):
            shutil.copy2(src, WORK)
    return True


def run_once(mode, iters, seed):
    """跑一輪 fuzzer。回傳 (exit_code, stdout, elapsed, crash_bytes)。"""
    crash_path = os.path.join(WORK, "crash.bin")
    last_path = os.path.join(WORK, "last_input.bin")
    for p in (crash_path, last_path):
        if os.path.exists(p):
            os.remove(p)

    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"

    t0 = time.time()
    try:
        p = subprocess.run(
            [EXE, mode, str(iters), hex(seed)],
            cwd=WORK, capture_output=True, timeout=600, env=env,
        )
        code = p.returncode
        out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        code, out = -1, "TIMEOUT"
    elapsed = time.time() - t0

    crash = None
    if os.path.exists(crash_path):
        with open(crash_path, "rb") as f:
            crash = f.read()
    return code, out, elapsed, crash


def parse_result(out):
    """解析 C 端輸出的 RESULT 行。"""
    for line in out.splitlines():
        if line.startswith("RESULT"):
            d = {}
            for kv in line.split()[1:]:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    d[k] = v
            return d
    return {}


def summarize_crash(out):
    for line in out.splitlines():
        if "ERROR: AddressSanitizer" in line:
            return line.strip()
    for line in out.splitlines():
        if "runtime error" in line:
            return line.strip()
    return "(無 sanitizer 報告)"


def experiment(mode, total_iters, chunk, seed):
    """反覆執行直到找到 crash 或跑完總量。"""
    print("=" * 80)
    label = "覆蓋率引導（guided）" if mode == "guided" else "盲目 mutation（blind）"
    print(" 模式：%s" % label)
    print(" 計畫總迭代：%d（每輪 %d）" % (total_iters, chunk))
    print("=" * 80)

    done = 0
    rounds = 0
    first_crash_iters = None
    first_crash_round = None
    crash_input = None
    crash_report = None
    total_elapsed = 0.0
    last_stats = {}

    while done < total_iters:
        this = min(chunk, total_iters - done)
        code, out, elapsed, crash = run_once(mode, this, seed + rounds)
        rounds += 1
        total_elapsed += elapsed
        done += this
        stats = parse_result(out)
        if stats:
            last_stats = stats

        if crash is not None:
            first_crash_iters = done
            first_crash_round = rounds
            crash_input = crash
            crash_report = summarize_crash(out)
            print("  ★ [第 %d 輪] 在第 %d 次迭代找到 crash（累計 %.2fs）" % (
                rounds, done, total_elapsed))
            print("     輸入（%d bytes）: %s" % (len(crash), crash.hex()))
            print("     %s" % crash_report[:100])
            break
        else:
            print("  [第 %d 輪] %d 次迭代，無 crash（累計 %.2fs）" % (
                rounds, done, total_elapsed))

    eps = done / total_elapsed if total_elapsed > 0 else 0
    result = {
        "mode": mode,
        "iters": done,
        "elapsed": total_elapsed,
        "exec_per_sec": eps,
        "coverage": int(last_stats.get("coverage", 0)),
        "guards": int(last_stats.get("guards", 0)),
        "corpus": int(last_stats.get("corpus", 0)),
        "first_crash_iters": first_crash_iters,
        "first_crash_round": first_crash_round,
        "crash_input": crash_input,
        "crash_report": crash_report,
    }

    print("\n" + "-" * 80)
    print(" 結果（%s）" % mode)
    print("-" * 80)
    print("  總迭代      : %d" % done)
    print("  總耗時      : %.2f 秒（%.0f exec/s）" % (total_elapsed, eps))
    print("  覆蓋率      : %d / %d guards" % (result["coverage"], result["guards"]))
    print("  corpus 大小 : %d" % result["corpus"])
    if first_crash_iters:
        print("  首次 crash  : 第 %d 次迭代（%.2f 秒）" % (first_crash_iters, total_elapsed))
    else:
        print("  首次 crash  : 未發現（已跑滿 %d 次）" % done)
    print("-" * 80)
    return result


def save_crash_files(results):
    os.makedirs(FINDINGS, exist_ok=True)
    for r in results:
        if not r["crash_input"]:
            continue
        src = os.path.join(WORK, "crash.bin")
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(FINDINGS, "fuzz_crash_%s.bin" % r["mode"]))
        rep = os.path.join(FINDINGS, "fuzz_crash_%s_report.txt" % r["mode"])
        with open(rep, "w", encoding="utf-8") as f:
            f.write("fuzz_main 崩潰報告\n")
            f.write("模式          : %s\n" % r["mode"])
            f.write("觸發輸入 hex  : %s\n" % r["crash_input"].hex())
            f.write("觸發輸入長度  : %d bytes\n" % len(r["crash_input"]))
            f.write("首次 crash 於 : 第 %d 次迭代\n" % r["first_crash_iters"])
            f.write("執行速度      : %.0f exec/s\n" % r["exec_per_sec"])
            f.write("=" * 74 + "\n")
            f.write("%s\n" % r["crash_report"])
        print("  → 報告: findings/fuzz_crash_%s_report.txt" % r["mode"])


def main():
    ap = argparse.ArgumentParser(description="覆蓋率引導 vs 盲目 mutation 對照實驗")
    ap.add_argument("--mode", choices=["guided", "blind"], default="guided")
    ap.add_argument("--iters", type=int, default=2_000_000)
    ap.add_argument("--chunk", type=int, default=500_000,
                    help="每輪迭代數（用來展示「第幾輪找到」）")
    ap.add_argument("--compare", action="store_true")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0x5EED)
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    if not args.no_build:
        if not build():
            sys.exit(1)
    elif not os.path.exists(EXE):
        print("[錯誤] 找不到 %s，請先執行 build（移除 --no-build）" % EXE)
        sys.exit(1)

    print("\n目標觸發條件（僅供驗證，未餵給 fuzzer）:")
    print("  hex = %s" % KNOWN_TRIGGER.hex())
    print("  需要同時滿足：魔數 FZZ、版本 0x01、型別 0x0A、保留 0x00、")
    print("  declared > 0x8000、checksum、declared ∈ [0xC000, 0xC0FF]")
    print("  → 共 11 層語意條件，其中 declared 是 256 個值的窄窗\n")

    if args.compare:
        res_g = experiment("guided", args.iters, args.chunk, args.seed)
        print()
        res_b = experiment("blind", args.iters, args.chunk, args.seed)
        results = [res_g, res_b]

        print("\n" + "=" * 80)
        print(" 對照實驗結果")
        print("=" * 80)
        print("%-12s %12s %12s %12s %14s" % (
            "模式", "總迭代", "exec/s", "覆蓋guards", "首次crash迭代"))
        print("-" * 80)
        for r in results:
            fc = str(r["first_crash_iters"]) if r["first_crash_iters"] else "未發現"
            print("%-12s %12d %12.0f %12d %14s" % (
                r["mode"], r["iters"], r["exec_per_sec"], r["coverage"], fc))
        print("=" * 80)

        print("\n【結論】")
        if res_g["first_crash_iters"] and not res_b["first_crash_iters"]:
            print("  覆蓋率引導在第 %d 次迭代找到 crash；" % res_g["first_crash_iters"])
            print("  盲目模式在 %d 次迭代內（%.1f 倍工作量）完全找不到。" % (
                res_b["iters"], res_b["iters"] / res_g["first_crash_iters"]))
            print()
            print("  為什麼差距這麼大？")
            print("    · guided 保留「部分正確」的輸入（例如已通過魔數但不合 checksum），")
            print("      下一輪 mutation 從它繼續推進 → 逐層累積。")
            print("    · blind 不保留任何中間成果，每輪都從原始淺 seed 重來，")
            print("      命中 11 層條件的聯合機率極低。")
        elif res_g["first_crash_iters"] and res_b["first_crash_iters"]:
            ratio = res_b["first_crash_iters"] / res_g["first_crash_iters"]
            print("  guided 第 %d 次找到；blind 第 %d 次找到。" % (
                res_g["first_crash_iters"], res_b["first_crash_iters"]))
            print("  → guided 效率為 blind 的 %.1f 倍" % ratio)
        else:
            print("  兩種模式都未在 %d 次迭代內找到。" % args.iters)

        print()
        print("  對照 CH03：這正是 Big Sleep 團隊所做對照實驗的縮小版——")
        print("  他們跑 150 CPU-hours 的 AFL 仍未發現 SQLite 的漏洞，")
        print("  說明當觸發條件是「特定語意組合」而非單純路徑覆蓋時，")
        print("  覆蓋率引導也有其極限。本實驗中 guided 能找到，部分歸功於")
        print("  mutation 策略包含 checksum-aware 與 declared 欄位導向；")
        print("  若移除這些「格式感知」策略，兩者都會失敗——")
        print("  這正是 LLM 能補上的位置（理解格式語意後直接產生合法輸入）。")

        save_crash_files(results)
    else:
        r = experiment(args.mode, args.iters, args.chunk, args.seed)
        save_crash_files([r])


if __name__ == "__main__":
    main()
