/*
 * ============================================================================
 *  fuzz_target.c — 供 in-process coverage-guided fuzzer 測試的目標
 * ============================================================================
 *
 *  對應研究報告 CH06 S2（工具鏈：fuzzer 原理）與 CH03
 *  （Big Sleep 的「覆蓋率引導 vs 盲目 mutation」對照實驗）。
 *
 *  ⚠ 刻意含漏洞，僅供本機教育用途。
 *
 *  這個檔案「只」包含目標邏輯（不含 main），由 fuzz_main.c 驅動。
 *  好處：in-process fuzzing（libFuzzer 的作法），不需要每次啟動新行程，
 *        速度可從 30 exec/s 提升到數萬 exec/s。
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * 覆蓋率收集（trace-pc-guard 插樁回呼）
 * ------------------------------------------------------------------------- */
#define MAX_GUARDS 8192

static uint32_t g_guard_count = 0;
static uint8_t  g_guard_flags[MAX_GUARDS];

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    for (uint32_t *p = start; p < stop; ++p) {
        *p = g_guard_count++;
        if (g_guard_count >= MAX_GUARDS) { g_guard_count = MAX_GUARDS - 1; }
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t idx = *guard;
    if (idx < MAX_GUARDS) g_guard_flags[idx] = 1;
}

uint32_t cov_total(void) { return g_guard_count; }
void cov_reset(void) { memset(g_guard_flags, 0, sizeof(g_guard_flags)); }
int cov_hit(uint32_t i) { return i < MAX_GUARDS && g_guard_flags[i]; }

/* ---------------------------------------------------------------------------
 * 漏洞路徑：漸進式巢狀條件
 *
 *  設計目標（教學用途）：
 *    讓「盲目 mutation」幾乎不可能靠運氣命中，而「覆蓋率引導」
 *    可以一格一格推進——藉此量測兩者的差距。
 *
 *  但門檻也不能過高，否則引導式在有限時間內也找不到。
 *  這裡設計成 7 層，魔數 3 個位元組採用「容易在 corpus 中演化」的形式。
 *
 *  輸入格式：
 *    [0..2]  魔數 "FZZ"        （3 層比對）
 *    [3]     版本 0x01
 *    [4]     型別 0x0A
 *    [5]     保留 0x00
 *    [6..7]  declared（big-endian）
 *    [8]     checksum = XOR of data[0..5]
 *    [9..]   payload
 *
 *  漏洞：declared = 0xC001 時
 *        need = (declared - 0x8000) * 4 在 16-bit 下截斷成 4
 *        但 write_len = declared - 0x8000 = 0x4001 (16385)
 *        → malloc(4) 卻寫入 16385 bytes → heap-buffer-overflow
 * ------------------------------------------------------------------------- */
int check_packet(const uint8_t *data, size_t size) {
    if (size < 9) return 0;                     /* 層 1 */
    if (data[0] != 0x46) return 0;              /* 層 2 'F' */
    if (data[1] != 0x5A) return 0;              /* 層 3 'Z' */
    if (data[2] != 0x5A) return 0;              /* 層 4 'Z' */
    if (data[3] != 0x01) return 0;              /* 層 5 版本 */
    if (data[4] != 0x0A) return 0;              /* 層 6 型別 */
    if (data[5] != 0x00) return 0;              /* 層 7 保留 */

    uint16_t declared = (uint16_t)((data[6] << 8) | data[7]);
    if (declared < 0x8001) return 0;            /* 層 8 需大於 0x8000 */

    uint8_t cksum = 0;
    for (int i = 0; i < 6; i++) cksum ^= data[i];
    if (data[8] != cksum) return 0;             /* 層 9 checksum */

    /* 漏洞視窗：declared 落在 0xC000..0xC0FF（256 個值的窄窗） */
    if (declared < 0xC000) return 0;            /* 層 10 */
    if (declared > 0xC0FF) return 0;            /* 層 11 */

    unsigned short need = (unsigned short)((unsigned int)(declared - 0x8000) * 4);
    if (need == 0) need = 1;

    uint8_t *buf = (uint8_t *)malloc(need);
    if (!buf) return 0;

    size_t write_len = (size_t)(declared - 0x8000);
    for (size_t i = 0; i < write_len; i++) {
        buf[i] = data[9 + (i % (size - 9))];
    }

    int ok = (buf[0] == 0x58) ? 1 : 0;
    free(buf);
    return ok;
}
