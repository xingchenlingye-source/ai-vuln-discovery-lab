/*
 * ============================================================================
 *  fuzz_target.c — 目標 + 覆蓋率量測（v2：加入 edge coverage）
 * ============================================================================
 *
 *  對應研究報告 CH06 S2（工具鏈）與 CH03（覆蓋率引導的極限）。
 *
 *  ⚠ 刻意含漏洞，僅供本機教育用途。
 *
 *  v1 → v2 的關鍵改進：從「basic block coverage」升級為「edge coverage」
 *
 *  為什麼要改？實測發現一個警訊：
 *    guided 崩潰時的覆蓋率是 10/93，而 blind 跑久一點可達 14/93。
 *    「低覆蓋的 guided 找到漏洞、高覆蓋的 blind 找不到」——
 *    這說明 basic block coverage 作為「新穎性判準」的鑑別力不足：
 *    它只知道「這個 block 被碰過」，不知道「是從哪條路徑進來的」。
 *
 *  AFL 的解法（本版採用）：
 *    1. **Edge coverage**：記錄「轉移」(prev_guard → cur_guard)，
 *       而不是只記節點。同樣的 block 從不同前驅進入 = 不同的探索成果。
 *    2. **Hit count bucketing**：把執行次數分桶（1, 2, 3, 4-7, 8-15,
 *       16-31, 32-127, 128+）。次數變多代表進入了新的迴圈深度，
 *       這是「路徑探索」的重要信號，單純的 0/1 會遺失。
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * 覆蓋率量測
 * ------------------------------------------------------------------------- */
#define MAX_GUARDS 8192
#define EDGE_MAP   65536          /* edge bitmap 大小（AFL 是 64K） */

static uint32_t g_guard_count = 0;
static uint8_t  g_guard_flags[MAX_GUARDS];   /* v1：0/1 命中 */
static uint16_t g_guard_hits[MAX_GUARDS];    /* v2：執行次數（用於分桶） */

/* edge coverage：記錄 (prev → cur) 的轉移 */
static uint8_t  g_edge_map[EDGE_MAP];
static uint32_t g_prev_guard = 0;

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
    if (idx >= MAX_GUARDS) return;

    /* v1：basic block 命中 */
    g_guard_flags[idx] = 1;

    /* v2a：執行次數（飽和累加，避免溢位） */
    if (g_guard_hits[idx] < 0xFFFF) g_guard_hits[idx]++;

    /* v2b：edge coverage —— 記錄「上一點 → 這一點」的轉移
     *
     *  因為 guard 已被插樁在每個 basic block 開頭，連續兩次回呼的索引
     *  就代表一條邊。這正是 AFL 的 edge coverage（簡化版）。
     */
    {
        uint32_t cur = idx;
        uint32_t edge = ((g_prev_guard << 5) ^ (cur >> 3) ^ cur) & (EDGE_MAP - 1);
        g_edge_map[edge] = 1;
        g_prev_guard = cur;
    }
}

uint32_t cov_total(void) { return g_guard_count; }

void cov_reset(void) {
    memset(g_guard_flags, 0, sizeof(g_guard_flags));
    memset(g_guard_hits, 0, sizeof(g_guard_hits));
    memset(g_edge_map, 0, sizeof(g_edge_map));
    g_prev_guard = 0;
}

int cov_hit(uint32_t i) { return i < MAX_GUARDS && g_guard_flags[i]; }
int cov_hits(uint32_t i) { return i < MAX_GUARDS ? g_guard_hits[i] : 0; }

/* 統計有多少條 edge 被走到（僅用於回報，不做逐項掃描的熱路徑） */
long cov_edge_count(void) {
    long n = 0;
    for (int i = 0; i < EDGE_MAP; i++) {
        if (g_edge_map[i]) n++;
    }
    return n;
}

/*
 * 把執行次數分桶（AFL 的 CLASSIFY_COUNTS）
 *
 *  1        → 1
 *  2        → 2
 *  3        → 3
 *  4..7     → 4
 *  8..15    → 5
 *  16..31   → 6
 *  32..127  → 7
 *  128..255 → 8
 *  256+     → 9
 *
 * 意義：同一個 block 被「碰到更多次」代表迴圈深度不同，
 *        那是新的程式狀態——只用 0/1 判斷會漏掉這類探索。
 */
int cov_bucket(uint32_t i) {
    if (i >= MAX_GUARDS) return 0;
    uint16_t c = g_guard_hits[i];
    if (c == 0) return 0;
    if (c == 1) return 1;
    if (c == 2) return 2;
    if (c == 3) return 3;
    if (c < 8)  return 4;
    if (c < 16) return 5;
    if (c < 32) return 6;
    if (c < 128) return 7;
    if (c < 256) return 8;
    return 9;
}

/* ---------------------------------------------------------------------------
 * 漏洞路徑（與 v1 相同，以保持對照實驗的可比性）
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
    if (declared < 0x8001) return 0;            /* 層 8 */

    uint8_t cksum = 0;
    for (int i = 0; i < 6; i++) cksum ^= data[i];
    if (data[8] != cksum) return 0;             /* 層 9 checksum */

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
