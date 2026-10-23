/*
 * ============================================================================
 *  fuzz_main.c — in-process coverage-guided fuzzer（自製 libFuzzer 替代）
 * ============================================================================
 *
 *  對應研究報告：
 *   - CH06 S2（工具鏈：fuzzer 的核心迴圈）
 *   - CH03（Big Sleep 的「覆蓋率引導 vs 盲目 mutation」對照實驗）
 *
 *  為什麼要自己寫？
 *    本環境 clang（MinGW target）不支援 -fsanitize=fuzzer，
 *    但 -fsanitize-coverage=trace-pc-guard 可用 —— 那正是 libFuzzer
 *    內部使用的同一套插樁機制。所以我們自己實作回饋迴圈。
 *
 *  in-process 的關鍵優勢（實測 30 exec/s → 數萬 exec/s）：
 *    Python 版每輪都要 CreateProcess 啟動新行程，開銷主導一切。
 *    libFuzzer 之所以快，是因為它在**同一行程內**反覆呼叫目標函式。
 *
 *  崩潰處理策略：
 *    ASan 攔到錯誤時預設會 _exit()，fuzzer 就死了。
 *    解法：設定 ASAN_OPTIONS=abort_on_error=1，並安裝 SIGABRT handler，
 *          在 handler 中把「導致崩潰的輸入」寫入 crash.bin 再結束。
 *    外層用 Python 啟動器偵測非零退出碼後：
 *      (1) 保存 crash.bin
 *      (2) 從存活的 corpus 重新啟動 fuzzer（AFL 的 fork-server 簡化版）
 *
 *  用法：
 *    fuzz_main.exe <mode> <iters> <seed> [corpus_dir] [last_input_file]
 *      mode = guided | blind
 * ============================================================================
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 由 fuzz_target.c 提供 */
extern int check_packet(const uint8_t *data, size_t size);
extern uint32_t cov_total(void);
extern void cov_reset(void);
extern int cov_hit(uint32_t i);

#define MAX_CORPUS 4096
#define MAX_INPUT  1024

static uint8_t g_current[MAX_INPUT];
static size_t  g_current_len = 0;
static const char *g_last_file = NULL;
static const char *g_crash_file = NULL;
static long    g_execs_at_death = 0;   /* 崩潰時已執行的迭代數 */

/* ---------------------------------------------------------------------------
 * 崩潰輸入保存的演進（值得記錄的實作經驗）
 *
 * 第一次嘗試：signal(SIGABRT, handler) 在 handler 中寫檔
 *   → 失敗。因為 ASan 攔到錯誤後會呼叫自家回呼並 _exit()/abort()，
 *     我們的 handler 不一定被執行（實測 exit code 為 3，檔案未產生）。
 *
 * 第二次嘗試：每次迭代前把輸入寫入檔案
 *   → 可行但太慢（I/O 主導，摧毀 in-process 的效能優勢）。
 *
 * 最終解法：ASan 的官方回呼 __sanitizer_set_death_callback
 *   → 只在「真的崩潰」時被呼叫，平時零成本。
 *     這正是把「記錄狀態」與「熱路徑」分離的正確作法。
 * ------------------------------------------------------------------------- */
void __sanitizer_set_death_callback(void (*callback)(void));

static void on_death(void) {
    if (g_last_file && g_current_len > 0) {
        FILE *f = fopen(g_last_file, "wb");
        if (f) { fwrite(g_current, 1, g_current_len, f); fclose(f); }
    }
    if (g_crash_file && g_current_len > 0) {
        FILE *f = fopen(g_crash_file, "wb");
        if (f) { fwrite(g_current, 1, g_current_len, f); fclose(f); }
    }

    /* 崩潰瞬間的覆蓋率統計
     *
     * 為什麼要在這裡印？
     *   guided 往往在幾千次迭代內就找到 crash，週期性輸出（每 10000 次）
     *   根本來不及印。若只靠 stdout 的 PROGRESS 行，「崩潰前的覆蓋率」
     *   就會是空白 —— 而這正是我們最想知道的數字之一。
     *   death callback 是唯一能在崩潰當下可靠執行的位置。
     */
    {
        uint32_t total = cov_total();
        long hits = 0;
        for (uint32_t g = 0; g < total; g++) {
            if (cov_hit(g)) hits++;
        }
        /* 寫入檔案（stdout 可能已被 ASan 接管或有緩衝問題） */
        FILE *f = fopen("coverage_at_crash.txt", "w");
        if (f) {
            fprintf(f, "execs_at_crash=%ld\ncoverage_at_crash=%ld\nguards=%u\n",
                    g_execs_at_death, hits, total);
            fclose(f);
        }
        fprintf(stderr, "[FUZZER] crash at execs=%ld, coverage=%ld/%u guards\n",
                g_execs_at_death, hits, total);
    }
}

static void on_signal(int sig) {
    (void)sig;
    on_death();
    _exit(99);
}

/* ---------------------------------------------------------------------------
 * 覆蓋率統計輸出
 *
 *  為什麼要週期性輸出？
 *    guided 模式通常在找到 crash 時就被 ASan 中斷，程式來不及印最終的
 *    RESULT 行 —— 於是「崩潰前的覆蓋率」就遺失了。
 *    週期性輸出讓我們能看到覆蓋率隨時間的成長，以及崩潰那一刻的數字。
 * ------------------------------------------------------------------------- */
static void print_progress(const char *mode, long execs, uint32_t total,
                           const uint8_t *cov, int n_corpus, long new_cov) {
    long hits = 0;
    for (uint32_t g = 0; g < total; g++) {
        if (cov[g]) hits++;
    }
    printf("PROGRESS mode=%s execs=%ld coverage=%ld guards=%u corpus=%d new_cov=%ld\n",
           mode, execs, hits, total, n_corpus, new_cov);
    fflush(stdout);
}

/* ---------------------------------------------------------------------------
 * mutation（AFL 風格的簡單版本）
 * ------------------------------------------------------------------------- */
static uint64_t rng_state;
static uint32_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 11);
}
static uint32_t rnd_n(uint32_t n) { return n ? rnd() % n : 0; }

static const uint8_t INTERESTING[] = {
    0x00, 0x01, 0x0A, 0x46, 0x5A, 0x58, 0xFF, 0xC0, 0x01, 0x80, 0x7F
};
#define N_INTERESTING (sizeof(INTERESTING) / sizeof(INTERESTING[0]))

static size_t mutate(const uint8_t *src, size_t len, uint8_t *dst,
                     int rounds) {
    memcpy(dst, src, len);
    size_t n = len;
    for (int r = 0; r < rounds; r++) {
        if (n == 0) {
            n = 1 + rnd_n(16);
            for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)rnd();
            continue;
        }
        switch (rnd_n(8)) {
            case 0: {                                   /* bit flip */
                size_t i = rnd_n((uint32_t)n);
                dst[i] ^= (uint8_t)(1u << rnd_n(8));
                break;
            }
            case 1: {                                   /* interesting byte */
                size_t i = rnd_n((uint32_t)n);
                dst[i] = INTERESTING[rnd_n(N_INTERESTING)];
                break;
            }
            case 2: {                                   /* random byte */
                size_t i = rnd_n((uint32_t)n);
                dst[i] = (uint8_t)rnd();
                break;
            }
            case 3: {                                   /* insert */
                if (n < MAX_INPUT - 1) {
                    size_t i = rnd_n((uint32_t)(n + 1));
                    memmove(dst + i + 1, dst + i, n - i);
                    dst[i] = INTERESTING[rnd_n(N_INTERESTING)];
                    n++;
                }
                break;
            }
            case 4: {                                   /* delete */
                if (n > 1) {
                    size_t i = rnd_n((uint32_t)n);
                    memmove(dst + i, dst + i + 1, n - i - 1);
                    n--;
                }
                break;
            }
            case 5: {                                   /* append */
                if (n < MAX_INPUT - 1) {
                    dst[n++] = INTERESTING[rnd_n(N_INTERESTING)];
                }
                break;
            }
            case 6: {
                /* checksum-aware：改動標頭後自動重算 checksum。
                 *
                 * 為什麼需要這個？
                 *   目標有一層「checksum 必須等於 data[0..5] 的 XOR」。
                 *   純隨機 mutation 改動標頭後 checksum 幾乎必定失效，
                 *   於是檢查永遠停在那一層——這是「語意相依條件」的
                 *   典型樣貌（對應 CH01：覆蓋率無法引導到語意組合）。
                 *   知道格式的 fuzzer 可以直接維持這個不變量。
                 */
                if (n >= 9) {
                    size_t i = rnd_n(6);
                    dst[i] = INTERESTING[rnd_n(N_INTERESTING)];
                    uint8_t ck = 0;
                    for (int k = 0; k < 6; k++) ck ^= dst[k];
                    dst[8] = ck;
                }
                break;
            }
            default: {
                /* 隨機設定 16-bit declared 欄位（讓它落在漏洞視窗附近） */
                if (n >= 9) {
                    uint16_t v;
                    switch (rnd_n(3)) {
                        case 0: v = 0x8001 + (uint16_t)rnd_n(0x4000); break;
                        case 1: v = 0xC000 + (uint16_t)rnd_n(0x100);  break;
                        default: v = (uint16_t)rnd();                  break;
                    }
                    dst[6] = (uint8_t)(v >> 8);
                    dst[7] = (uint8_t)(v & 0xFF);
                }
                break;
            }
        }
    }
    return n;
}

/* ---------------------------------------------------------------------------
 * 主迴圈
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
                "用法: %s <guided|blind> <iters> <seed> [corpus_dir] [last_file]\n",
                argv[0]);
        return 2;
    }
    const char *mode = argv[0 + 1];
    long iters = atol(argv[2]);
    rng_state = (uint64_t)strtoull(argv[3], NULL, 0);
    if (rng_state == 0) rng_state = 0x9E3779B97F4A7C15ULL;

    const char *corpus_dir = (argc > 4) ? argv[4] : NULL;
    g_last_file = (argc > 5) ? argv[5] : NULL;
    g_crash_file = "crash.bin";

    /* ASan 的死亡回呼：只在真的崩潰時執行，平時零成本 */
    __sanitizer_set_death_callback(on_death);
    signal(SIGABRT, on_signal);
    signal(SIGSEGV, on_signal);
    signal(SIGILL, on_signal);

    int guided = (strcmp(mode, "guided") == 0);

    /* --- corpus 初始化 --- */
    static uint8_t corpus[MAX_CORPUS][MAX_INPUT];
    static size_t corpus_len[MAX_CORPUS];
    static int corpus_used[MAX_CORPUS];   /* 是否已貢獻過新覆蓋 */
    int n_corpus = 0;

    /* 初始 seeds（刻意都很淺，不含接近答案的輸入） */
    static const uint8_t seed0[] = { 0 };
    static const uint8_t seed1[] = { 'A' };
    static const uint8_t seed2[] = { 0x46, 0x5A };
    static const uint8_t seed3[] = { 0x46, 0x5A, 0x5A, 0x01 };
    static const uint8_t seed4[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00 };
    const uint8_t *seeds[] = { seed0, seed1, seed2, seed3, seed4 };
    const size_t seed_lens[] = { sizeof(seed0), sizeof(seed1), sizeof(seed2),
                                 sizeof(seed3), sizeof(seed4) };
    for (int i = 0; i < 5; i++) {
        memcpy(corpus[n_corpus], seeds[i], seed_lens[i]);
        corpus_len[n_corpus] = seed_lens[i];
        corpus_used[n_corpus] = 0;
        n_corpus++;
    }

    /* --- 全域覆蓋（guided 模式用來判斷「是否有新覆蓋」） --- */
    static uint8_t global_cov[8192];
    memset(global_cov, 0, sizeof(global_cov));

    uint32_t total_guards = 0;
    long execs = 0;
    long new_cov_events = 0;
    long corpus_adds = 0;
    uint8_t cand[MAX_INPUT];

    for (long it = 0; it < iters; it++) {
        /* 1. 挑 parent（guided 偏好較新的 corpus 項目，模仿 AFL 的 queue） */
        int pi;
        if (guided && n_corpus > 0) {
            uint32_t span = (uint32_t)(n_corpus < 8 ? n_corpus : 8);
            pi = n_corpus - 1 - (int)rnd_n(span);
            if (pi < 0) pi = 0;
        } else {
            pi = (int)rnd_n((uint32_t)n_corpus);
        }

        int rounds = guided ? (1 + (int)rnd_n(3)) : (1 + (int)rnd_n(6));
        size_t clen = mutate(corpus[pi], corpus_len[pi], cand, rounds);

        memcpy(g_current, cand, clen);
        g_current_len = clen;

        /* 2. 執行目標 */
        cov_reset();
        check_packet(cand, clen);
        execs++;
        g_execs_at_death = execs;   /* 供 death callback 回報崩潰時的迭代數 */
        total_guards = cov_total();

        /* 3. 覆蓋率回饋 */
        if (guided) {
            int is_new = 0;
            for (uint32_t g = 0; g < total_guards; g++) {
                if (cov_hit(g) && !global_cov[g]) {
                    global_cov[g] = 1;
                    is_new = 1;
                }
            }
            if (is_new) {
                new_cov_events++;
                if (n_corpus < MAX_CORPUS) {
                    memcpy(corpus[n_corpus], cand, clen);
                    corpus_len[n_corpus] = clen;
                    corpus_used[n_corpus] = 1;
                    n_corpus++;
                    corpus_adds++;
                    /* 保存有價值的輸入 */
                    if (corpus_dir) {
                        char path[512];
                        snprintf(path, sizeof(path), "%s/cov_%ld_%d.bin",
                                 corpus_dir, execs, n_corpus);
                        FILE *f = fopen(path, "wb");
                        if (f) { fwrite(cand, 1, clen, f); fclose(f); }
                    }
                }
            }
        } else {
            /* blind 模式：只累積統計用覆蓋率，不用於引導 */
            for (uint32_t g = 0; g < total_guards; g++) {
                if (cov_hit(g)) global_cov[g] = 1;
            }
        }

        /* 週期性回報覆蓋率（guided 常在找到 crash 時被中斷，
           若只在最後印出，崩潰前的覆蓋率就看不到了） */
        if ((it + 1) % 10000 == 0) {
            long h = 0;
            for (uint32_t g = 0; g < total_guards; g++) {
                if (global_cov[g]) h++;
            }
            printf("PROGRESS mode=%s execs=%ld coverage=%ld guards=%u corpus=%d new_cov=%ld\n",
                   mode, it + 1, h, total_guards, n_corpus, new_cov_events);
            fflush(stdout);
        }
    }

    /* --- 統計輸出（給 Python 解析） --- */
    long hits = 0;
    for (uint32_t g = 0; g < total_guards; g++) {
        if (global_cov[g]) hits++;
    }
    printf("RESULT mode=%s execs=%ld coverage=%ld guards=%u corpus=%d new_cov=%ld\n",
           mode, execs, hits, total_guards, n_corpus, new_cov_events);
    return 0;
}
