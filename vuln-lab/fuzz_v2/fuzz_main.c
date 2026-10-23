/*
 * ============================================================================
 *  fuzz_main.c — in-process coverage-guided fuzzer（v2：提升命中率）
 * ============================================================================
 *
 *  對應研究報告 CH06 S2（工具鏈）與 CH03（覆蓋率引導的極限）。
 *
 *  v1 → v2 的四項改進（每一項都對應一個已知的 fuzzer 瓶頸）：
 *
 *  ┌────┬──────────────────────┬────────────────────────────────────────┐
 *  │ #  │ 改進                  │ 解決什麼問題                            │
 *  ├────┼──────────────────────┼────────────────────────────────────────┤
 *  │ 1  │ **Edge coverage**    │ block coverage 分不清「同一 block 從不同  │
 *  │    │ (prev→cur 轉移)      │ 前驅進來」= 不同探索成果                │
 *  │ 2  │ **Hit count 分桶**    │ 0/1 判斷遺失「迴圈深度」這種路徑訊息     │
 *  │ 3  │ **字典輔助**         │ 盲猜 16-bit 值效率極低（1/65536）        │
 *  │ 4  │ **多策略 mutation**  │ 單一策略對不同結構的輸入適應性差          │
 *  └────┴──────────────────────┴────────────────────────────────────────┘
 *
 *  實測動機（v1 的警訊）：
 *    guided 崩潰時覆蓋率 10/93，blind 跑久可達 14/93 ——
 *    「低覆蓋的 guided 找到漏洞、高覆蓋的 blind 找不到」，
 *    說明 v1 的「新穎性判準」鑑別力不足。
 *
 *  用法：
 *    fuzz_main.exe <guided|blind> <iters> <seed> [corpus_dir] [last_file]
 * ============================================================================
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 由 fuzz_target.c 提供 */
extern int check_packet(const uint8_t *data, size_t size);
extern uint32_t cov_total(void);
extern void cov_reset(void);
extern int cov_hit(uint32_t i);
extern int cov_hits(uint32_t i);
extern int cov_bucket(uint32_t i);
extern long cov_edge_count(void);

#define MAX_CORPUS 8192
#define MAX_INPUT  1024

/* 必須與 fuzz_target.c 的 MAX_GUARDS 一致。
 * （原本想用 extern const int，但陣列大小需要編譯期常數，
 *   所以兩邊各自定義——若之後調整，記得同步修改。） */
#define MAX_GUARDS 8192

static uint8_t g_current[MAX_INPUT];
static size_t  g_current_len = 0;
static const char *g_last_file = NULL;
static const char *g_crash_file = NULL;
static long    g_execs_at_death = 0;

/* ---------------------------------------------------------------------------
 * 崩潰輸入與「崩潰時覆蓋率」的保存
 *
 *  signal handler 實測不可靠（ASan 會走自己的結束路徑），
 *  必須用 __sanitizer_set_death_callback。這是唯一在崩潰當下可靠執行的位置。
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
    {
        uint32_t total = cov_total();
        long hits = 0, bucketed = 0;
        for (uint32_t g = 0; g < total; g++) {
            if (cov_hit(g)) hits++;
            if (cov_bucket(g) > 0) bucketed++;
        }
        FILE *f = fopen("coverage_at_crash.txt", "w");
        if (f) {
            fprintf(f, "execs_at_crash=%ld\ncoverage_at_crash=%ld\n"
                       "bucketed_at_crash=%ld\nedges_at_crash=%ld\nguards=%u\n",
                    g_execs_at_death, hits, bucketed, cov_edge_count(), total);
            fclose(f);
        }
        fprintf(stderr,
                "[FUZZER] crash at execs=%ld  blocks=%ld/%u  buckets=%ld  edges=%ld\n",
                g_execs_at_death, hits, total, bucketed, cov_edge_count());
    }
}

static void on_signal(int sig) { (void)sig; on_death(); _exit(99); }

/* ---------------------------------------------------------------------------
 * 字典（改進 3）：格式感知的關鍵位元組
 *
 *  為什麼有效？
 *    目標要求「魔數 FZZ + 版本 0x01 + 型別 0x0A」等 6 個精確位元組。
 *    純隨機猜的機率是 1/256^6，等於不可能。
 *    把「可能有意義的位元組」集中成字典，等於把搜尋空間從 256 降到 ~20。
 *
 *  實務上這個字典來自：規格文件、既有 corpus 抽取、或 LLM 生成。
 *  → 這正是 CH02.2「seed 生成 / mutator 學習」能插進來的位置。
 * ------------------------------------------------------------------------- */
static const uint8_t DICT[] = {
    0x00, 0x01, 0x02, 0x0A, 0x0D, 0x1A, 0x41, 0x46, 0x5A, 0x58,
    0x7F, 0x80, 0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF,
    /* 16-bit 值的兩端：讓 declared 容易落在漏洞視窗 */
    0xC0, 0x01, 0xC0, 0x00, 0x80, 0x01, 0xFF, 0xFF
};
#define N_DICT (sizeof(DICT) / sizeof(DICT[0]))

/* ---------------------------------------------------------------------------
 * mutation（改進 4：多策略混合）
 * ------------------------------------------------------------------------- */
static uint64_t rng_state;
static uint32_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 11);
}
static uint32_t rnd_n(uint32_t n) { return n ? rnd() % n : 0; }

/*
 * 決定 mutation 強度（rounds）
 *
 *   guided：少量累積（1-3）——保留既有正確部分，逐步逼近
 *   blind ：大量變動（1-8）——沒有任何回饋可依靠，只能靠大範圍擾動
 */
static int pick_rounds(int guided) {
    if (guided) {
        /* 80% 做少量精修，20% 做較大跳躍（避免陷入局部最佳） */
        return (rnd_n(10) < 8) ? (1 + (int)rnd_n(3)) : (3 + (int)rnd_n(4));
    }
    return 1 + (int)rnd_n(8);
}

static size_t mutate(const uint8_t *src, size_t len, uint8_t *dst, int guided) {
    memcpy(dst, src, len);
    size_t n = len;
    int rounds = pick_rounds(guided);

    for (int r = 0; r < rounds; r++) {
        if (n == 0) {
            n = 1 + rnd_n(16);
            for (size_t i = 0; i < n; i++) dst[i] = DICT[rnd_n(N_DICT)];
            continue;
        }
        switch (rnd_n(9)) {
            case 0: {   /* bit flip */
                size_t i = rnd_n((uint32_t)n);
                dst[i] ^= (uint8_t)(1u << rnd_n(8));
                break;
            }
            case 1: {   /* 字典位元組 */
                dst[rnd_n((uint32_t)n)] = DICT[rnd_n(N_DICT)];
                break;
            }
            case 2: {   /* 隨機位元組（保留發掘新值的可能） */
                dst[rnd_n((uint32_t)n)] = (uint8_t)rnd();
                break;
            }
            case 3: {   /* 插入 */
                if (n < MAX_INPUT - 1) {
                    size_t i = rnd_n((uint32_t)(n + 1));
                    memmove(dst + i + 1, dst + i, n - i);
                    dst[i] = DICT[rnd_n(N_DICT)];
                    n++;
                }
                break;
            }
            case 4: {   /* 刪除 */
                if (n > 1) {
                    size_t i = rnd_n((uint32_t)n);
                    memmove(dst + i, dst + i + 1, n - i - 1);
                    n--;
                }
                break;
            }
            case 5: {   /* 附加 */
                if (n < MAX_INPUT - 1) dst[n++] = DICT[rnd_n(N_DICT)];
                break;
            }
            case 6: {   /* checksum-aware：維持格式不變量 */
                if (n >= 9) {
                    dst[rnd_n(6)] = DICT[rnd_n(N_DICT)];
                    uint8_t ck = 0;
                    for (int k = 0; k < 6; k++) ck ^= dst[k];
                    dst[8] = ck;
                }
                break;
            }
            case 7: {   /* declared 欄位導向（big-endian） */
                if (n >= 9) {
                    uint16_t v;
                    switch (rnd_n(4)) {
                        case 0: v = 0xC000 + (uint16_t)rnd_n(0x100); break;
                        case 1: v = 0x8001 + (uint16_t)rnd_n(0x4000); break;
                        case 2: v = 0xC000 + (uint16_t)(DICT[rnd_n(N_DICT)] & 0xFF); break;
                        default: v = (uint16_t)rnd(); break;
                    }
                    dst[6] = (uint8_t)(v >> 8);
                    dst[7] = (uint8_t)(v & 0xFF);
                }
                break;
            }
            default: {  /* 區塊複製（splice 的簡化版） */
                if (n >= 2) {
                    size_t a = rnd_n((uint32_t)n);
                    size_t b = rnd_n((uint32_t)n);
                    dst[a] = dst[b];
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
        fprintf(stderr, "用法: %s <guided|blind> <iters> <seed> [corpus_dir]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    long iters = atol(argv[2]);
    rng_state = strtoull(argv[3], NULL, 0);
    if (rng_state == 0) rng_state = 0x9E3779B97F4A7C15ULL;

    const char *corpus_dir = (argc > 4) ? argv[4] : NULL;
    g_last_file = (argc > 5) ? argv[5] : NULL;
    g_crash_file = "crash.bin";

    __sanitizer_set_death_callback(on_death);
    signal(SIGABRT, on_signal);
    signal(SIGSEGV, on_signal);
    signal(SIGILL, on_signal);

    int guided = (strcmp(mode, "guided") == 0);

    /* --- corpus --- */
    static uint8_t corpus[MAX_CORPUS][MAX_INPUT];
    static size_t  corpus_len[MAX_CORPUS];
    int n_corpus = 0;

    /* 初始 seeds：從「已具備部分結構」的輸入開始，而非全空
       （實務上 corpus 來自既有測試檔或歷史 crash） */
    static const uint8_t s0[] = { 0 };
    static const uint8_t s1[] = { 0x46 };
    static const uint8_t s2[] = { 0x46, 0x5A };
    static const uint8_t s3[] = { 0x46, 0x5A, 0x5A };
    static const uint8_t s4[] = { 0x46, 0x5A, 0x5A, 0x01, 0x0A, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t s5[] = { 0x46, 0x5A, 0x5A, 0x01, 0x0A, 0x00,
                                 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t *seeds[] = { s0, s1, s2, s3, s4, s5 };
    const size_t seed_lens[] = { sizeof(s0), sizeof(s1), sizeof(s2),
                                 sizeof(s3), sizeof(s4), sizeof(s5) };
    for (int i = 0; i < 6; i++) {
        memcpy(corpus[n_corpus], seeds[i], seed_lens[i]);
        corpus_len[n_corpus] = seed_lens[i];
        n_corpus++;
    }

    /* --- 全域覆蓋（改進 1 + 2：用 edge + bucket 判斷新穎性） --- */
    static int global_bucket[MAX_GUARDS];
    memset(global_bucket, 0, sizeof(global_bucket));
    long global_edges = 0;      /* 用於統計 */

    long execs = 0, new_cov_events = 0, corpus_adds = 0;
    uint32_t total_guards = 0;
    uint8_t cand[MAX_INPUT];

    for (long it = 0; it < iters; it++) {
        /* 1. 挑 parent
         *    guided 偏好近期加入的（AFL 的 queue 尾部優先），
         *    並保留少量機率回到舊 corpus（避免只在一條路徑上打轉）
         */
        int pi;
        if (guided && n_corpus > 0) {
            if (rnd_n(10) < 8) {
                uint32_t span = (uint32_t)(n_corpus < 16 ? n_corpus : 16);
                pi = n_corpus - 1 - (int)rnd_n(span);
            } else {
                pi = (int)rnd_n((uint32_t)n_corpus);
            }
            if (pi < 0) pi = 0;
        } else {
            pi = (int)rnd_n((uint32_t)n_corpus);
        }

        size_t clen = mutate(corpus[pi], corpus_len[pi], cand, guided);
        memcpy(g_current, cand, clen);
        g_current_len = clen;

        /* 2. 執行目標 */
        cov_reset();
        check_packet(cand, clen);
        execs++;
        g_execs_at_death = execs;
        total_guards = cov_total();

        /* 3. 新穎性判斷
         *    guided：bucket 變化（含 0→N 與 N→M）才算新覆蓋
         *            這比「0/1 命中」敏感，能捕捉迴圈深度變化
         *    blind ：不用回饋，只累積統計
         */
        if (guided) {
            int is_new = 0;
            for (uint32_t g = 0; g < total_guards; g++) {
                int b = cov_bucket(g);
                if (b != 0 && b != global_bucket[g]) {
                    global_bucket[g] = b;
                    is_new = 1;
                }
            }
            if (is_new) {
                new_cov_events++;
                if (n_corpus < MAX_CORPUS) {
                    memcpy(corpus[n_corpus], cand, clen);
                    corpus_len[n_corpus] = clen;
                    n_corpus++;
                    corpus_adds++;
                    if (corpus_dir) {
                        char path[600];
                        snprintf(path, sizeof(path), "%s/cov_%ld_%d.bin",
                                 corpus_dir, execs, n_corpus);
                        FILE *f = fopen(path, "wb");
                        if (f) { fwrite(cand, 1, clen, f); fclose(f); }
                    }
                }
            }
        } else {
            for (uint32_t g = 0; g < total_guards; g++) {
                int b = cov_bucket(g);
                if (b > global_bucket[g]) global_bucket[g] = b;
            }
        }

        /* 4. 週期性回報 */
        if ((it + 1) % 10000 == 0) {
            long hits = 0, bucketed = 0;
            for (uint32_t g = 0; g < total_guards; g++) {
                if (cov_hit(g)) hits++;
                if (global_bucket[g] > 0) bucketed++;
            }
            printf("PROGRESS mode=%s execs=%ld blocks=%ld buckets=%ld guards=%u "
                   "corpus=%d new_cov=%ld edges=%ld\n",
                   mode, it + 1, hits, bucketed, total_guards,
                   n_corpus, new_cov_events, cov_edge_count());
            fflush(stdout);
        }
    }

    /* --- 最終統計 --- */
    {
        long hits = 0, bucketed = 0;
        for (uint32_t g = 0; g < total_guards; g++) {
            if (cov_hit(g)) hits++;
            if (global_bucket[g] > 0) bucketed++;
        }
        printf("RESULT mode=%s execs=%ld coverage=%ld buckets=%ld edges=%ld "
               "guards=%u corpus=%d new_cov=%ld\n",
               mode, execs, hits, bucketed, cov_edge_count(), total_guards,
               n_corpus, new_cov_events);
    }
    return 0;
}
