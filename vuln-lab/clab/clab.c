/*
 * ============================================================================
 *  clab.c — C 記憶體安全漏洞實作靶場（VULNERABLE 版本）
 * ============================================================================
 *
 *  對應研究報告 CH06 第一階段（S1：記憶體安全）與第二階段（S2：工具鏈）。
 *
 *  !!! 警告 !!!
 *  本程式「刻意」包含多個記憶體安全漏洞，僅供本機編譯、隔離環境、
 *  教育用途。請勿用於任何真實目標。
 *
 *  編譯（含 AddressSanitizer + UndefinedBehaviorSanitizer）：
 *      clang -fsanitize=address,undefined -g -O0 -o clab.exe clab.c
 *
 *  執行：clab.exe <case>
 *      case 1 : 堆疊緩衝區溢位（off-by-one）        CWE-193 / CWE-121
 *      case 2 : 堆積緩衝區溢位（整數截斷導致配置過小） CWE-190 -> CWE-122
 *      case 3 : 釋放後使用（use-after-free）         CWE-416
 *      case 4 : 未初始化讀取（uninitialized read）    CWE-457
 *      case 5 : 陣列負索引寫入（sentinel 未處理）     CWE-787
 *
 *  設計理念：
 *    每個案例都是「真實專案中出現過的錯誤模式」的簡化版，
 *    並且都對應到報告 CH03 中某個真實漏洞的機制。
 *    用 sanitizer 執行後，可以觀察到標準的 ASan/UBSan 報告格式。
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * 案例 1：堆疊緩衝區溢位（off-by-one，邊界比較運算子用錯）
 * 對應 CWE-193（Off-by-one Error）/ CWE-121（Stack-based Buffer Overflow）
 * ------------------------------------------------------------------------- */
static void case1_off_by_one(void) {
    char buf[8];
    printf("[case 1] char buf[8]，迴圈條件寫成 i <= 8（應為 i < 8）\n");

    /* 漏洞點：<= 造成寫入索引 0..8，但 buf 只有索引 0..7 */
    for (int i = 0; i <= 8; i++) {
        buf[i] = 'A';
    }

    /* 為了讓編譯器不要最佳化掉，讀回一個值 */
    printf("[case 1] 若無 sanitizer，這裡不會有任何錯誤訊息\n");
    printf("[case 1] buf[0] = %c\n", buf[0]);
}

/* ---------------------------------------------------------------------------
 * 案例 2：堆積緩衝區溢位（長度計算截斷，導致配置過小）
 * 對應 CWE-190（Integer Overflow）/ CWE-122（Heap-based Buffer Overflow）
 * ------------------------------------------------------------------------- */
static void case2_integer_truncation(void) {
    /*
     * 模擬從網路讀到的 16-bit 長度欄位。
     * 真實情境：攻擊者可控制這個值。
     */
    unsigned short count = 0x8000;          /* 32768 */
    unsigned short bytes_needed = count * 2; /* 0x10000 截斷成 0 */

    printf("[case 2] count = %u，count * 2 在 16-bit 下 = %u（數學上應為 %u）\n",
           (unsigned)count, (unsigned)bytes_needed, (unsigned)count * 2);

    /* 漏洞點：配置的大小被截斷成 0，但稍後要寫入 count 個位元組 */
    char *heap = (char *)malloc(bytes_needed == 0 ? 1 : bytes_needed);
    if (heap == NULL) {
        printf("[case 2] malloc 失敗\n");
        return;
    }
    printf("[case 2] malloc(%u) 實際配置 %u bytes，但即將寫入 %u bytes\n",
           (unsigned)bytes_needed, (unsigned)(bytes_needed == 0 ? 1 : bytes_needed),
           (unsigned)count);

    /* 漏洞點：寫入遠超過配置大小 */
    for (unsigned i = 0; i < count; i++) {
        heap[i] = (char)(i & 0xFF);
    }

    printf("[case 2] heap[0] = %d\n", heap[0]);
    free(heap);
}

/* ---------------------------------------------------------------------------
 * 案例 3：釋放後使用（use-after-free）
 * 對應 CWE-416
 * ------------------------------------------------------------------------- */
struct Session {
    int user_id;
    char token[8];
};

static void case3_use_after_free(void) {
    struct Session *s = (struct Session *)malloc(sizeof(struct Session));
    if (s == NULL) return;
    s->user_id = 0x1234;
    strcpy(s->token, "secret");

    printf("[case 3] session 已建立，user_id = 0x%X\n", s->user_id);

    free(s);   /* 釋放 */
    printf("[case 3] 已 free(s)，但指標 s 仍然存在\n");

    /*
     * 漏洞點：free 之後繼續使用 s。
     * 真實世界中這塊記憶體可能已被重新配置給其他物件。
     */
    printf("[case 3] 讀取已釋放的 s->user_id = 0x%X\n", s->user_id);

    strcpy(s->token, "pwned");   /* 寫入已釋放的記憶體 */
    printf("[case 3] 已寫入已釋放的記憶體\n");
}

/* ---------------------------------------------------------------------------
 * 案例 4：未初始化讀取（uninitialized memory read）
 * 對應 CWE-457，並示範記憶體洩漏（MemorySanitizer 的領域，但 ASan 也可觀察）
 * ------------------------------------------------------------------------- */
static void case4_uninitialized_read(void) {
    int *arr = (int *)malloc(sizeof(int) * 4);   /* 未初始化 */
    if (arr == NULL) return;

    printf("[case 4] malloc 之後未初始化即讀取（內容是先前殘留的資料）\n");

    /* 漏洞點：只寫入 arr[0]，卻讀取 arr[0..3] */
    arr[0] = 42;
    int sum = 0;
    for (int i = 0; i < 4; i++) {
        sum += arr[i];      /* arr[1..3] 未初始化 */
    }
    printf("[case 4] sum = %d（其中包含未初始化的值）\n", sum);

    free(arr);
}

/* ---------------------------------------------------------------------------
 * 案例 5：陣列負索引寫入（sentinel 值未被正確處理）
 * 對應 CWE-787（Out-of-bounds Write）
 * 這是 Big Sleep 在 SQLite 找到的漏洞機制的簡化重現。
 * ------------------------------------------------------------------------- */
#define SERIES_COLUMN_START 1

struct IndexConstraint {
    int iColumn;    /* -1 代表 ROWID（sentinel 值） */
    int op;
};

static void case5_negative_index(void) {
    /*
     * 模擬 SQLite 的 seriesBestIndex()：
     *   iCol = pConstraint->iColumn - SERIES_COLUMN_START;
     *   aIdx[iCol] = i;
     *
     * 當 iColumn = -1（ROWID sentinel）時，iCol = -2，
     * 造成負索引寫入 aIdx 之前的位置。
     */
    int aIdx[3];                       /* 只允許索引 0..2 */
    struct IndexConstraint c;
    c.iColumn = -1;                    /* ROWID sentinel */
    c.op = 1;

    printf("[case 5] pConstraint->iColumn = %d（ROWID 的 sentinel 值）\n", c.iColumn);

    int iCol = c.iColumn - SERIES_COLUMN_START;
    printf("[case 5] iCol = %d - %d = %d\n", c.iColumn, SERIES_COLUMN_START, iCol);

    /*
     * 真實 SQLite 在此處有 assert(iCol >= 0 && iCol <= 2)，
     * 但 release build 會移除 assert，於是負索引寫入實際發生。
     */
    printf("[case 5] release build 無 assert，執行 aIdx[%d] = 1\n", iCol);
    aIdx[iCol] = 1;                    /* 漏洞點：負索引寫入 */

    printf("[case 5] 若無 sanitizer，這裡不會有任何訊息\n");
    printf("[case 5] aIdx[0] = %d\n", aIdx[0]);
}

/* ------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("用法: %s <1-5>\n", argv[0]);
        printf("  1 = 堆疊 off-by-one\n");
        printf("  2 = 整數截斷導致堆積溢位\n");
        printf("  3 = use-after-free\n");
        printf("  4 = 未初始化讀取\n");
        printf("  5 = 負索引寫入（Big Sleep SQLite 機制）\n");
        return 1;
    }

    int which = atoi(argv[1]);
    printf("=== clab (VULNERABLE) case %d ===\n", which);

    switch (which) {
        case 1: case1_off_by_one();            break;
        case 2: case2_integer_truncation();    break;
        case 3: case3_use_after_free();        break;
        case 4: case4_uninitialized_read();    break;
        case 5: case5_negative_index();        break;
        default: printf("未知案例\n");          return 1;
    }

    printf("=== case %d 結束 ===\n", which);
    return 0;
}
