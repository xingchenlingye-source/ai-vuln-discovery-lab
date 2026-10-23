#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 memlab.py — 記憶體安全漏洞「機制」模擬器
=============================================================================

 為什麼需要這個檔案？
   本練習環境無法安裝 C/C++ 編譯器（winget 下載被網路阻擋），
   因此無法用 AddressSanitizer 示範真實的記憶體錯誤。

   但「理解漏洞機制」不需要真的讓程式崩潰——我們可以用 Python
   建立一個**可控的記憶體模型**，把 C 語言的緩衝區、邊界、生命週期
   具體化成可觀察的物件，然後重現四個最經典的記憶體安全漏洞。

 教學價值：
   - 對應報告 CH06 S1「記憶體安全」主題
   - 對應 CH01「覆蓋率不等於語意正確性」的具體樣貌
   - Big Sleep 的 SQLite 漏洞就是一個「負索引寫入堆疊緩衝區」

 重要聲明：
   這是「機制模擬」，不是真實記憶體操作。真實的 C 記憶體錯誤會造成
   未定義行為（UB）與實際可利用的記憶體損毀，本模擬僅用於理解原理。

 執行：python memlab.py
=============================================================================
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# 記憶體模型：把「位元組陣列 + 邊界 + 生命週期」具體化
# ---------------------------------------------------------------------------
@dataclass
class Buffer:
    """模擬一塊固定大小的記憶體緩衝區。"""

    name: str
    size: int                      # 配置的位元組數
    data: bytearray = field(init=False)
    freed: bool = False            # 是否已被 free
    is_stack: bool = True          # 堆疊或堆積
    violation: Optional[str] = None  # 記錄第一件「不該發生的事」

    def __post_init__(self):
        self.data = bytearray(self.size)

    # --- 安全的寫入 -------------------------------------------------------
    def write(self, offset: int, value: int) -> bool:
        """寫入一個位元組。越界時記錄違規但不中斷（重現 UB 的沉默性）。"""
        if self.freed:
            self._flag("use-after-free：對已 free 的 %s 寫入" % self.name)
            return False
        if offset < 0:
            self._flag("out-of-bounds write（負索引）：%s[%d]" % (self.name, offset))
            return False
        if offset >= self.size:
            self._flag(
                "out-of-bounds write：%s[%d] 超出配置大小 %d"
                % (self.name, offset, self.size)
            )
            return False
        self.data[offset] = value & 0xFF
        return True

    def read(self, offset: int) -> Optional[int]:
        if self.freed:
            self._flag("use-after-free：讀取已 free 的 %s" % self.name)
            return None
        if offset < 0 or offset >= self.size:
            self._flag("out-of-bounds read：%s[%d]" % (self.name, offset))
            return None
        return self.data[offset]

    def free(self):
        """釋放記憶體（模擬 free）。"""
        self.freed = True

    def _flag(self, msg: str):
        if self.violation is None:      # 只記錄第一次，模擬 sanitizer 的「首次違規」
            self.violation = msg

    # --- 視覺化 -----------------------------------------------------------
    def render(self, highlight: Optional[int] = None) -> str:
        cells = []
        for i in range(self.size):
            v = self.data[i]
            mark = "^" if i == highlight else " "
            cells.append("%s%02x" % (mark, v))
        state = " [FREED]" if self.freed else ""
        return "  %-16s [%s]%s\n    %s" % (
            self.name,
            " ".join(cells),
            state,
            " ".join("%2d" % i for i in range(self.size)),
        )


@dataclass
class Heap:
    """模擬堆積：追蹤配置與釋放。」"""

    blocks: List[Buffer] = field(default_factory=list)

    def alloc(self, name: str, size: int) -> Buffer:
        b = Buffer(name=name, size=size, is_stack=False)
        self.blocks.append(b)
        return b

    def show(self) -> str:
        return "\n".join(b.render() for b in self.blocks)


def banner(title: str):
    print("\n" + "=" * 74)
    print(" " + title)
    print("=" * 74)


# ---------------------------------------------------------------------------
# 案例 1：Off-by-one（CWE-193）
# ---------------------------------------------------------------------------
def case_off_by_one():
    banner("案例 1 · Off-by-one 寫入（CWE-193）")
    print("""
 典型 C 程式碼：
     char buf[8];
     for (int i = 0; i <= 8; i++)   // ← 應該寫 i < 8
         buf[i] = 0x41;

 迴圈跑 9 次，寫入索引 0..8，但 buf 只有索引 0..7。
 索引 8 是「剛好差一格」的越界——這是最常見也最難察覺的錯誤。
""")
    buf = Buffer("buf", 8)
    print(" 配置：", buf.render())
    print("\n 執行 for (i = 0; i <= 8; i++) buf[i] = 0x41 ...")
    for i in range(9):
        ok = buf.write(i, 0x41)
        status = "OK" if ok else "★ 越界！"
        print("   write(buf[%d])  %s" % (i, status))
    print("\n 最終記憶體狀態：")
    print(buf.render())
    print("\n 【Sanitizer 會說】")
    print("   " + (buf.violation or "無違規"))
    print("""
 【根因】邊界條件的比較運算子用錯（<= vs <）。
 【為什麼難找】程式「幾乎正確」，99% 的輸入都不會出事；
               只有在迴圈剛好走到最後一格時才越界。
 【修補】改用 i < 8，或使用 sizeof(buf)/sizeof(buf[0]) 取代硬編碼長度。
 【真實案例對照】Big Sleep 在 SQLite 找到的漏洞，root cause 是
                 iColumn 欄位的 -1 sentinel 未被處理，導致 iCol 變成 -2，
                 寫入 aIdx[-2]（負索引越界），與此例同類。""")


# ---------------------------------------------------------------------------
# 案例 2：整數溢位導致配置過小（CWE-190 → CWE-787）
# ---------------------------------------------------------------------------
def case_integer_overflow():
    banner("案例 2 · 整數溢位導致配置過小（CWE-190 → CWE-787）")
    print("""
 典型 C 程式碼（16-bit 整數環境）：
     unsigned short n = 0;
     n = read_u16_from_network();     // 攻擊者可控
     unsigned short total = n * 2;    // ← 乘法可能溢位！
     char *buf = malloc(total);
     memcpy(buf, data, n);            // 實際需要 n bytes

 若 n = 0x8000（32768），則 n * 2 = 0x10000 → 截斷為 0。
 malloc(0) 只配置 0 bytes，但 memcpy 會寫入 32768 bytes。
""")
    data_len = 32768
    n = 0x8000
    print(" 攻擊者輸入 n = %d (0x%04X)" % (n, n))
    print(" n * 2 的數學結果 = %d" % (n * 2))
    # 模擬 16-bit unsigned short 截斷
    truncated = (n * 2) & 0xFFFF
    print(" 截斷為 16-bit unsigned short 後 = %d (0x%04X)  ← 溢位！" % (truncated, truncated))
    alloc_size = truncated
    print("\n malloc(%d) → 配置 %d bytes" % (alloc_size, alloc_size))
    heap = Heap()
    buf = heap.alloc("buf", max(alloc_size, 1))
    print(" 實際緩衝區大小：", buf.size, "bytes")
    print("\n memcpy(buf, data, %d) 開始..." % n)
    written = 0
    for i in range(n):
        if not buf.write(i, 0x42):
            break
        written += 1
    print(" 成功寫入 %d bytes，之後越界。" % written)
    print("\n 【Sanitizer 會說】")
    print("   " + (buf.violation or "無違規"))
    print("""
 【根因】「長度計算」使用了一個會溢位的整數型別，導致配置的大小
         小於實際要寫入的資料量。
 【關鍵洞察】問題不在 memcpy，而在 malloc 的參數。
             Fuzzing 必須先滿足 n = 0x8000 這個特定值才會觸發，
             這正是 CH01 所說「覆蓋率不等於語意正確性」的典型：
             即使這三行都被覆蓋 100% 次，沒有正確的 n 就永遠不會崩潰。
 【修補】使用足以容納的型別（size_t）並在乘法前檢查溢位：
            if (n > SIZE_MAX / 2) return ERROR;
            size_t total = (size_t)n * 2;""")


# ---------------------------------------------------------------------------
# 案例 3：Use-After-Free（CWE-416）
# ---------------------------------------------------------------------------
def case_use_after_free():
    banner("案例 3 · Use-After-Free（CWE-416）")
    print("""
 典型 C 程式碼：
     struct Session *s = create_session();
     use_session(s);
     free(s);                    // ← 釋放
     ...
     log_session(s->user_id);    // ← 仍然使用！已釋放的記憶體

 釋放後的記憶體可能被重新配置給別的物件，導致：
   (a) 讀到別人的資料（資訊洩漏）
   (b) 寫入破壞別人的資料（記憶體損毀）
   (c) 若攻擊者能控制重新配置的內容 → 可控制函式指標 → 執行任意程式碼
""")
    heap = Heap()
    s = heap.alloc("session", 8)
    print(" 1. 配置 session（8 bytes）")
    print(s.render())
    print("\n 2. 寫入 session 資料")
    for i, v in enumerate([0x11, 0x22, 0x33, 0x44]):
        s.write(i, v)
    print(s.render())
    print("\n 3. free(session)")
    s.free()
    print(s.render())
    print("\n 4. 配置新的 attacker_controlled（大小相同，可能重用同一塊記憶體）")
    evil = heap.alloc("attacker_buf", 8)
    for i in range(8):
        evil.write(i, 0xDE)
    print(evil.render())
    print("\n 5. 仍然使用舊的 session 指標 (use-after-free)")
    val = s.read(0)
    print("   s->user_id 讀到 = 0x%02X  ← 已經不是原本的 0x11 了！" % (val or 0))
    print("\n 【Sanitizer 會說】")
    print("   " + (s.violation or "無違規"))
    print("""
 【根因】物件生命週期管理錯誤：指標在 free 之後仍被使用。
 【為什麼難找】程式在 free 後「看起來」還在運作，行為取決於
             配置器是否剛好重用那塊記憶體——這造成「間歇性崩潰」，
             對 fuzzing 極不友善（同樣的輸入有時崩有時不崩）。
 【修補】free 後立即將指標設為 NULL；使用 RAII／智慧指標；
        或採用可自動檢查生命週期的語言（Rust 的所有權系統）。
 【真實案例對照】CH03 的 VulnLLM-R 論文中，作者觀察到 race condition
                 類漏洞需要動態資訊才能判定——UAF 同屬此類。""")


# ---------------------------------------------------------------------------
# 案例 4：負索引寫入堆疊（Big Sleep 案例的簡化重現）
# ---------------------------------------------------------------------------
def case_negative_index():
    banner("案例 4 · 負索引寫入堆疊緩衝區（Big Sleep SQLite 漏洞機制）")
    print("""
 背景：CH03 記錄的 Big Sleep 案例中，SQLite 的 seriesBestIndex() 有：

     struct sqlite3_index_constraint { int iColumn; ... };  // -1 代表 ROWID
     ...
     iCol = pConstraint->iColumn - SERIES_COLUMN_START;  // SERIES_COLUMN_START = 1
     assert( iCol >= 0 && iCol <= 2 );                   // 只有 debug build 有
     ...
     aIdx[iCol] = i;                                     // ← 負索引寫入！

 當 iColumn = -1（ROWID sentinel）時：
     iCol = -1 - 1 = -2
     aIdx[-2] = i;   ← 寫到 aIdx 陣列「之前」的記憶體

 在 release build 中 assert 被移除，於是寫入發生。
 這正是「sentinel 值」語意約定未被所有使用者正確處理的典型。
""")
    print(" 模擬堆疊佈局（由上而下為低位址到高位址）：")
    stack = [
        Buffer("pConstraint_ptr", 8),   # 在 aIdx 之前
        Buffer("aIdx", 7),              # 陣列本體
        Buffer("其他區域變數", 4),
    ]
    for b in stack:
        print(b.render())

    print("\n 情境：攻擊者送出 SELECT * FROM generate_series(1,10,1) WHERE ROWID = 1;")
    pConstraint_iColumn = -1
    SERIES_COLUMN_START = 1
    iCol = pConstraint_iColumn - SERIES_COLUMN_START
    print("   pConstraint->iColumn = %d (ROWID sentinel)" % pConstraint_iColumn)
    print("   iCol = %d - %d = %d" % (pConstraint_iColumn, SERIES_COLUMN_START, iCol))
    print("\n   assert(iCol >= 0 && iCol <= 2) 在 debug build：失敗（但 release 無此檢查）")
    print("   執行 aIdx[%d] = i;" % iCol)

    # 模擬：負索引寫入會落在 aIdx 之前的物件
    # iCol = -2 → 越界 2 個「int」，即 aIdx 之前的 8 bytes（32-bit int 環境）
    overflow_offset_into_prev = 8 + (iCol * 4)   # 8 + (-2 * 4) = 0
    print("\n   aIdx[%d] 實際落在「aIdx 之前 2 個 int（8 bytes）」：" % iCol)
    print("   而該處正是 pConstraint 指標的低 32 bits！")
    target = stack[0]
    target.write(overflow_offset_into_prev, 0xAA)
    print(target.render(highlight=overflow_offset_into_prev))
    print("""
 【根因】以負數作為「語意 sentinel」的設計，讓所有使用該欄位的程式碼
        都必須自行處理這個邊界。seriesBestIndex() 漏掉了。
 【為什麼 fuzzing 找不到】
        (1) 需要 generate_series 擴充功能被啟用——OSS-Fuzz 的 harness 沒開
        (2) 需要「對 ROWID 下約束」這個特定語意組合
        (3) 覆蓋率無法引導：程式碼可達性很高，但缺少語意組合
        → Big Sleep 團隊實測 150 CPU-hours 的 AFL 仍無法發現
 【修補】SQLite 同日修補（commit 41d58a014ce89356），正確處理 sentinel。""")


# ---------------------------------------------------------------------------
def summary():
    banner("總結：四個案例的共同結構")
    print("""
  ┌────────────────────┬──────────────────┬─────────────────────────────┐
  │ 案例               │ CWE              │ 防禦的關鍵                  │
  ├────────────────────┼──────────────────┼─────────────────────────────┤
  │ Off-by-one         │ CWE-193          │ 邊界條件的型別與比較運算子  │
  │ 整數溢位→配置過小  │ CWE-190→CWE-787  │ 長度運算使用足夠寬的型別    │
  │ Use-After-Free     │ CWE-416          │ 物件生命週期管理            │
  │ 負索引寫入堆疊     │ CWE-787          │ sentinel 語意的完整處理     │
  └────────────────────┴──────────────────┴─────────────────────────────┘

 三個共同點（對應報告 CH01）：

  1. 【都是語意問題，不是語法問題】
     程式碼「看起來對」，編譯器不會警告，大部分輸入也正常。

  2. 【覆蓋率無法引導到它們】
     這四種問題都需要「非常特定的輸入或狀態組合」。
     即使 100% 行覆蓋與分支覆蓋，仍可能完全無法觸發
     （Anthropic 在 CGIF 的 LZW 案例中明確指出這一點）。

  3. 【需要「可執行驗證」才能確認】
     靜態閱讀只能產生假設；要確認必須真的執行並觀察
     sanitizer 的報告。這正是 CH02.1「發現與驗證分離」的原因。

 下一步建議（真正的 C 環境）：
   若能取得編譯器，請把這四個案例寫成真正的 C 程式，
   以 clang -fsanitize=address,undefined -g 編譯後執行，
   觀察 ASan 的完整報告格式：
     #0 ... in function ...
     SUMMARY: AddressSanitizer: heap-buffer-overflow ...
""")


def main():
    print("=" * 74)
    print(" memlab.py — 記憶體安全漏洞機制模擬")
    print(" 對應研究報告 CH01、CH06 S1（記憶體安全）")
    print(" 注意：這是機制模擬，不是真實記憶體操作。")
    print("=" * 74)
    case_off_by_one()
    case_integer_overflow()
    case_use_after_free()
    case_negative_index()
    summary()


if __name__ == "__main__":
    main()
