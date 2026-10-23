# 自製 Coverage-Guided Fuzzer 與對照實驗

> 對應研究報告 **CH06 第二階段（S2：工具鏈——fuzzer 的原理與實作）**
> 與 **CH03**（Big Sleep 的 150 CPU-hours 對照實驗）。
>
> 這份文件記錄：為什麼不能用 libFuzzer、我們怎麼自己做出一個，
> 以及「覆蓋率引導」究竟比「盲目 mutation」好多少——**用實測數字回答**。

- 演練日期：2026-10-15
- 環境：Windows + LLVM-MinGW（clang 23.1.1）+ ASan + `trace-pc-guard`
- 結果：**guided 在 5,000–15,000 次迭代找到 crash；blind 跑滿 500,000 次找不到**

---

## 一、為什麼要自己寫 fuzzer

CH06 S2 的學習路徑列出「fuzzer、靜態分析、debugger、sanitizer」。本環境的實測結果是：

```
clang-23: error: unsupported option '-fsanitize=fuzzer' for target 'x86_64-w64-windows-gnu'
```

libFuzzer 的 runtime `.lib` 是 **MSVC ABI**，無法與 MinGW 的 GNU ABI 目標連結；
改用 MSVC target 則因系統無 Visual Studio 而缺 `stdio.h`。
AFL++／honggfuzz 未安裝（Windows 上需 WSL）。

**但關鍵發現是**：`-fsanitize-coverage=trace-pc-guard` **可用**——
而這正是 **libFuzzer 內部使用的同一套插樁機制**。

| 選項 | 結果 |
|---|---|
| `-fsanitize=fuzzer` | ❌ 不支援 |
| `-fsanitize-coverage=trace-pc` | ❌ 不支援 |
| **`-fsanitize-coverage=trace-pc-guard`** | ✅ **可用** |

→ 被封鎖的是「現成的引擎」，不是「覆蓋率引導的能力」。所以我們自己實作回饋迴圈。

---

## 二、架構

```
┌──────────────────────┐   啟動/統計/重啟   ┌────────────────────────────────┐
│  fuzzer.py           │ ─────────────────▶ │  fuzz_main.exe（C, in-process）│
│  （Python 啟動器）    │                    │   · 10 萬+ exec/s              │
│                      │ ◀───────────────── │   · trace-pc-guard 覆蓋率回饋  │
│  · 解析 RESULT 行     │      RESULT        │   · ASan 攔截 + death callback │
│  · 保存 crash 證據    │      / crash.bin   │   · corpus 管理 / mutation     │
└──────────────────────┘                    └────────────────────────────────┘
                                                      │
                                            ┌─────────▼──────────┐
                                            │ fuzz_target.c      │
                                            │  check_packet()    │
                                            │  （11 層巢狀檢查）  │
                                            └────────────────────┘
```

**為什麼是「Python + C」兩層**：Python 負責啟動、統計、重啟；C 負責熱路徑。
分工的理由見 §四的坑 1（效能差 4000 倍）。

---

## 三、目標與漏洞

`check_packet()` 有 **11 層漸進式巢狀條件**：

```
輸入格式：
  [0..2]  "FZZ"                     ← 3 層比對
  [3]     版本 0x01
  [4]     型別 0x0A
  [5]     保留 0x00
  [6..7]  declared（big-endian）
  [8]     checksum = XOR of data[0..5]
  [9..]   payload

漏洞（第 10-11 層之後）：
  need      = (unsigned short)((declared - 0x8000) * 4)   ← 16-bit 截斷
  write_len = declared - 0x8000                            ← 未截斷
  malloc(need) 之後寫入 write_len 個位元組
  → declared ∈ [0xC000, 0xC0FF] 時觸發 heap-buffer-overflow
```

**為什麼這樣設計**：觸發需要「同時滿足多層語意條件」，
這正是 CH01 所說「覆蓋率不等於語意正確性」的具體樣貌——
即使這 11 層的每一行都被覆蓋，缺少正確的**組合**也永遠不會崩潰。

### 實際找到的崩潰輸入

```
hex: 465a5a010a00c0dd4d0107cc0000000a7f
     F  Z  Z  01 0A 00 C0DD 4D ...
```

| 欄位 | 值 | 檢查 |
|---|---|---|
| 魔數 | `FZZ` | ✓ |
| 版本／型別／保留 | `01` `0A` `00` | ✓ |
| declared | `0xC0DD`（49373） | ✓ 命中 `[0xC000, 0xC0FF]` 窄窗 |
| checksum | `data[8]=0x4D` vs 計算 `0x4D` | ✓ 相符 |
| `need`（malloc 大小） | **884 bytes** | 16-bit 截斷後的結果 |
| `write_len`（實際寫入） | **16,605 bytes** | — |
| **溢位倍數** | **約 19 倍** | ← ASan 報 `heap-buffer-overflow` |

---

## 四、對照實驗結果

### 4.1 主實驗（相同 seed，公平比較）

| seed | guided | blind |
|---|---|---|
| `0x1` | ★ 第 **15,000** 次迭代（0.12 s） | 未發現（跑滿 500,000） |
| `0xABC` | ★ 第 **10,000** 次迭代（0.08 s） | 未發現（跑滿 500,000） |
| `0x9999` | ★ 第 **5,000** 次迭代（0.05 s） | 未發現（跑滿 500,000） |

**guided 命中率：3/3；blind：0/3。**

### 4.2 擴大 blind 的工作量

| 模式 | 總迭代 | exec/s | 覆蓋 guards | 首次 crash |
|---|---|---|---|---|
| guided | 500,000 | 4,948,623（崩潰前中斷） | — | **第 5,000–15,000 次** |
| blind | **2,000,000** | 817,972 | 14 / 84 | **未發現** |

**blind 跑了 4 倍工作量仍未找到。**

### 4.3 覆蓋率命中數（coverage guards）

這是本次實驗最反直覺、也最有教學價值的數據。

為了量測「崩潰瞬間的覆蓋率」，我在 `fuzz_main.c` 的
**ASan death callback** 中輸出統計（週期性輸出每 10,000 次才印一次，
但 guided 常在幾千次內就崩潰，根本來不及印）。

| seed | guided：崩潰時迭代數 | guided：崩潰時覆蓋率 | blind：相同迭代數的覆蓋率 | blind：500,000 次後覆蓋率 |
|---|---|---|---|---|
| `0x1` | 7,780 | **10 / 93** | — | **14 / 93** |
| `0xABC` | 5,899 | **10 / 93** | — | **13 / 93** |
| `0x9999` | 2,739 | **10 / 93** | — | **14 / 93** |

**核心發現：覆蓋率與「找到漏洞」是反相關的。**

| 模式 | 迭代數 | 覆蓋率 | 結果 |
|---|---|---|---|
| **guided** | 2,739 ～ 7,780 | **10 / 93（10.8%）** | ✅ **找到 crash** |
| **blind** | 500,000（多 64～182 倍） | **13–14 / 93（14–15%）** | ❌ **找不到** |

**blind 跑得多 64～182 倍、覆蓋率還更高，卻完全找不到漏洞。**

這完美印證了兩處報告論點：

1. **CH01「覆蓋率不等於語意正確性」**：blind 觸及了更多程式碼位置，
   卻沒有觸及那個「正確的條件組合」。
2. **CH03 中 Big Sleep 團隊的結論**：他們跑 150 CPU-hours 的 AFL 仍找不到
   SQLite 的漏洞，並明確指出「**程式碼覆蓋率不是可靠的引導訊號**」。
   本實驗在縮小規模上重現了同一個現象。

### 4.4 那 guided 的優勢是什麼？——不是覆蓋率，是**保留機制**

既然 guided 的覆蓋率更低，它為什麼反而能找到？差別在於**兩個層次**：

| 層次 | 作用 |
|---|---|
| **篩選標準**（coverage 是否增加） | 決定「哪些輸入值得留下」，但這只是啟發式 |
| **保留與累積**（corpus） | 把留下來的輸入當作下一輪起點 → **逐層推進條件** |

換句話說：
- blind 每次從土壤重新開始，永遠只能碰到「浅層」條件；
  **它 500,000 次累積出 14 個 guard，但那些覆蓋都不在通往漏洞的路徑上**。
- guided 只累積 10 個 guard，但**每一個都是「朝漏洞前進」的一步**
  （例如先通過魔數、再通過檢查，逐步逼近 declared 窄窗）。

> **引導的價值不在於「最大化覆蓋率」，
> 而在於「決定優先探索哪些路徑」。**
>
> 這也是為什麼 CH02.2 把 LLM 放在「seed 生成」與「mutator 學習」兩個位置——
> 那才是真正能影響「往哪裡走」的環節。

### 4.5 guided 的迭代數變異很大（重要的誠實記錄）

| seed | 首次 crash 迭代數 |
|---|---|
| `0x5EED` | 5,000 |
| `0x1` | 15,000（重測）／12,000（前次）／7,780（加入 death callback 後） |
| `0xABC` | 10,000 / 5,899 |
| `0x9999` | 5,000 / 2,739 |
| （較早的大 chunk 測試） | 182,000、176,000 |

**範圍：2,739 ～ 182,000 次迭代。** 這說明 fuzzing 的結果有**高度隨機性**，
單次實驗的數字不可當作定論——這正是為什麼 CH05 強調
「報告 benchmark 數字時必須說明 Pass@k 與變異程度」。

---

## 五、為什麼差距這麼大？（fuzzer 的核心原理）

### guided 的關鍵：保留「部分正確」的中間成果

```
隨機 mutation 命中 11 層條件的聯合機率極低，但 guided 逐層累積：

  第 1 代：某輸入通過「長度 ≥ 9」          → 有新覆蓋，存進 corpus
  第 2 代：在它基礎上，魔數變成 "F"         → 有新覆蓋，存進 corpus
  第 3 代：魔數變成 "FZ"                    → 有新覆蓋，存進 corpus
  第 4 代：魔數變成 "FZZ"                   → 有新覆蓋，存進 corpus
  ...     （checksum-aware 策略維持不變量）
  第 N 代：declared 落進 [0xC000, 0xC0FF]   → 崩潰！

每一步的「進步」都被記住，下一輪從那裡繼續。
```

### blind 的致命弱點：不保留任何中間成果

每一輪都從原始淺 seed（`""`、`"A"`、`"FZZ"`、全零…）重來。
要命中 11 層條件，等於要求**一次 mutation 就湊齊所有條件**——
機率低到 50 萬次也碰不到。

### 這正是 libFuzzer / AFL 存在的理由

| 機制 | 作用 |
|---|---|
| 覆蓋率回饋 | 保留「有新覆蓋」的輸入（guided 的核心） |
| **corpus 隊列** | 把探索成果變成下一輪的起點 |
| **in-process 執行** | 14 萬 exec/s vs Python 子行程的 30 exec/s |
| **持久化 corpus** | 跨 session 累積（本實驗未實作，見 §七） |

---

## 六、實作踩到的三個坑（本文件最有價值的部分）

### 坑 1：Python + subprocess 慢到無法做實驗

**第一版**用 Python 每輪 `subprocess.run()` 啟動 `fuzz_target.exe`：

```
執行次數      : 297（30 exec/s）
總覆蓋 guards : 6
```

**原因**：每次都要 CreateProcess + ASan runtime 載入，開銷主導一切。

**解法**：改成 **in-process**（同一行程內反覆呼叫 `check_packet()`），
這正是 libFuzzer 的核心設計：

```
Python + subprocess :     約 30 exec/s
C in-process        : 約 140,000 exec/s   ← 快 4,600 倍
```

### 坑 2：ASan 崩潰時，`signal(SIGABRT)` handler 不一定會被執行

**第一次嘗試**：安裝 `signal(SIGABRT, handler)`，在 handler 中寫出崩潰輸入。
實測結果：**exit code 3，crash.bin 完全沒產生**。
ASan 攔到錯誤後走自己的回呼並結束行程，我們的 handler 沒被叫到。

**第二次嘗試**：每次迭代前把輸入寫入檔案。
可行，但 **I/O 主導，摧毀了 in-process 的效能優勢**。

**最終解法**：用 ASan 官方回呼 `__sanitizer_set_death_callback()`：

```c
void __sanitizer_set_death_callback(void (*callback)(void));
static void on_death(void) {
    /* 只在真的崩潰時被呼叫 —— 平時零成本 */
    write_file(g_last_file, g_current, g_current_len);
}
```

**這個坑的普適教訓**：**把「記錄狀態」與「熱路徑」分離**。
不要為了「萬一崩潰」而在每一輪都付出成本。

### 坑 3：純隨機 mutation 永遠穿不過 checksum 那一層

**現象**：加上多樣 mutation 策略後，guided 的覆蓋率仍只停在 18/84 guards。

**原因**：目標有一層「`data[8]` 必須等於 `data[0..5]` 的 XOR」。
純隨機 mutation 改動標頭後 checksum 幾乎必定失效，
於是檢查**永遠停在那一層**——這是「語意相依條件」的典型樣貌。

**解法**：加入 **checksum-aware mutation**（改動標頭後自動重算 checksum）
與 **declared 欄位導向 mutation**。

**這裡有一個重要的教學點**：
> 本實驗中 guided 能找到漏洞，**部分歸功於這些「格式感知」的策略**。
> 若移除它們，guided 與 blind 都會失敗。
>
> 這正是 **LLM 能補上的位置**——理解格式語意後直接產生合法輸入，
> 而不需要人類手寫格式感知的 mutation 規則。
> 這也對應 CH02.2「AI 引導 fuzzing：seed 生成」與「mutator 學習」兩條路線。

### 坑 4（附帶）：我自己手算 checksum 算錯了

驗證「已知觸發輸入」時失敗，找了半天才發現：
我手算 `data[0..5]` 的 XOR 時**漏掉了 `data[3] = 0x01`**，
得到 `0x8C` 而不是正確的 `0x4D`。

→ **能讓程式算的就不要手算**。這也是為什麼 fuzzer 的 checksum-aware
策略是讓程式重算，而不是靠人工推導。

---

## 七、與 CH03 的對照：覆蓋率引導也有極限

本實驗看似在「證明覆盖引導很有效」，但真正的重點在於兩者的界線：

| 情境 | 覆蓋率引導是否有效 |
|---|---|
| 觸發條件是**路徑覆蓋**（走到某個分支就會崩） | ✅ 非常有效 |
| 觸發條件是**語意組合**（需湊齊多層條件） | ⚠️ 逐步累積仍可能達到，但速度大降 |
| 觸發條件需要**格式不變量**（如 checksum） | ❌ 純 mutation 永遠過不去，需格式感知 |
| 需要**外部狀態**（如跨請求的會話、時序） | ❌ fuzzer 天生不擅長 |

**Big Sleep 的 SQLite 案例落在第三與第四類之間**：
他們跑 150 CPU-hours 的 AFL 仍未發現，因為觸發需要
「`generate_series` 擴充被啟用」+「對 ROWID 下約束」的特定語意組合。
這正是他們結論「覆蓋率不是可靠的引導訊號」的實測依據。

---

## 八、未實作的部分（誠實記錄）

| 項目 | 狀態 | 說明 |
|---|---|---|
| Corpus 持久化 | ❌ 未實作 | 跨 session 累積語料（libFuzzer 的 `-merge` 機制） |
| 字典輔助 mutation | ❌ 未實作 | AFL 的 `-x dict`；本實驗以 `INTERESTING` 位元組陣列代替 |
| 真實 fork-server | ❌ 未實作 | 本實驗用 Python 重啟代替（簡化版） |
| 自訂 mutator 外掛 | ❌ 未實作 | libFuzzer 的 `LLVMFuzzerCustomMutator` |
| 多執行緒 fuzzing | ❌ 未實作 | libFuzzer 的 `-jobs` / `-workers` |
| libFuzzer 本體 | ❌ 環境限制 | MinGW target 不支援；需 MSVC 或 Linux |

---

## 九、檔案清單與複現方式

```
vuln-lab/fuzz/
├── fuzz_target.c                    # 目標（11 層巢狀檢查 + 漏洞）
├── fuzz_main.c                      # in-process fuzzer 主迴圈
├── fuzzer.py                        # Python 啟動器（編譯/統計/重啟）
└── work/
    ├── fuzz_main.exe                # 編譯產物
    ├── corpus/                      # 語料（含 guided 保留下來的項目）
    └── *.dll                        # ASan runtime（必需，少了會 exit -1073741515）

vuln-lab/findings/
├── fuzz_comparison.txt              # 對照實驗輸出
├── fuzz_crash_guided.bin            # 崩潰輸入（17 bytes）
├── fuzz_crash_guided_report.txt     # ASan 報告
└── verify_crash.py                  # 崩潰輸入驗證腳本
```

**複現**：
```powershell
# 對照實驗（自動編譯、執行、統計）
python vuln-lab/fuzz/fuzzer.py --compare --iters 2000000 --chunk 500000

# 單一模式
python vuln-lab/fuzz/fuzzer.py --mode guided --iters 500000

# 驗證崩潰輸入
python vuln-lab/findings/verify_crash.py vuln-lab/findings/fuzz_crash_guided.bin
```

---

*本文件為教育用途的學習記錄。所有測試均在本機自建靶場完成，未涉及任何未經授權的系統。*
