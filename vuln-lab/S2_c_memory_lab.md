# S2 實作：C 記憶體安全靶場與 sanitizer 實戰

> 本文件對應研究報告 **CH06 第一階段（S1：記憶體安全）** 與 **第二階段（S2：工具鏈）**。
>
> 這是「AI 輔助漏洞挖掘」學習路徑中最關鍵的基礎：**你必須先能自己讀懂 sanitizer 報告，
> 才有能力判斷 AI 產出的漏洞假設是真是假**。

- 演練日期：2026-10-15
- 環境：Windows + LLVM-MinGW（clang 23.1.1）+ AddressSanitizer + UndefinedBehaviorSanitizer
- 結果：**5/5 案例全數被 sanitizer 精確偵測**

---

## 一、環境建置（含三個實際踩到的坑）

### 1.1 編譯器安裝

```powershell
# LLVM 本體（提供 clang，但 Windows 上缺少 C 標準庫標頭）
winget install --id LLVM.LLVM --silent

# LLVM-MinGW UCRT（關鍵：提供 MinGW-w64 標頭與 runtime，clang 才能編譯 C）
winget install --id MartinStorsjo.LLVM-MinGW.UCRT --silent
```

**為什麼兩者都要**：`LLVM.LLVM` 的 clang 在 Windows 上的預設 target 是
`x86_64-pc-windows-msvc`，會去找 MSVC 的 `stdio.h`。若系統沒有 Visual Studio，
就會出現：

```
fatal error: 'stdio.h' file not found
```

`MartinStorsjo.LLVM-MinGW.UCRT` 是整合 MinGW-w64 的完整工具鏈，含標頭與 runtime，
target 為 `x86_64-w64-windows-gnu`，可直接編譯。

### 1.2 坑 1：ASan runtime DLL 缺失（最難診斷的一個）

第一次執行 ASan 編譯出來的程式，得到：

```
exit code: -1073741515     # 0xC0000135 STATUS_DLL_NOT_FOUND
輸出: （完全空白）
```

**沒有任何錯誤訊息**，只有一個看起來像崩潰的退出碼。用 `llvm-objdump -p` 檢查依賴才找到原因：

```
DLL Name: libclang_rt.asan_dynamic-x86_64.dll    ← 主因
DLL Name: libc++.dll                             ← ASan DLL 自己又依賴這個
DLL Name: api-ms-win-crt-*.dll
```

**解法**：把 runtime DLL 複製到 exe 同目錄，或把 MinGW 的 `bin` 加入 PATH：

```powershell
$mingw = "<winget package>\llvm-mingw-<version>-ucrt-x86_64"
$env:PATH = "$mingw\bin;$env:PATH"
# 或複製這四個 DLL 到 exe 旁：
#   libclang_rt.asan_dynamic-x86_64.dll, libc++.dll, libunwind.dll, libwinpthread-1.dll
```

**教訓**：`-1073741515` 是 Windows 上的 `STATUS_DLL_NOT_FOUND`。
遇到「無輸出 + 這個退出碼」，**直接聯想 DLL 缺失**，並用 `llvm-objdump -p` 查依賴鏈。
（注意要連依賴的依賴一起查——ASan DLL 本身還依賴 `libc++.dll`。）

### 1.3 坑 2：中文路徑讓 linker 失敗

```
ld.lld: error: cannot open output file
  C:\Users\1\.dsh\dsh_orb\請產出一份繁體中文的研究報告-...\clab.exe: No such file or directory
```

`ld.lld` 無法在含中文的路徑寫入輸出檔。**解法**：編譯到 ASCII 暫存目錄，
再把產物複製回來。

```powershell
$build = Join-Path $env:TEMP "clab_build"   # 純 ASCII 路徑
```

### 1.4 坑 3：PowerShell 把逗號當參數分隔符

```powershell
# 錯誤：PowerShell 會把 address,undefined 拆成兩個參數
& clang -fsanitize=address,undefined ...

# 正確：加引號保護
& clang "-fsanitize=address,undefined" ...
```

### 1.5 坑 4：`$ErrorActionPreference = "Stop"` 讓腳本在第一個案例就中斷

被測程式會把 ASan/UBSan 報告寫到 **stderr**。在
`$ErrorActionPreference = "Stop"` 下，PowerShell 會把「原生命令的 stderr 輸出」
視為終止性錯誤，導致自動化腳本中斷。

**這是一個很常見的自動化陷阱**：sanitizer 的輸出是**預期中的資料**，
不是腳本執行失敗。正確做法是把 `$ErrorActionPreference` 設為 `"Continue"`，
改用 `$LASTEXITCODE` 判斷執行結果。

（另外，本腳本必須以 **UTF-8 BOM** 儲存，否則 PowerShell 會用系統編碼
（Windows 繁中為 Big5）解讀，中文註解與字串全部變成亂碼並造成語法錯誤。）

---

## 二、五個案例與 sanitizer 實測結果

| # | 漏洞類型 | CWE | sanitizer 報告 | 退出碼 |
|---|---|---|---|---|
| 1 | 堆疊緩衝區溢位（off-by-one） | CWE-193 / CWE-121 | **UBSan + ASan: stack-buffer-overflow** | 1 |
| 2 | 整數截斷導致堆積溢位 | CWE-190 → CWE-122 | **ASan: heap-buffer-overflow** | 1 |
| 3 | 釋放後使用（use-after-free） | CWE-416 | **ASan: heap-use-after-free** | 1 |
| 4 | 未初始化讀取 | CWE-457 | **UBSan**（signed integer overflow 先觸發） | 0 |
| 5 | 負索引寫入（Big Sleep SQLite 機制） | CWE-787 | **UBSan + ASan: stack-buffer-underflow** | 1 |

### 2.1 案例 5 的完整 ASan 報告（最值得細讀的一個）

這個案例刻意重現 CH03 中 **Big Sleep 在 SQLite 找到的漏洞**機制
（`iColumn = -1` sentinel 未被處理，導致負索引寫入陣列）：

```
C:\...\clab.c:172:5: runtime error: index -2 out of bounds for type 'int[3]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior

==23756==ERROR: AddressSanitizer: stack-buffer-underflow on address 0x000e906ffab8
WRITE of size 4 at 0x000e906ffab8 thread T0
    #0 in case5_negative_index clab.c:172:16
    #1 in main clab.c:198:17
    #2 in __tmainCRTStartup
Address 0x000e906ffab8 is located in stack of thread T0 at offset 24 in frame
  This frame has 2 object(s):
    [32, 44) 'aIdx' (line 157) <== Memory access at offset 24 underflows this variable
    [64, 72) 'c' (line 158)
SUMMARY: AddressSanitizer: stack-buffer-underflow ... in case5_negative_index
```

**逐行解讀**：

| 欄位 | 意義 |
|---|---|
| `stack-buffer-underflow` | **向下**越界（不是 overflow）——ASan 能區分方向 |
| `WRITE of size 4` | 寫入 4 bytes（一個 `int`） |
| `#0 ... clab.c:172:16` | 精確到來源行與欄位 |
| `offset 24 ... [32, 44) 'aIdx'` | 存取位置在偏移 24，但 `aIdx` 位於偏移 32——**低於**陣列起點 |
| `<== underflows this variable` | ASan 明確指出是哪個變數被侵犯 |

**為什麼這是「零成本 debug」**：在沒有 sanitizer 的情況下，這個案例
（案例 1、4、5 也一樣）**完全不會產生任何可見錯誤**——程式會繼續跑完並印出結果，
記憶體損毀是靜默的。這正是 CH01「覆蓋率不等於語意正確性」的實體證據：
程式可達性很高，但錯誤只在非常特定的條件下才顯現，而且顯現時也沒有任何提示。

### 2.2 案例 2 的教學重點：問題不在 memcpy，而在 malloc 的參數

```
unsigned short count = 0x8000;            /* 32768，攻擊者可控 */
unsigned short bytes_needed = count * 2;  /* 0x10000 截斷成 0！ */
char *heap = malloc(bytes_needed);        /* 配置 0 bytes */
for (i = 0; i < count; i++) heap[i] = ...;/* 寫入 32768 bytes */
```

ASan 報告為 `heap-buffer-overflow`，但**根因是整數截斷**（CWE-190），
不是記憶體操作本身。這個對照正好示範為什麼報告 CH02.3 強調
「以 sanitizer 為唯一真相來源，但根因分析仍需人的推理」——
sanitizer 告訴你**哪裡**壞了，不直接告訴你**為什麼**。

### 2.3 案例 4 的誠實說明（工具限制）

案例 4 的目的是示範「未初始化記憶體讀取」（CWE-457）。但本環境只有
ASan + UBSan，**兩者都不是偵測未初始化讀取的正確工具**——
那需要 **MemorySanitizer（MSan）**，而 MSan 在 MinGW/Windows 上不支援。

實際執行時，反而是迴圈裡 `sum += arr[i]` 產生的
**signed integer overflow** 被 UBSan 抓到（因為未初始化的值是任意位元組，
湊巧造成溢位）。這是一個「工具選錯」的示範：**每個 sanitizer 有它專門的領域**。

---

## 三、Sanitizer 報告格式導讀（可直接套用到真實專案）

一份 ASan 報告包含四段，閱讀順序建議如下：

```
1) 錯誤類型與存取方向
   ==PID==ERROR: AddressSanitizer: heap-buffer-overflow / stack-buffer-underflow
   READ/WRITE of size N

2) 呼叫堆疊（#0 是最內層）
   #0 出錯的函式與行號  ← 從這裡開始看
   #1 呼叫者
   ...        ← 往上追到觸發路徑

3) 記憶體佈局（關鍵！）
   Address ... is located in <heap|stack> of thread T0 at offset N
     [32, 44) 'aIdx' <== Memory access at offset 24 underflows this variable
   → 告訴你：哪個變數、它的合法範圍、你的存取落在何處

4) Shadow memory 與圖例
   f1 = Stack left redzone（左紅區，向下越界會打到）
   f2 = Stack mid redzone
   f3 = Stack right redzone（右紅區，向上越界會打到）
   fd = Freed heap region（已釋放區域）
   fa = Heap left redzone
   → 方括號 [f1] 標出實際被存取的那一格
```

**建置建議**：開發時一律加上

```
-fsanitize=address,undefined -fno-omit-frame-pointer -g -O0
```

`-fno-omit-frame-pointer` 讓堆疊追蹤可靠，`-g` 提供行號，`-O0` 避免最佳化
把問題改寫掉（但也因此**正式環境仍可能出問題**——這是取捨）。

---

## 四、對照報告的學習路徑

| 本次實作 | 對應報告章節 | 具體收穫 |
|---|---|---|
| 五個 CWE 的實際程式與觸發條件 | CH06 S1 | 把 CWE 編號與真實崩潰訊息對應起來 |
| clang + ASan + UBSan 實戰 | CH06 S2 | 建立可重複的驗證環境 |
| 案例 5 重現 Big Sleep 機制 | CH03 | 理解「sentinel 未處理 → 負索引 → underflow」 |
| 靜默的記憶體損毀（案例 1/4/5） | CH01 | 覆蓋率不等於語意正確性 |
| sanitizer 說「哪裡」，人要說「為什麼」 | CH02.3、CH02.4 | 工具的邊界與根因分析的價值 |
| 工具選錯（案例 4 應用 MSan） | CH05 | 每個工具都有它的適用範圍 |

---

## 五、複現方式

```powershell
# 一鍵編譯並執行全部 5 個案例（自動處理上述所有環境坑）
pwsh -File vuln-lab/clab/build_clab.ps1

# 只跑特定案例
pwsh -File vuln-lab/clab/build_clab.ps1 -Case 5
```

產出：
- `findings/clab_case<N>_report.txt` — 每個案例的完整 sanitizer 報告
- `findings/clab_summary.csv` — 五個案例的總結表

---

## 六、下一步（真正的 fuzzing）

有了可編譯的 C 靶場後，可以進一步：

1. **加入 libFuzzer**：clang 內建 `-fsanitize=fuzzer,address`，可直接對
   某個函式做覆蓋率引導的模糊測試。把案例 2 的長度計算抽成函式，
   讓 fuzzer 去尋找觸發截斷的輸入。
2. **AFL++**：需另外取得，或使用 `afl-clang-fast`。
3. **對照實驗**：對同一段程式分別用 libFuzzer 與「人工構造輸入」，
   比較發現時間與覆蓋率引導是否有效——這正好是 CH03 中
   Big Sleep 團隊做的 150 CPU-hours 對照實驗的縮小版。

---

*本文件為教育用途的學習記錄。所有測試均在本機自建靶場完成，未涉及任何未經授權的系統。*
