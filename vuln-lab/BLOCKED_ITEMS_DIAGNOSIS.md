# 未能執行項目之診斷報告

> 本文記錄 `README.md` 第七節標示為「未執行」的兩個項目**為何無法執行**，
> 以及經實測後確認的可行替代路徑。
>
> 診斷時間：2026-10-15（VPN 接入後、clang 安裝完成後）
> 環境：Windows + LLVM-MinGW UCRT（clang 23.1.1）+ LLVM 23.1.3（MSVC target）

---

## 摘要

| 項目 | 狀態 | 根本原因 |
|---|---|---|
| 把靶場接上 fuzzing（libFuzzer） | **阻塞** | `-fsanitize=fuzzer` 不支援 `x86_64-w64-windows-gnu` target |
| 練習 harness 生成 | **可執行，未執行** | 非技術阻塞，僅為工作量排序（待辦） |

**核心發現**：Windows 上的防禦性編譯環境，**記憶體安全的 sanitizer 可用，
但 fuzzing 工具鏈不可用**。這是一項真實的環境限制，且在 CH06 的學習路徑上
構成一個具體的取捨點——值得記錄下來，因為它是「工具鏈選擇」的實例教材。

---

## 一、libFuzzer 不可用的完整原因

### 1.1 直接錯誤

```powershell
clang "-fsanitize=fuzzer,address" -O1 -o probe.exe probe.c
```

```
clang-23: error: unsupported option '-fsanitize=fuzzer' for target 'x86_64-w64-windows-gnu'
```

### 1.2 sanitizer 支援矩陣（實測結果）

以 `-fsanitize=<name>` 逐一編譯測試程式，結果如下：

| sanitizer | MinGW target (`x86_64-w64-windows-gnu`) | 說明 |
|---|---|---|
| `address`（ASan） | ✅ **可用** | 記憶體錯誤偵測，本靶場主力 |
| `undefined`（UBSan） | ✅ **可用** | 未定義行為偵測 |
| `memory`（MSan） | ❌ 不支援 | 未初始化讀取偵測——**案例 4 的缺憾** |
| `thread`（TSan） | ❌ 不支援 | 資料競爭偵測 |
| `leak`（LSan） | ❌ 不支援 | 記憶體洩漏偵測 |
| `fuzzer`（libFuzzer） | ❌ 不支援 | **本項阻塞的主因** |
| `coverage` | ❌ 不支援 | 覆蓋率回饋（libFuzzer 的基礎） |

### 1.3 為什麼不支援？（三層原因）

**第一層：clang driver 的 target 限制**

libFuzzer 是一個**與平台 runtime 深度綁定**的 engine，需要：
- 覆蓋率回饋（SanitizerCoverage 插樁）
- 訊號處理與 crash 捕捉
- 程序內部的 mutation loop

這些都需要對應平台的 runtime 支援。clang 的 driver 對
`x86_64-w64-windows-gnu`（MinGW）明確拒絕 `-fsanitize=fuzzer`。

**第二層：runtime 檔案其實存在，但 target 不匹配**

實測發現 libFuzzer 的靜態函式庫**確實存在於磁碟上**：

```
<minGW>\lib\clang\23\lib\windows\libclang_rt.fuzzer-x86_64.a
<minGW>\lib\clang\23\lib\windows\libclang_rt.fuzzer_no_main-x86_64.a
<minGW>\lib\clang\23\lib\windows\libclang_rt.fuzzer_interceptors-x86_64.a
<LLVM>\lib\clang\23\lib\windows\clang_rt.fuzzer-x86_64.lib
```

→ 這些是 **MSVC ABI** 的 runtime（`.lib` 為 MSVC 格式）。
它們無法與 MinGW 的 GNU ABI 目標連結。
這解釋了為什麼「檔案在，但選項被拒」——**不是缺檔案，是 ABI 不匹配**。

**第三層：MSVC target 需要 Visual Studio**

理論上可改用 MSVC target（`x86_64-pc-windows-msvc`）搭配上述 `.lib`，
但那需要 Visual Studio 的 C 執行期與標頭檔。實測確認：

```
clang.exe (C:\Program Files\LLVM\bin\clang.exe) -fsanitize=fuzzer ...
   → fatal error: 'stdio.h' file not found
```

系統上沒有 MSVC 工具鏈（只有 .NET SDK），因此 MSVC target 也走不通。

### 1.4 已確認的替代方案與其可行性

| 方案 | 可行性 | 說明 |
|---|---|---|
| MSVC target + libFuzzer | ❌ | 需安裝 Visual Studio Build Tools（數 GB），且需接受其授權 |
| AFL++ | ❌ | 未安裝；Windows 上需 WSL 或先行編譯，本環境無 WSL |
| honggfuzz | ❌ | 未安裝；同樣以 Linux 為主要支援平台 |
| atheris（Python libFuzzer） | ❌ | 專案已停止維護，且需 libFuzzer 支援 |
| **自製 coverage-guided fuzzer** | ✅ **已驗證可行** | 見 §1.5——`trace-pc-guard` 可用 |
| **純 mutation fuzzer（無覆蓋率）** | ✅ | 最簡版本，可示範 AFL 的核心迴圈 |

### 1.5 關鍵發現：`trace-pc-guard` 可用（覆蓋率引導之路未被完全封死）

這是本次診斷最重要的發現。libFuzzer 的 driver 選項被拒，
**但它底層依賴的覆蓋率插樁機制其實是可用的**：

| 選項 | 結果 |
|---|---|
| `-fsanitize-coverage=trace-pc` | ❌ 不支援 |
| `-fsanitize-coverage=inline-8bit-counters` | ❌ 不支援 |
| **`-fsanitize-coverage=trace-pc-guard`** | ✅ **可用** |
| `-fprofile-instr-generate` | ✅ 可用 |
| `--coverage` | ✅ 可用 |

實測以自訂的 `__sanitizer_cov_trace_pc_guard` / `__sanitizer_cov_trace_pc_guard_init`
回呼函式編譯成功並執行——**這正是 libFuzzer 內部使用的同一套機制**。

**意義**：雖然不能直接用 libFuzzer 的 driver，但可以用這套插樁
**自行實作一個 coverage-guided fuzzer**（AFL 的 forkserver 模式在概念上相同）。
換句話說，阻塞的是「現成的 fuzzer 引擎」，不是「覆蓋率引導的能力」。

**更新後的結論**：路徑 A 不只是「勉強可行」，而是**可以做出真正具備
覆蓋率回饋的 fuzzer**，足以複現 CH03 中「覆蓋率引導 vs 盲目 mutation」的對照實驗。

---

## 二、這項限制的教學價值（不只是障礙）

這個「不能用」的結果，其實正好示範了報告中兩個重要論點：

### 2.1 對應 CH06 S2「工具鏈」：工具選擇本身是一門技術

學習路徑中列出「fuzzer、靜態分析、debugger、sanitizer」，
但實務上**每個工具有它的平台限制與 ABI 限制**。
「裝了 clang 就有 libFuzzer」是錯的假設——這正是本次診斷的價值。

### 2.2 對應 CH03「Big Sleep 的 150 CPU-hours 對照實驗」

Big Sleep 團隊為了驗證「fuzzing 為何找不到該 bug」，特地跑了
150 CPU-hours 的 AFL。**若沒有可用的 fuzzer，這個對照實驗就無法複現**。
本診斷說明了為什麼在 Windows + MinGW 環境下複現該實驗會遇到障礙，
以及為什麼實務研究者常直接使用 Linux 容器（對應 CH04 的 OSS-Fuzz 生態）。

### 2.3 對應 CH05「能力邊界」：工具不足會限制可驗證性

案例 4（未初始化讀取，CWE-457）需要 **MSan**，而 MSan 在 MinGW 不支援。
這使得該案例的驗證只能退而求其次（觀察到的是 UBSan 的整數溢位，
而非 MSan 的 use-of-uninitialized-value）。
**工具的缺口直接限制了你能證明什麼**——這是 CH05「benchmark 與真實世界落差」
在工具層面的另一種表現。

---

## 三、建議的可行路徑

### 路徑 A：自製輕量 fuzzer（推薦，立即可行）

用 Python 寫一個 mutation fuzzer，量測：

1. **隨機 mutation** 對案例 2（整數截斷）需要多少次才能命中觸發條件
2. **有覆蓋率引導**（用 clang 的 `-fprofile-instr-generate` 或
   `--coverage`，若可用）與**無引導**的差異
3. 對照 Big Sleep 的結論：「覆蓋率不是可靠的引導訊號」

需要先確認 clang 的覆蓋率插樁選項在 MinGW target 是否可用。
**已驗證結果（見 §1.5）**：`-fsanitize-coverage=trace-pc-guard`、`-fprofile-instr-generate`、
`--coverage` 三者皆可用，因此**可以做出真正具備覆蓋率回饋的 fuzzer**，
而不只是盲目的 mutation。這讓 CH03 的對照實驗（覆蓋率引導 vs 盲目 mutation）得以複現。

### 路徑 B：改用 MSVC 工具鏈

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools \
  --override "--add Microsoft.VisualStudio.Workload.VCTools --quiet"
```

體積大（數 GB）、時間長，但可完整取得 libFuzzer。
**若目標是長期做 C/C++ fuzzing 練習，這是正解；若只是本次練習，不建議。**

### 路徑 C：改用 Linux 容器

Docker 未安裝（前次已確認）。若安裝 Docker Desktop，
即可使用官方 `oss-fuzz` 或 `aflplusplus` 映像檔，
這是最接近 CH03／CH04 真實研究環境的做法。

---

## 四、harness 生成練習（另一項未執行）

此項**沒有技術阻塞**。純粹因為：

1. 它是報告 CH06 S3 練習 5 的內容，已在 S3 的 LLM 審計實驗中以
   「以 `evaluate_llm_audit.py` 當裁判」的形式部分涵蓋
2. 前幾輪的優先順序是「先建立可驗證的環境」（S1/S2），
   harness 生成屬於後續的 S3 深化

**判定：待辦事項，非阻塞。**

---

## 五、結論

| 項目 | 判定 |
|---|---|
| libFuzzer 不可用 | **環境硬限制**（MinGW ABI + 無 MSVC），已完整診斷 |
| 案例 4 的 MSan | 同樣是環境硬限制 |
| harness 生成 | 非阻塞，僅為待辦 |

**這份診斷本身的價值**：它把「工具不可用」從一句模糊的「未執行」
變成可複現、可解釋、有替代方案的工程判斷。這正是報告 CH05 強調的
——**誠實記錄限制，比宣稱完成更有價值**。

---

*本文件為教育用途的環境診斷記錄。所有測試均在本機執行，未涉及任何外部系統。*
