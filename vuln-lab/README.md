# VulnLab 演練記錄：五個漏洞的完整挖掘流程

> **本文件對應報告 CH06 S1／S2 的實作驗收端，以及 CH02.1「發現與驗證分離」的具體示範。**
>
> 倫理聲明：本演練全程只對 `127.0.0.1` 上**自己撰寫的靶場**送出請求，未接觸任何真實外部目標。
> 所有 payload 皆為觸發驗證用途，未執行任何外連、持久化或破壞性操作。

- 演練日期：2026-10-15
- 靶場版本：`vulnapp_v1.py`（漏洞版） vs `patched/vulnapp_v2.py`（修補版）
- 執行環境：Python 3.12.14（bundled）；無 C 編譯器、無 Docker
- 驗證結果：**漏洞版 5/5 觸發；修補版 0/5 觸發，且正常功能 5/5 保留**

---

## 一、五個漏洞總表

| 編號 | 漏洞 | CWE | 端點 | Source（輸入） | Sink（危險操作） |
|---|---|---|---|---|---|
| V1 | SQL Injection | CWE-89 | `/search?q=` | query string | 字串拼接 → `cursor.execute` |
| V2 | Reflected XSS | CWE-79 | `/hello?name=` | query string | 字串格式化 → HTML 回應 |
| V3 | Path Traversal | CWE-22 | `/file?file=` | query string | `os.path.join` → `open()` |
| V4 | OS Command Injection | CWE-78 | `/ping?host=` | query string | `subprocess(shell=True)` |
| V5 | Insecure Deserialization | CWE-502 | `/import?d=` | base64 字串 | `pickle.loads` |

五者的共同結構是：**使用者可控輸入 → 未經處理 → 進入危險 sink**。這正是 CH01 提到的「資料流思維」——漏洞幾乎都不是「某一行寫錯」，而是<strong>一條橫跨多層的資料流失去了邊界</strong>。

---

## 二、逐項根因分析（Root Cause Analysis）

### V1 · SQL Injection — CWE-89

**觸發輸入**
```
GET /search?q=' OR '1'='1
```

**實際結果**：回傳全部使用者資料，並外洩 admin 的機密 → `FLAG{sql_injection_revealed_admin_secret}`

**根因**

```python
sql = "SELECT id, username, role, secret FROM users WHERE username = '%s'" % term
cur.execute(sql)          # ← 問題：輸入被當成「SQL 語法」而非「資料」
```

資料庫引擎無法區分「程式設計師寫的 SQL」與「使用者輸入的字串」——兩者在拼接後已經是同一個字串。

**修補（v2）**

```python
sql = "SELECT id, username, role, secret FROM users WHERE username = ?"
cur.execute(sql, (term,))  # 參數化：輸入永遠是資料，不可能改變語法結構
```

**為什麼這是正確的修法**：`sqlite3` 的參數化（prepared statement）會在協定層把查詢與參數分開傳送，資料庫在解析階段就已經決定了查詢結構，輸入無法參與解析。這比「過濾引號」的黑名單作法可靠得多（黑名單永遠有繞過方式：編碼、註解、`LIKE`、二階注入等）。

**CWE 對照**：CWE-89 Improper Neutralization of Special Elements used in an SQL Command

---

### V2 · Reflected XSS — CWE-79

**觸發輸入**
```
GET /hello?name=<script>alert(1)</script>
```

**實際結果**：回應中出現**原樣未轉義**的 `<script>alert(1)</script>`

**根因**

```python
body = "<h2>/hello</h2><p>Hello, %s!</p>" % name   # ← 未做 HTML 編碼
```

瀏覽器無法區分「網站要顯示的文字」與「網站要執行的腳本」——兩者在回應中都是 HTML 原始碼。

**修補（v2）**

```python
body = "<h2>/hello</h2><p>Hello, %s!</p>" % html.escape(name)
# 輸出後變成 &lt;script&gt;alert(1)&lt;/script&gt; —— 顯示為文字，不執行
```

**結構性修法**：更根本的作法是使用會**自動轉義**的樣板引擎（Jinja2 autoescape、Django templates），讓「忘記轉義」在框架層級就不可能發生。手動 `html.escape` 的風險是：新增輸出點時容易漏掉。

**CWE 對照**：CWE-79 Improper Neutralization of Input During Web Page Generation

---

### V3 · Path Traversal — CWE-22

**觸發輸入**
```
GET /file?file=../SECRET_FOR_LAB.txt
```

**實際結果**：讀到沙箱**之外**的機密檔 → `FLAG{path_traversal_escaped_the_sandbox}`

**根因**

```python
path = os.path.join(LAB_ROOT, fname)   # ← 看似安全，其實 ../ 會直接生效
open(path)                              # os.path.join 不會阻止向上跳脫
```

這是初學者最常誤解的一點：`os.path.join` **只負責連接路徑片段**，它不做任何安全檢查。當 `fname` 以 `../` 開頭時，`join` 的結果會被推回上層目錄。

**修補（v2）—— 兩道防線**

```python
# 防線 1：白名單驗證檔名格式（拒絕 / \ .. 等字元）
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_\-]+\.(txt|md|log)$")
if not SAFE_FILENAME.match(fname):
    return refuse()

# 防線 2：正規化後確認仍在允許的根目錄之下
path = os.path.realpath(os.path.join(LAB_ROOT, fname))
if not (path == LAB_ROOT or path.startswith(LAB_ROOT + os.sep)):
    return refuse()
```

**為什麼需要兩道**：
- 只做字串檢查（防線 1）會被**編碼繞過**（`%2e%2e%2f`）或**作業系統差異**繞過（Windows 的 `\` 與 `..\`、8.3 短檔名）。
- 只做 `realpath` 檢查（防線 2）在**符號連結（symlink）**情境下需要小心，且必須用 `realpath` 而非 `abspath`（後者不解析 symlink）。
- 兩者並用才同時涵蓋「格式異常」與「語意越界」兩種情況。

**實務補充**：最安全的作法是**根本不用使用者提供的檔名**，而是用一個對照表（`{"readme": "readme.txt"}`），只允許查表命中。這樣連檔名解析都不需要信任。

**CWE 對照**：CWE-22 Improper Limitation of a Pathname to a Restricted Directory

---

### V4 · OS Command Injection — CWE-78

**觸發輸入**
```
GET /ping?host=127.0.0.1 & echo INJECTION_MARKER_12345
```

**實際結果**：回應中出現我們自己插入的 `INJECTION_MARKER_12345`——證明 `&` 之後的內容被 shell 當成**第二個指令**執行。

**根因**

```python
cmd = "ping -n 1 " + host
subprocess.run(cmd, shell=True, ...)   # ← shell=True 讓輸入參與指令解析
```

`shell=True` 會把整串字串交給 `/bin/sh`（Windows 為 `cmd.exe`）解析。這意味著 `&`、`|`、`;`、`` ` ``、`$()` 等**shell 元字元**全都會被賦予語法意義。

**修補（v2）—— 三層防禦**

```python
# 1. 格式白名單
if not SAFE_HOST.match(host): return refuse()
# 2. 語意驗證（真的是合法 IP）
ipaddress.ip_address(host)
# 3. 參數陣列 + shell=False（完全不經 shell）
subprocess.run(["ping", "-n", "1", host], shell=False, ...)
```

**最關鍵的是第 3 層**：`shell=False` 加上參數陣列後，`"127.0.0.1 & echo x"` 會被當成**一個完整的參數**傳給 `ping`（而 `ping` 會因為參數不合法而失敗），shell 元字元完全失去意義。前兩層則是縱深防禦（defense in depth）。

**CWE 對照**：CWE-78 Improper Neutralization of Special Elements used in an OS Command

---

### V5 · Insecure Deserialization — CWE-502

**觸發輸入**：`GET /import?d=<base64 of malicious pickle>`

**實際結果**：`pickle.loads` 執行期間觸發了我們預期的程式碼，產生標記檔 → `FLAG{insecure_deserialization_code_executed}`

**根因**

```python
obj = pickle.loads(raw)   # ← pickle 在反序列化時會「執行」還原物件的指令
```

`pickle` 的設計本質是「**還原任意 Python 物件**」。為了做到這件事，它允許 payload 指定要呼叫的函式與參數（透過 `__reduce__`）。因此 `pickle.loads` 對不可信資料而言，等同於 `eval`。

**修補（v2）**

```python
obj = json.loads(d)   # JSON 只能表達資料（字串/數字/陣列/物件），無法表達「行為」
```

JSON 的資料模型不包含「呼叫函式」這個概念，因此**在語言層級就不可能**造成程式碼執行。若業務上必須用 pickle（例如傳輸 numpy 陣列或自訂類別），則必須加上：
1. **簽章驗證**（`hmac`）——確認資料來自可信來源；
2. **來源白名單**與完整性檢查；
3. 隔離的解析環境。

**CWE 對照**：CWE-502 Deserialization of Untrusted Data

---

## 三、修補驗證的兩個必要條件

本次演練刻意同時檢查兩個條件，這是 CH02.4 強調的重點：

| 條件 | 檢查方式 | 本次結果 |
|---|---|---|
| **條件 1：攻擊失效** | 對 v2 重跑 `verify_findings.py` | ✅ 0/5 觸發（全部攻擊輸入失效） |
| **條件 2：功能保留** | 對兩版跑 `functional_test.py` | ✅ 5/5 正常功能可用 |

**為什麼條件 2 同樣重要**：最偷懶的「修補」是把功能整個關掉（直接回 403、註解掉端點），這樣條件 1 一定通過，但程式已經沒有用了。這在真實修補審查中必須被擋下。

---

## 四、本次演練實際踩到的四個坑（最有價值的部分）

> CH05 強調「AI 的輸出必須經過外部驗證」。以下四個問題**全部都是自動化流程的真實除錯過程**，比順利跑完更有學習價值。

### 坑 1：`8080` 埠被 Steam 佔用，靶場根本沒啟動

**現象**：驗證腳本回傳 `HTTP Error 404: Not Found`，但同時 `Invoke-WebRequest http://127.0.0.1:8080/` 卻回傳 HTTP 200。

**誤判風險**：看到 200 就以為「伺服器正常」，但那個 200 其實來自 Steam 的 CEF remote debugging 頁面。

**真正原因**（讀 `srv_err.log` 才發現）：
```
PermissionError: [WinError 10013] 以一种访问权限不允许的方式做了一个访问套接字的尝试。
```
`8080` 已被 `steamwebhelper`（PID 30768）佔用，我的靶場 `bind()` 失敗後**進程直接結束**。

**教訓**：
- **HTTP 200 不代表「你的服務」在回應**——一定要驗證回應**內容特徵**（本次加了 `VulnLab` 字樣檢查）。
- **一定要看伺服器的 stderr**，不要只看客戶端的錯誤。
- 換到空閒埠（8765／8766）即解決。

### 坑 2：Python 檔案被 CRLF 換行符破壞，出現語法錯誤

**現象**：`SyntaxError: unterminated string literal (detected at line 128)`

**原因**：我寫入的檔案中，某個長字串在編輯過程中真的被換行了，引號未閉合。

**教訓**：產生多行字串時要小心；錯誤訊息給的**行號是準確的**，直接讀那幾行就能定位。

### 坑 3：`pickle` payload 跨模組失敗——本次最重要的技術收穫

**現象**：本地測試 `pickle.loads` 成功，但送到伺服器後標記檔沒產生。

**伺服器回傳的真實錯誤**：
```
Can't get attribute '_w' on <module '__main__' from '...\vulnapp_v1.py'>
```

**根因**：`pickle` **只儲存「函式／類別的完整匯入路徑」，不儲存程式碼本體**。我在 `verify_findings.py`（模組名 `__main__`）定義 payload 類別，但伺服器端的 `__main__` 是 `vulnapp_v1.py`——兩邊的 `__main__` 不是同一個模組，所以找不到 `_write_marker`。

**解法**：payload 只依賴**兩端都存在**的標準函式庫符號。改用 `builtins.eval` 搭配純字串運算式後，在任何 Python 直譯器上都能成功反序列化。

**這個坑的深層意義**：它正好示範了 CH02.1 的核心主張——「**發現與驗證必須分離**」。如果我只看「本地測試通過」就宣稱漏洞存在，就會產生一個**誤報**。是伺服器端的確定性錯誤訊息把我拉回現實的。

### 坑 4：我自己設計的測試斷言產生誤判（false positive）

**現象**：功能測試回報「V3 正常讀檔 = BROKEN」，看起來是修補造成功能回歸。

**真正原因**：我的斷言是「回應中要包含字串 `sandbox`」（因為 v1 會回顯檔案路徑）。但 **v2 刻意不再回顯伺服器路徑**——這本身是**正確的安全設計**（避免資訊洩漏），卻讓我的斷言失效。

**修正**：斷言改為檢查**檔案的實際內容**（`這是沙箱內的公開檔案`），而非路徑字串。

**教訓**：**測試本身也會說謊**。當測試結果與預期不符時，要先懷疑斷言，再懷疑程式。這個坑與 CH05「benchmark 與真實世界的落差」是同一類問題——**量測方式決定了你看見什麼**。

---

## 五、對應到報告的學習路徑

| 本次演練內容 | 對應報告章節 |
|---|---|
| CWE 分類、資料流思維、五個漏洞原理 | CH06 S1 |
| 執行驗證、修補、回歸測試、閱讀伺服器日誌 | CH06 S2 |
| 「發現與驗證分離」的實作 | CH02.1 |
| 修補的兩個驗收條件 | CH02.4 |
| 幻覺／誤報的實際體感（坑 3） | CH05.1 |
| 量測方式影響結論（坑 4） | CH05.4 |
| 只在自建靶場練習、payload 只做無害驗證 | CH08.3、CH08.4 |

---

## 六、後續擴充（已執行）

### 6.1 C 編譯器安裝（**已成功**）

首次嘗試（無 VPN）失敗，記錄於 `findings/llvm_install_failed.txt`：

```
退出碼: -2147012867 (0x80072EFD ERROR_INTERNET_CANNOT_CONNECT)
下載 https://github.com/llvm/.../LLVM-23.1.3-win64.msi 時 InternetOpenUrl() failed
```

**接入 VPN 後重試成功**，最終安裝：

| 套件 | 用途 |
|---|---|
| `LLVM.LLVM` 23.1.3 | clang 本體 |
| `MartinStorsjo.LLVM-MinGW.UCRT` | MinGW-w64 標頭與 runtime（Windows 上編譯 C 的關鍵） |

驗證結果：**ASan 與 UBSan 完整可用**。

### 6.2 S2 實作：C 記憶體安全靶場（clab/）

詳見 **`S2_c_memory_lab.md`**。五個案例全部被 sanitizer 精確偵測：

| # | 漏洞 | CWE | sanitizer 報告 |
|---|---|---|---|
| 1 | 堆疊 off-by-one | CWE-193 / CWE-121 | UBSan + **ASan: stack-buffer-overflow** |
| 2 | 整數截斷導致堆積溢位 | CWE-190 → CWE-122 | **ASan: heap-buffer-overflow** |
| 3 | use-after-free | CWE-416 | **ASan: heap-use-after-free** |
| 4 | 未初始化讀取 | CWE-457 | UBSan（**工具選錯示範**：應為 MSan） |
| 5 | 負索引寫入（Big Sleep SQLite 機制） | CWE-787 | UBSan + **ASan: stack-buffer-underflow** |

**案例 5 是本靶場最有價值的一個**——它重現了 CH03 中 Big Sleep 的漏洞機制，
ASan 明確報出 `stack-buffer-underflow`、指出 offset 24 低於 `aIdx` 的 `[32, 44)`、
並標註 `<== Memory access at offset 24 underflows this variable`。

**四個環境坑（皆已寫入腳本自動處理）**：
1. ASan runtime DLL 缺失 → `exit code -1073741515`，**且完全無錯誤訊息**（用 `llvm-objdump -p` 追依賴鏈才找到，且 ASan DLL 自己還依賴 `libc++.dll`）
2. 中文路徑讓 `ld.lld` 無法寫入輸出 → 編譯到 ASCII 暫存目錄
3. PowerShell 把 `-fsanitize=address,undefined` 的逗號當參數分隔符 → 需加引號
4. `$ErrorActionPreference="Stop"` 讓 sanitizer 的 stderr 被當成腳本錯誤 → 改為 `Continue`，並用 `$LASTEXITCODE` 判斷

### 6.3 S3 實作：以確定性裁判量測 LLM 審計準確率

詳見 **`S3_llm_audit_evaluation.md`**。摘要：

| 審計員（prompt 策略） | Recall | Precision | 漏報 | 誤報 |
|---|---|---|---|---|
| A 自由審計 | 83% | 100% | F6 | 無 |
| B 變體分析 | 83% | 100% | F6 | 無 |
| C CWE 清單掃描 | 83% | **56%** | F6 | 4 項 |
| D 嚴格審查（逐項實測） | **100%** | **100%** | 無 | 無 |

**五項關鍵發現**：
1. **「同一 CWE 的第二個出現點」是最主要漏報來源**——三位審計員都只報了 `/hello` 的 XSS，沒人發現 `/hash?v=` 也有同樣問題（呼應 Big Sleep 選擇變體分析的理由）。
2. **誤報不是幻覺，而是過度推論與重複計數**（設計情境誤判、清單誘導、與既有 finding 重疊）。
3. **清單式 prompt 有系統性偏差**——C 對 10 項中的 9 項給出 `present=true`，且 `uncertain` 為 0（不確定性被清單壓力吸收）。
4. **「端點安全」與「參數漏洞」是正交維度**——B 正確判定 algo 白名單安全，卻在 `v` 參數上失手。
5. **誘餌奏效但只騙到部分人**——`is_valid_name()` 是死代碼，A/C/D 都正確指出它未被呼叫。

**最重要的一段**：裁判腳本自己曾對 F4（pickle）給出**假陰性**——原因是標記檔
路徑指向不存在的目錄。這正是 CH05 的具體樣貌：**誤報與漏報都可能來自量測方式，
而不是來自目標本身**。詳見 S3 報告第四節。

---

## 七、原始建議的下一步

> 以下為最初的四項建議，執行狀態已標註。

1. ~~**補上 C/C++ 記憶體安全練習**~~ → **已完成**（VPN 接入後取得 clang，見 `S2_c_memory_lab.md`）。
2. ~~**加入 LLM 環節（CH06 S3）**~~ → **已完成**：見 `S3_llm_audit_evaluation.md`。
3. ~~**把靶場接上 fuzzing**~~ → **已完成**（見 `S2b_fuzzer_experiment.md`）。
   環境限制的診斷見 `BLOCKED_ITEMS_DIAGNOSIS.md`（libFuzzer 在 MinGW target 不支援），
   但 `-fsanitize-coverage=trace-pc-guard` 可用，因此**自製了 in-process
   coverage-guided fuzzer**，並完成對照實驗：
   **guided 在 5,000–15,000 次迭代找到 crash；blind 跑滿 500,000 次找不到。**
3b. ~~**提升 fuzzer 命中率**~~ → **已完成**（見 `S2c_fuzzer_improvement.md`）。
   實作 edge coverage + hit count 分桶 + 格式感知 mutation，並做 ablation 實驗。
   **結果：中位迭代 7,177 → 591（快 12.1 倍）**；但兩個發現與直覺相反：
   「格式感知 mutation」才是決定成敗的關鍵（無它時命中率 100% → 33%），
   而我加入的「字典」反而讓效能變差 **2.6 倍**（因為字典與目標實際需求不匹配）。
4. **練習 harness 生成**（未執行，**非阻塞**）：屬 S3 深化項目，
   已在 S3 實驗中以「`evaluate_llm_audit.py` 當裁判」部分涵蓋。

---

## 八、檔案清單

```
vuln-lab/
├── S3_llm_audit_evaluation.md     # ★ S3 實驗報告：以裁判量測 LLM 審計準確率
├── S2_c_memory_lab.md             # ★ S2 實作報告：C 記憶體安全 + sanitizer 實戰
├── S2c_fuzzer_improvement.md      # ★ S2c 命中率優化：實測與反直覺發現
├── S2c_selfcheck.md               # ★ S2c 自檢：可重現性複驗
├── S2d_hitrate_instability.md     # ★ S2d 根因：命中率為何不穩定
├── S2e_hitrate_statistics.md      # ★ S2e 統計：命中率與波動量測
├── OWASP_Top10_2025_notes.md      # ★ OWASP Top 10:2025 學習筆記與靶場對照
├── S1b_owasp_gap_practice.md      # ★ S1b 練習：A01 IDOR + A10 fail-open + A03 供應鏈
├── S1c_a09_logging_alerting.md    # ★ S1c 練習：A09 日誌與警報（6 缺口 + 修補）
├── S1d_a04_a06_practice.md        # ★ S1d 練習：A04 加密失效 + A06 不安全設計
├── S1e_a02_config_practice.md     # ★ S1e 練習：A02 安全設定錯誤（10/10 完成）
├── S1f_gap_fixes.md               # ★ S1f 缺口修復：A03 深度 + 驗證管線 + CI
├── S1g_cve_2020_1747_reproduction.md  # ★ S1g 真實案例：CVE-2020-1747 本地複現
├── S1h_bilibili_src_course.md     # ★ S1h 學習筆記：SRC 漏洞挖掘課程架構分析
├── S1i_frontend_http_tooling.md   # ★ S1i 補強：前端觀察 + HTTP 層工具鏈
├── S1j_xss_csrf_xxe.md            # ★ S1j 補強：XSS / CSRF / XXE（A05 完整）
├── S1k_bilibili_src_course2.md    # ★ S1k 學習筆記：SRC 課程 84 集架構分析
├── S1l_ssrf.md                    # ★ S1l 補強：SSRF（課程最大模組）
├── S1m_remaining_gaps.md          # ★ S1m 補全：剩餘 7 類缺口（7/7）
├── S1n_env_limits_and_oss.md      # ★ S1n 補全：帳號接管/短信/盲打 + 開源資源評估
├── S2c_lfi_crypto_labs.md         # ★ S2c 補強：LFI（5/5）+ XOR/known-plaintext（6/6）
├── S2e_blind_sqli_lab.md          # ★ S2e 補強：無回饋盲注（布林 4/4 + time-based）
├── S2f_blind_benchmark.md         # ★ S2f 效能：盲注加速實測（7.0×–12.4×）
├── S2h_phplab_php_specific.md     # ★ S2h 補強：四類 PHP 特有漏洞（真實 PHP 8.3）
├── S3a_five_gaps_labs.md          # ★ S3a 補強：五缺口（ECB/Perl×3/PHAR）9/9
├── memlab.py                      # 記憶體安全機制模擬（純 Python，備援教材）
├── targets/
│   ├── vulnapp_v1.py          # 漏洞版靶場（5 個 CWE）
│   ├── sandbox/readme.txt     # 沙箱內公開檔案
│   ├── SECRET_FOR_LAB.txt     # 沙箱外機密檔（供 path traversal 驗證）
│   └── lab.db                 # SQLite 練習資料庫
├── patched/
│   └── vulnapp_v2.py          # 修補版靶場（5 項修補對照）
├── clab/                      # ★ S2 C 記憶體安全靶場（真 clang + sanitizer）
│   ├── clab.c                 # 5 個記憶體安全 CWE 的實作
│   └── build_clab.ps1         # 一鍵編譯與執行（自動處理 DLL 與路徑問題）
├── fuzz/                      # ★ S2b 自製 coverage-guided fuzzer（v1）
│   ├── fuzz_target.c          # 目標（11 層巢狀檢查 + 漏洞）
│   ├── fuzz_main.c            # in-process fuzzer 主迴圈（14 萬 exec/s）
│   ├── fuzzer.py              # Python 啟動器（編譯／統計／重啟）
│   └── work/                  # 建置產物與 corpus
├── fuzz_v2/                   # ★ S2c 命中率優化版（edge + bucket + 格式感知）
│   ├── fuzz_target.c          # 加入 edge coverage 量測
│   ├── fuzz_main.c            # v2 主迴圈（hit bucket + 字典 + 格式感知）
│   └── benchmark.py           # v1/v2 對照與 ablation 實驗
├── authlab/                   # ★ S1b 靶場（A01 / A10 / A07）
│   ├── authlab.py             # 漏洞版（V1 IDOR、V2 缺省允許、V3 錯誤洩漏、V4 資源洩漏、V5 靜默失敗、V6 fail-open）
│   ├── authlab_patched.py     # ★ 修補版（6 個漏洞全修）
│   ├── authlab2.py            # ★ A07 認證失效 + A01 垂直越權（7 個漏洞）
│   ├── verify_authlab.py      # 漏洞版驗證（6/6）
│   ├── verify_patched.py      # ★ 修補驗證（攻擊失效 6/6 + 功能保留 6/6）
│   ├── verify_authlab2.py     # ★ A07 驗證（7/7）
│   └── PATCH_GUIDE.md         # ★ 修補對照（6 組漏洞版 → 修補版）
├── ecblab/                    # ★ S3a ECB block splicing（4/4）
├── perllab/                   # ★ S3a Perl 三缺口（真實 Perl 5.42.3 CGI，3/3）
├── pharlab/                   # ★ S3a PHAR 反序列化（真實 PHP 8.3，2/2）
├── phplab/                    # ★ S2h PHP 特有漏洞（真實 PHP 8.3.35）
│   ├── phplab.php             # 弱比較/strcmp陣列/反序列化/LogPoisoning/SQL截斷
│   └── verify_phplab.py       # 驗證（6/6）
├── blindlab/                  # ★ S2e 盲注靶場（無回饋情境）
│   ├── blindlab.py            # B1 布林盲注 / B2 time-based / B3 錯誤洩漏 / 安全對照
│   ├── bench_blind.py         # ★ 效能基準（序列 vs 並發，7.0×–12.4×）
│   └── verify_blindlab.py     # 驗證（4/4，自動化盲注破解）
├── lfllab/                    # ★ S2c LFI 靶場（路徑穿越/過濾繞過/php://filter）
│   ├── lfllab.py              # 5 種手法 + 安全對照
│   └── verify_lfllab.py       # 驗證（5/5）
├── cryptolab/                 # ★ S2c 加密學靶場（XOR/known-plaintext）
│   ├── cryptolab.py           # 4 種漏洞 + HMAC/CSPRNG 對照
│   └── verify_cryptolab.py    # 驗證（6/6）
├── accountlab/                # ★ S1n 三服務靶場：帳號接管/短信/盲打
│   ├── accountlab.py          # 主應用 8940 + SMS閘道 8941 + 盲打平台 8942
│   └── verify_accountlab.py   # 驗證（9/9，跨三服務）
├── webvulnlab/                # ★ S1m 整合靶場：7 類缺口
│   ├── webvulnlab.py          # 文件上傳/CORS/SSTI/CRLF/重定向/JSONP/未授權
│   └── verify_webvulnlab.py   # 驗證（7/7，七種不同驗證方式）
├── ssrflab/                   # ★ S1l 靶場：SSRF（雙埠：主應用 + 內部服務）
│   ├── ssrflab.py             # 靶場（5 種 SSRF 手法 + 安全對照）
│   └── verify_ssrflab.py      # 驗證（6/6）
├── xsslab/                    # ★ S1j 靶場：XSS / CSRF / XXE（A05 的另一半）
│   ├── xsslab.py              # 靶場（反射/存儲/DOM XSS、CSRF、XXE）
│   └── verify_xsslab.py       # 驗證（5/5，五種不同驗證方式）
├── frontendlab/               # ★ S1i 前端邏輯靶場（補足「讀 JS」缺口）
│   ├── frontendlab.py         # 靶場（6 類前端線索藏在 app.js）
│   ├── verify_frontendlab.py  # 驗證（只讀 JS 的攻擊者視角，5/5）
│   └── httpfuzz.py            # ★ HTTP 層 fuzzer（黑箱，3 種模式）
├── cve-lab/                   # ★ S1g 真實 CVE 複現（CVE-2020-1747）
│   ├── cve_2020_1747_test.py      # 多版本 × 多載荷初步掃描
│   ├── cve_2020_1747_compare.py   # 5.3 vs 5.3.1 精確對比
│   └── cve_2020_1747_proof.py     # 可執行證明
├── run_all.py                 # ★ 統一驗證管線（整合五種驗證型態，9 靶場）
├── ../.gitignore              # ★ 排除私鑰與產物（金鑰管理紀律）
├── .github/workflows/         # ★ CI：supply-chain-ci.yml + dependency-watch.yml
├── configlab/                 # ★ S1e 靶場：A02 安全設定錯誤
│   ├── configlab.py           # 設定缺陷版（C1 DEBUG、C2 缺標頭、C3 CORS、C4 預設憑證、C5 危險方法、C6 密鑰洩漏）
│   ├── configlab_patched.py   # ★ 修補版（只改設定，不改邏輯）
│   ├── verify_configlab.py    # 問題驗證（6/6，讀回應標頭）
│   └── verify_configlab_patched.py  # ★ 修補驗證（6/6 + 5/5）
├── buyLab/                    # ★ S1d 靶場：A06 不安全設計 + A04 加密失效
│   ├── buyLab.py              # 漏洞版（B1 限購繞過、B2 TOCTOU、B3 客戶端定價、B4 MD5、B5 弱隨機、B6 明文卡號）
│   ├── buyLab_patched.py      # ★ 修補版（原子操作 + 唯一約束 + 伺服器定價 + PBKDF2 + CSPRNG + 加密儲存）
│   ├── verify_buylab.py       # 漏洞驗證（6/6，含並發測試）
│   └── verify_buylab_patched.py  # ★ 修補驗證（攻擊失效 6/6 + 功能保留 4/4）
├── loglab/                    # ★ S1c 靶場：A09 日誌與警報失效
│   ├── loglab.py              # 漏洞版（L1 不記錄、L2 無審計、L3 明文密碼、L4 無告警、L5 可清除、L6 無關聯ID）
│   ├── loglab_patched.py      # ★ 修補版（結構化 JSON 日誌 + 告警門檻 + 遮罩 + request_id）
│   ├── verify_loglab.py       # 漏洞驗證（6/6）
│   └── verify_loglab_patched.py  # ★ 修補驗證（缺口補上 6/6 + 功能保留 4/4）
├── supplychain-lab/           # ★ S1b 供應鏈練習（A03）
│   ├── requirements-vulnerable.txt  # 8 個歷史漏洞版本套件
│   ├── scan_deps.py           # 自製 OSV API 掃描器
│   └── sbom.py                # ★ SBOM 生成 + 雜湊清單 + 簽章驗證
├── audit/                     # ★ S3 盲審實驗
│   ├── audit_target.py        # 盲審目標（5 個植入漏洞 + 1 個隱藏點 + 誘餌）
│   └── evaluate_llm_audit.py  # 確定性裁判（量測 Recall / Precision）
└── findings/
    ├── verification_result.txt     # 漏洞版驗證輸出（5/5 觸發）
    ├── verification_patched.txt    # 修補版驗證輸出（0/5 觸發）
    ├── functional_result.txt       # 功能回歸測試（5/5 保留）
    ├── llm_audit_evaluation.txt    # ★ S3 裁判輸出（4 位審計員準確率）
    ├── clab_case1..5_report.txt    # ★ S2 sanitizer 完整報告
    ├── clab_summary.csv            # ★ S2 五案例總結表
    ├── fuzz_comparison.txt         # ★ S2b 對照實驗輸出
    ├── fuzz_crash_guided.bin       # ★ S2b 崩潰輸入（17 bytes）
    ├── fuzz_crash_guided_report.txt # ★ S2b ASan 報告
    ├── verify_crash.py             # 崩潰輸入驗證腳本
    ├── memlab_output.txt           # 記憶體模擬輸出
    └── llvm_install_failed.txt     # 首次安裝失敗記錄（無 VPN 時）
```

**啟動方式**
```powershell
# 漏洞版
python vuln-lab/targets/vulnapp_v1.py 8765
# 修補版
python vuln-lab/patched/vulnapp_v2.py 8766
# 驗證
python vuln-lab/verify_findings.py 8765 vulnerable
python vuln-lab/verify_findings.py 8766 patched
```

---

*本文件為教育用途的學習記錄。所有測試均在本機自建靶場完成，未涉及任何未經授權的系統。*
