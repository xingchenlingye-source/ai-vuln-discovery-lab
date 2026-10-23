# 修補對照：A01 IDOR 與 A10 fail-open

> 對應 **authlab.py** 的 6 個漏洞。每個都給出「漏洞版 → 修補版」的對照與理由。
>
> 修補驗證的兩個必要條件（見 `README.md` 第三節）：
> **① 攻擊失效　② 正常功能保留**

---

## V1 · IDOR 水平越權（A01 / CWE-639）

### 漏洞版

```python
cur.execute("SELECT id, owner_id, title, body, classified FROM documents WHERE id = ?",
            (int(doc),))
row = cur.fetchone()
# ★ 完全沒有驗證 uid 是否有權讀取 owner_id 的文件
return respond(200, row[3])
```

**問題**：只檢查「這份文件存在嗎」，沒檢查「這個人有權看嗎」。

### 修補版

```python
cur.execute("""SELECT id, owner_id, title, body, classified
               FROM documents WHERE id = ?""", (int(doc),))
row = cur.fetchone()

# 修補 1：資源不存在與無權存取回應必須一致（避免 enumeration）
if row is None:
    return respond(404, "not found")

doc_id, owner_id, title, body, classified = row

# 修補 2：明確做授權檢查
if owner_id != uid and not is_admin(uid):
    return respond(404, "not found")      # 刻意用 404，不是 403
```

**為什麼用 404 而非 403？**
`403 Forbidden` 等於告訴攻擊者「這份文件存在，只是你沒權限」——
這本身就是資訊洩漏，可用來**列舉（enumerate）**系統中有哪些資源。
業界慣例是「無權存取」與「不存在」回**同一個**回應。

### 另一種更安全的寫法（推薦）

```python
# 把授權條件直接放進查詢，查不到自然就沒有
cur.execute("""SELECT id, owner_id, title, body, classified
               FROM documents
               WHERE id = ? AND (owner_id = ? OR ? = 1)""",
            (int(doc), uid, 1 if is_admin(uid) else 0))
```

**理由**：授權邏輯與查詢合為一體，「忘记檢查」在結構上就不可能發生。
這對應報告 CH02.3 的原則：**用結構消除錯誤，而不是靠人記得檢查**。

---

## V2 · 缺省允許（A01 / CWE-862）

### 漏洞版

```python
if row is None:
    # ★ 查無資料卻回 200
    return respond(200, "查無此文件，但服務正常運作")
```

### 修補版

```python
if row is None:
    return respond(404, "not found")
```

**原則**：**預設拒絕（deny by default）**。
任何「不明確允許」的情況都應該拒絕，而不是落入「正常路徑」。

---

## V3 · 錯誤訊息洩漏（A10 / CWE-209）

### 漏洞版

```python
except Exception as e:
    return respond(500, "%s" % e)          # ★ 原始例外直接給使用者
```

### 修補版

```python
import logging, uuid
log = logging.getLogger("authlab")

except Exception as e:
    err_id = uuid.uuid4().hex[:8]
    log.exception("error_id=%s", err_id)    # 詳細內容只進內部日誌
    return respond(500, "處理失敗（錯誤代碼 %s）" % err_id)
```

**兩個重點**：
1. **使用者**只看到通用訊息 + 錯誤代碼（可據此報案，但不洩漏內部）
2. **維運者**可從日誌用 `err_id` 找到完整 traceback

這同時對應 **A09（Security Logging and Alerting Failures）**——
日誌要記，但不能記在使用者看得到的地方。

---

## V4 · 資源未釋放（A10 / CWE-460）

### 漏洞版

```python
f = open(log_path, "a")
OPEN_HANDLES += 1
f.write("...")
if mode == "bad":
    raise ValueError("模擬處理失敗")      # ★ f 沒有 close()
f.close()
```

### 修補版（try/finally）

```python
f = open(log_path, "a")
OPEN_HANDLES += 1
try:
    f.write("...")
    if mode == "bad":
        raise ValueError("模擬處理失敗")
finally:
    f.close()                              # 所有路徑都會執行
    OPEN_HANDLES -= 1
```

### 更好的寫法（with）

```python
with open(log_path, "a") as f:
    OPEN_HANDLES += 1
    try:
        f.write("...")
        if mode == "bad":
            raise ValueError("模擬處理失敗")
    finally:
        OPEN_HANDLES -= 1
# 離開 with 時自動關閉，即使拋出例外
```

**危害**：每次例外洩漏一個檔案描述子。
累積到系統上限後，服務將無法開啟任何檔案 → **DoS**。
OWASP A10 的官方範例情境 #1 描述的正是這類資源耗盡。

---

## V5 · 未檢查回傳值（A10 / CWE-252 / CWE-391）

### 漏洞版

```python
def render_profile(user_id):
    profile = load_user_profile(user_id)   # 失敗時回傳 None
    return profile[0], profile[1], profile[2]   # ★ 未檢查就索引
```

加上上層寬鬆的 `except`：

```python
try:
    name, role, key = render_profile(uid)
    ...
except Exception:
    return respond(200, "（無資料）")       # ★ 把錯誤偽裝成空資料
```

**問題**：呼叫端**無法區分**「查詢失敗」與「使用者真的沒有資料」。
這在金融、醫療等場景是嚴重問題——「餘額查詢失敗」顯示成「餘額 0」。

### 修補版

```python
def render_profile(user_id):
    profile = load_user_profile(user_id)
    if profile is None:                     # 修補 1：檢查回傳值
        raise LookupError("profile not found for uid=%s" % user_id)
    return profile[0], profile[1], profile[2]
```

```python
try:
    name, role, key = render_profile(uid)
    return respond(200, ...)
except LookupError:
    return respond(404, "找不到使用者")     # 修補 2：明確區分錯誤類型
except Exception:
    log.exception("unexpected")             # 修補 3：不吞掉未知例外
    return respond(500, "系統錯誤")
```

**三個修補缺一不可**：
- 不檢查回傳值 → 錯誤被延後到不可預期的地方
- 寬鬆 except → 錯誤被靜默吞掉
- 沒有日誌 → 錯誤永遠不會被發現（A09）

---

## V6 · fail-open 認證（A10 / CWE-636）

### 漏洞版

```python
def check_permission_fail_open(user_id, doc_id):
    try:
        con = sqlite3.connect(DB_PATH)
        ...
        return owner_id == user_id or user_id == 3
    except Exception:
        return True          # ★ fail open —— 檢查失敗就放行
```

**為什麼危險**：例外代表「**我們不知道答案**」。
把「不知道」當成「允許」，等於攻擊者只要能讓權限服務故障，就能繞過所有授權。

### 修補版

```python
def check_permission(user_id, doc_id):
    try:
        con = sqlite3.connect(DB_PATH)
        ...
        return owner_id == user_id or is_admin(user_id)
    except Exception:
        log.exception("permission check failed uid=%s doc=%s", user_id, doc_id)
        # 修補 1：fail closed —— 例外時一律拒絕
        raise PermissionError("permission service unavailable")
        # 修補 2：讓呼叫端知道是「服務故障」而非「無權限」
```

呼叫端：

```python
try:
    allowed = check_permission(uid, doc_id)
except PermissionError:
    return respond(503, "權限服務暫時無法使用")   # 明確的服務故障
if not allowed:
    return respond(404, "not found")
```

**關鍵區別**：
| 情況 | 回應 | 意義 |
|---|---|---|
| 有權限 | 200 | 允許 |
| 無權限 | 404 | 拒絕（不洩漏存在性） |
| **檢查失敗** | **503** | **服務故障，不是允許** |

OWASP A10 官方原則：
> "If you are part way through a transaction of any kind, it is extremely important
> that you roll back every part of the transaction and start again (also known as
> **failing closed**)."

---

## 修補驗證清單

| 漏洞 | 修補方式 | 驗證條件 ①（攻擊失效） | 驗證條件 ②（功能保留） |
|---|---|---|---|
| V1 IDOR | 授權條件放入查詢 / 檢查 owner_id | `?uid=1&doc=201` 回 404 | `?uid=1&doc=101` 仍回 200 |
| V2 缺省允許 | 查無資料一律 404 | `?doc=999999` 回 404 | 正常文件不受影響 |
| V3 錯誤洩漏 | 通用訊息 + 錯誤代碼 | `?doc=abc` 不含 ValueError | 錯誤仍被記錄到日誌 |
| V4 資源洩漏 | try/finally 或 with | `mode=bad` 後未釋放數為 0 | `mode=ok` 正常運作 |
| V5 靜默失敗 | 檢查回傳值 + 精確 except | `?uid=999` 回 404 | `?uid=1` 仍回資料 |
| V6 fail-open | fail closed + 拋出例外 | 服務故障時回 503 | 正常時授權判斷不變 |

---

## 三個貫穿全部漏洞的原則

1. **預設拒絕（deny by default）** — 不明確允許的一律拒絕（V1、V2、V6）
2. **失敗要說出來，但只對內部說** — 對外通用訊息，對內完整日誌（V3、V4、V5）
3. **用結構消除錯誤** — 把授權放進查詢、用 `with` 管理資源，
   而不是靠人記得檢查（V1、V4）

> 第 3 點對應報告 CH02.3：
> **「防護存在」不等於「防護生效」**——
> 最可靠的防護是讓錯誤在結構上不可能發生。

---

*本文件為教育用途的修補對照。所有測試均在本機自建靶場完成。*
