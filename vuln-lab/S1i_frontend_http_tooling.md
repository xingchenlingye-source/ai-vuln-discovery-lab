# S1 補充：完善「前端觀察能力」與「HTTP 層工具鏈」

> 補上兩項能力缺口（來自 Bilibili SRC 課程架構分析的發現）。
>
> 對應研究報告 **CH06 S1/S2（學習路徑與工具鏈）**、**CH02.1（可觀察性）**、**CH03（fuzzing 的訊號問題）**。

- 日期：2026-10-15
- 新增靶場：`frontendlab/`（6 類前端線索）
- 新增工具：`httpfuzz.py`（黑箱 HTTP fuzzer）
- 驗證結果：**前端邏輯 5/5**｜**HTTP 掃描發現 5 端點 + 1 隱藏參數**

---

## 一、兩個缺口為何是缺口

先前本專案的所有靶場都是**我自己寫的 Python 後端**——
所以「我能直接讀原始碼」。但真實系統有兩個本專案無法訓練的能力：

| 缺口 | 為什麼本專案的靶場教不了 |
|---|---|
| **讀 JS / 看前端** | 我的靶場沒有前端——弱點都寫在後端，直接看得見 |
| **HTTP 層工具鏈** | 我有 C/C++ fuzzer，但那需要**原始碼 + 插樁**；真實目標是黑箱 |

---

## 二、缺口 1：前端邏輯靶場（FrontendLab）

### 2.1 設計理念

> **頁面上看到的 ≠ 系統實際支援的。**

靶場刻意把「**可觀察性**」當成主題——六類線索全部藏在 `/static/app.js` 裡，
必須用瀏覽器開發者工具（F12 → Sources / Network）才能發現。

### 2.2 六類線索

| # | 線索 | CWE | 藏在哪裡 |
|---|---|---|---|
| J1 | **JS 註解洩漏內部 API 路徑** | CWE-540 | `// FIXME: admin 後台端點 /api/admin/users 還沒有加權限檢查` |
| J2 | **前端硬編碼加密金鑰** | CWE-321 | `var ENC_KEY = "s3cr3t-frontend-key-2026"` |
| J3 | **隱藏參數** | CWE-472 | `PRODUCT_META` 含 `internal_cost`、`hidden_discount` |
| J4 | **未授權的隱藏 API** | CWE-862 | `/api/admin/users`（無任何權限檢查） |
| J5 | **前端加密可被逆向** | CWE-602 | `encryptPayload()` 與金鑰都在前端 |
| J6 | **原始碼洩漏測試環境** | CWE-489 | `APP_CONFIG.env = "staging"`、`version`、`buildDate` |

### 2.3 驗證方式（模擬真實滲透測試的第一步）

驗證腳本 `verify_frontendlab.py` **不讀後端原始碼**，
完全模擬攻擊者的資訊收集流程：

```
步驟 ①  取得 /static/app.js
步驟 ②  靜態分析：找註解、硬編碼常數、端點、參數
步驟 ③  用找到的線索實際呼叫 API
步驟 ④  確認後端確實沒有防護
```

### 2.4 實測結果

**步驟 ② 靜態分析的實際發現**：

```
找到註解 3 條，洩漏的 API 路徑：
    /api/admin/users, /api/checkout, /api/debug/config, /api/v2/checkout
找到硬編碼金鑰：s3cr3t-frontend-key-2026
找到環境資訊：env=staging, version=2.4.1-beta, buildDate=2026-04-10
找到隱藏參數／旗標：
    internal_cost, hidden_discount, allowPriceOverride (feature flag)
```

**步驟 ③④ 用線索攻擊的結果（5/5）**：

| 驗證項 | 結果 |
|---|---|
| J1+J4 註解洩漏路徑 + 未授權 admin API | ✅ `GET /api/admin/users` → 200 + 使用者清單 |
| J2+J6 debug 端點洩漏硬編碼金鑰 | ✅ 端點回傳的金鑰與 JS 常數**完全一致** |
| J3 隱藏參數外洩 | ✅ `?internal=1` → 內部成本 |
| J5 前端加密可被逆向 | ✅ 自行加密 `price=1`（原價 5000）被接受 |
| 額外：未授權價格覆寫端點 | ✅ `POST /api/admin/price` → 200 |

### 2.5 最核心的觀念

> **前端的一切都可被使用者看見與修改。**
> 所以**前端的加密、驗證、隱藏欄位都不是安全機制**——
> 它們只是「讓事情看起來比較難」。

具體到 J5：我用**從 JS 找到的金鑰與 XOR 演算法**，
自行產生了一份「合法」的加密請求，把 5000 元的商品改成 1 元，**後端照單全收**。

---

## 三、缺口 2：HTTP 層工具鏈（httpfuzz.py）

### 3.1 兩類 fuzzing 的根本差異（本節最重要的收穫）

| | `fuzz_v2`（本專案） | `httpfuzz`（本檔） |
|---|---|---|
| 目標 | C/C++ **記憶體安全** | Web **應用邏輯** |
| 觀測方式 | **白箱**（插樁） | **黑箱**（只看回應） |
| 訊號 | **crash**（ASan） | **回應差異** |
| 覆蓋率回饋 | ✅ `trace-pc-guard` | ❌ **無法取得** |
| 速度 | **14 萬 exec/s** | 每秒數十個請求 |
| 需要人工判斷 | 低（crash 很明確） | **高**（差異要解讀） |
| 誤判率 | 極低 | **高**（雜訊多） |

### 3.2 三種模式與實測結果

#### 模式 1：端點探索

```
基準線（不存在的路徑）：GET /this-path-should-not-exist-9x8y7z → 404, 26 bytes

掃描結果：
  /api/admin/users     200   303 bytes  ★FLAG     ← 隱藏端點
  /api/debug/config    200   266 bytes  ★FLAG     ← 隱藏端點
  /api/product         200    30 bytes
  /api/cart            200   150 bytes
  /static/app.js       200  2883 bytes
```

#### 模式 2：參數 fuzzing

```
基準線：GET /api/product?id=1 → 200, 30 bytes

測試隱藏參數（29 條 × 10 值）：
  internal=1    200   181 bytes  ★FLAG   (Δ+151)
```

**這個結果與缺口 1 互相驗證**：JS 中洩漏的 `internal_cost` 欄位，
對應到後端的 `internal` 參數——**前端提供假設，fuzzing 負責驗證**。

#### 模式 3：HTTP 方法探測

```
GET      200     30 bytes
POST     404     26 bytes
PUT      501    356 bytes
DELETE   501    359 bytes
PATCH    501    358 bytes
OPTIONS  501    360 bytes
HEAD     501      0 bytes
TRACE    501    358 bytes
```

**教學點：501 vs 405**

| 狀態碼 | 意義 |
|---|---|
| **501** Not Implemented | 伺服器**不支援這個方法**（這裡是 Python `BaseHTTPRequestHandler` 的預設行為） |
| **405** Method Not Allowed | 伺服器支援該方法，但**這個資源不允許**（正確的做法） |

本專案 `configlab_patched.py` 用的是 **405**（正確），
而 `frontendlab.py` 走的是 501（預設行為、非刻意）——
**這個對比本身就是教材**。

### 3.3 黑箱 fuzzing 的困難（誠實說明）

本工具的判定邏輯只有「狀態碼 + 長度 + 內容雜湊」可比：

```
· 200 可能是真實端點，也可能是 SPA 的 catch-all 回首頁
· 404 頁面長度各不相同 → 長度差異不代表有新內容
· 重導向、壓縮、快取都會改變長度
· 動態內容（時間戳、隨機值）造成誤報
· 無效參數被靜默忽略 → 漏報
```

> **對比**：本專案的 `fuzz_v2` 有 ASan crash 這個**明確、低誤判**的訊號。
> 這就是為什麼**白箱（有覆蓋率）比黑箱（只有回應差異）可靠得多**——
> 也解釋了為什麼 CH03 引用 Big Sleep 團隊「覆蓋率不是可靠引導訊號」時，
> 那仍然是在**白箱前提下**的批評；黑箱的訊號品質更差。

### 3.4 安全閘門（必須記錄）

工具內建限制：

```python
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

def check_target(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        # ⛔ 拒絕執行，並說明原因
```

**為什麼有這個限制**：HTTP fuzzing 會送出大量請求。
對未授權目標執行，可能構成騷擾、服務中斷，且法律上屬未授權存取。

---

## 四、兩個缺口合併使用的價值

```
前端（JS 分析）  →  提供「假設」
                      ↓
HTTP fuzzing     →  負責「驗證」
```

**實測驗證了這個組合**：

| 前端線索 | HTTP fuzzing 驗證 |
|---|---|
| JS 註解提到 `/api/admin/users` | 掃描確認該端點存在且回 200 |
| JS 註解提到 `/api/debug/config` | 掃描確認該端點存在且洩漏金鑰 |
| `PRODUCT_META` 含 `internal_cost` | 參數 fuzzing 確認 `?internal=1` 有效 |

> 這與本專案 CH02.2 的原則一致：
> **LLM 該放在「產生假設」與「理解語意」的位置**，
> 而驗證則交給可執行的工具。

---

## 五、OWASP 涵蓋影響

| 類別 | 補強前 | 補強後 |
|---|---|---|
| **A01 存取控制** | 水平 + 垂直越權 | ➕ **未授權隱藏 API**（前端洩漏路徑） |
| **A02 安全設定** | 6 項設定缺陷 | ➕ **debug 端點未關閉** |
| **A04 加密失效** | 6 漏洞 | ➕ **前端硬編碼金鑰**（CWE-321） |
| **A05 注入** | SQLi / command injection | ⚠️ 仍缺 XSS / CSRF / XXE |

**新增的獨特價值**：本專案首次訓練了「**只靠前端資訊找弱點**」的能力——
這是先前所有靶場都無法提供的。

---

## 六、檔案與複現

```
vuln-lab/frontendlab/
├── frontendlab.py            # 靶場（後端 + 前端 JS，6 類線索）
├── verify_frontendlab.py     # 驗證（模擬只讀 JS 的攻擊者視角，5/5）
├── httpfuzz.py               # ★ HTTP 層 fuzzer（黑箱，3 種模式）
└── findings/
    ├── frontendlab_verification.txt
    └── httpfuzz_scan.txt
```

**複現**：
```powershell
# 啟動靶場
python vuln-lab/frontendlab/frontendlab.py 8920

# 驗證前端邏輯（只讀 JS）
python vuln-lab/frontendlab/verify_frontendlab.py 8920

# HTTP 層 fuzzing
python vuln-lab/frontendlab/httpfuzz.py scan    http://127.0.0.1:8920
python vuln-lab/frontendlab/httpfuzz.py params  http://127.0.0.1:8920/api/product?id=1
python vuln-lab/frontendlab/httpfuzz.py methods http://127.0.0.1:8920/api/product?id=1
```

**手動練習**（最推薦）：開瀏覽器 → `http://127.0.0.1:8920/` → **F12** →
Sources 找 `app.js`，按著 §2.2 的六類線索自己找一遍。

---

## 七、開發時踩到的 bug（值得記錄）

啟動靶場時出現 `KeyError: 'font-family'`。

**原因**：`PAGE.format(body=...)` 的模板中，**CSS 的大括號沒有轉義**。

```python
PAGE = """<style>body{font-family:...}</style>..."""
                    ↑ .format() 把 {font-family:...} 當成佔位符
```

**修正**：CSS 的 `{` `}` 必須寫成 `{{` `}}`。

> **教訓**：用 `str.format()` 產生 HTML/CSS/JS 時，
> **所有字面大括號都要轉義**。而且這個 bug 會**延遲到第一次請求才爆發**
> （模組載入時不會報錯），所以「伺服器啟動成功」不等於「服務可用」——
> **必須實際送一個請求才算驗證完成**。

---

## 八、剩餘缺口（誠實列出）

| 缺口 | 狀態 |
|---|---|
| **XSS / CSRF / XXE** | ❌ 仍缺（A05 的另一半） |
| 真實瀏覽器自動化驗證 | ❌ 未做（需 Playwright/Selenium） |
| 大型路徑字典（SecLists） | ❌ 未引入（本工具用 31 條教學字典） |
| HTTP/2、WebSocket 層 | ❌ 未涵蓋 |
| 認證後的 fuzzing（帶 session） | ⚠️ 部分（本工具無 session 管理） |

---

*本文件為教育用途的實作記錄。所有測試均在本機自建靶場完成，
HTTP fuzzer 內建主機白名單，僅允許 127.0.0.1 / localhost。*
