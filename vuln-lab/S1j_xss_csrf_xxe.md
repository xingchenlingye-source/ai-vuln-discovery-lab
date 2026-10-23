# S1 補充：XSS / CSRF / XXE（補足 A05 的另一半）

> 補上本專案在 **OWASP Top 10:2025 A05 Injection** 的最後缺口。
>
> 對應研究報告 **CH06 S1（學習路徑）**、**CH02.1（驗證方式配合漏洞類型）**。

- 日期：2026-10-15
- 新增靶場：`xsslab/`（5 個漏洞）
- 驗證結果：**5/5 全部通過**
- 附帶補強：**認證後 fuzzing**（`httpfuzz.py` 支援 `--cookie` / `--header`）

---

## 一、為什麼這是 A05 的另一半

本專案的 A05 覆蓋原本只有：

| 已有的 | 性質 |
|---|---|
| SQL injection | **伺服器端**注入（SQL 解析器） |
| Command injection | **伺服器端**注入（shell 解析器） |

但 A05 的另一半是**客戶端與解析器層**：

| 新增的 | 性質 | 為什麼難 |
|---|---|---|
| **XSS** | 注入到**受害者瀏覽器** | 需要瀏覽器才會執行 |
| **CSRF** | 借用受害者的**已認證身分** | 漏洞在「缺少的防護」而非「注入的內容」 |
| **XXE** | 注入到 **XML 解析器** | 取決於解析器的設定 |

---

## 二、五個漏洞與驗證結果

| # | 漏洞 | CWE | 驗證方式 | 結果 |
|---|---|---|---|---|
| 1 | **反射型 XSS** | CWE-79 | 看回應是否含**未轉義**標籤 | ✅ |
| 2 | **存儲型 XSS** | CWE-79 | **再查詢一次**確認持久化 | ✅ |
| 3 | **DOM 型 XSS** | CWE-79 | 靜態分析 sink（`innerHTML`） | ✅ |
| 4 | **CSRF** | CWE-352 | 看有沒有 token / Origin / SameSite | ✅ |
| 5 | **XXE** | CWE-611 | 看回應是否為**展開後的實體值** | ✅ |

---

## 三、五種驗證方式的差異（本靶場的核心教學點）

這是本專案第六次遇到「**不同漏洞需要不同驗證方式**」：

| 漏洞類型 | 驗證要看什麼 | 出處 |
|---|---|---|
| 注入（SQLi/CMDi） | HTTP **回應內容** | `authlab` |
| 日誌類（A09） | **日誌與告警檔案** | `loglab` |
| 競態類（A06） | **併發請求** | `buyLab` |
| 加密類（A04） | 已知值反查／重現性 | `buyLab` |
| 設定類（A02） | **回應標頭** + 允許的方法 | `configlab` |
| **反射型 XSS** | 回應中的**未轉義標籤** | **`xsslab`** |
| **存儲型 XSS** | **再查詢一次**（持久化） | **`xsslab`** |
| **DOM 型 XSS** | **執行前端 JS**（本檔用靜態分析） | **`xsslab`** |
| **CSRF** | **缺少的防護**（token/Origin/SameSite） | **`xsslab`** |
| **XXE** | **展開後的實體值** | **`xsslab`** |

### 特別值得注意的三點

**① 存儲型 XSS 必須「再查詢一次」**

```
POST /comment {text: "<script>alert('stored-xss')</script>"}  → 200
GET  /comments                                                 → payload 再次出現 ★
```

只看第一次 POST 的回應**不足以下結論**——必須確認它被**持久化**。

**這也是存儲型比反射型嚴重的原因**：不需誘導點擊，任何訪客都會中。

**② CSRF 的漏洞是「缺少防護」而非「有注入」**

驗證方式是檢查三個機制是否存在：

```
CSRF token        → 不存在 ✅（漏洞成立）
Origin 檢查       → 不檢查 ✅
Cookie SameSite   → 屬性缺席 ✅

實測：帶惡意 Origin 的轉帳請求成功，餘額 10000 → 9001
```

**③ DOM 型 XSS 的 payload「永遠不會送到伺服器」**

```
測試載荷：/#<img src=x onerror=alert(3)>
```

它只存在於 URL 的 fragment（`#` 之後）——**瀏覽器不會把 fragment 送給伺服器**。
所以這種漏洞**在伺服器日誌中完全看不到**。

> 驗證限制（誠實說明）：要 100% 確認必須**執行前端 JS**（真實瀏覽器）。
> 本檔以**靜態分析證明 sink 存在**（`location.hash` → `innerHTML`），
> 並在頁面內同時提供安全對照（`textContent`）。

---

## 四、XXE 的實測發現（重要）

### 測試結果

```
XML 內容：<!ENTITY x SYSTEM "file:///C:/Windows/win.ini"> … &x;
POST /xml  → HTTP 200；實體被展開 = True
展開內容  ：'; for 16-bit app support\n[fonts]\n[extensions]\n...'
安全對照  ：GET /xml?safe=1（resolve_entities=False）→ 展開 = False ✅
```

### 關鍵發現：標準庫其實是安全的

測試過程中我發現：

```
xml.etree.ElementTree  → ParseError: undefined entity &x;
                          （預設拒絕外部實體 → 天生沒有 XXE）
```

> **所以 XXE 不是「隨便用 XML 就會有」**。真實世界的 XXE 來自三個來源：
> 1. **第三方解析器開啟危險選項**（如 lxml 的 `resolve_entities=True`）
> 2. **舊版解析器**（預設展開實體）
> 3. **開發者為了「支援 DTD」而主動關閉防護**

本靶場用 **lxml + `resolve_entities=True, load_dtd=True`** 示範第 ① 種，
並提供 `resolve_entities=False` 的正確對照。

**這個發現的教學價值**：不要背誦「XML 有 XXE」，
而要理解「**是解析器的設定決定了有沒有 XXE**」。

---

## 五、附帶補強：認證後 fuzzing

真實目標的漏洞常位在**登入之後**——未認證的掃描只看得到登入頁。

因此為 `httpfuzz.py` 加入 session 支援：

```powershell
# 帶 Cookie
python httpfuzz.py scan http://TARGET --cookie "session=abc123; role=user"

# 帶自訂標頭（例如 JWT）
python httpfuzz.py scan http://TARGET --header "Authorization: Bearer xxx"
```

**實測輸出**：
```
==============================================================================
 ★ 認證後模式（已帶上 session）
==============================================================================
   Cookie: session=alice123; role=user
```

實作方式是把 session 標頭貫穿所有三種模式（scan / params / methods）。

---

## 六、開發時踩到的 bug（兩個，都值得記錄）

### Bug 1：`do_POST` 忘了解析 query string

```
NameError: name 'qs' is not defined
```

`do_GET` 有 `qs = parse_qs(u.query)`，但 `do_POST` 沒有，
而 XXE 處理需要讀 `?safe=1` 參數。

**症狀**：`RemoteDisconnected: Remote end closed connection without response`
——**連線被關閉、沒有回應**，而不是漂亮的錯誤訊息。

> **教訓**：`NameError` 在 HTTP handler 裡會表現為「連線中斷」。
> 看到 `RemoteDisconnected` 時，**先去看伺服器的 stderr**，
> 而不是懷疑網路或客戶端。

### Bug 2：`PAGE.format()` 與 CSS 大括號（延續上一個靶場的教訓）

在 `frontendlab` 也踩過同一個坑：`.format()` 會把 CSS 的 `{...}` 當成佔位符。

> 這次的處理方式不同——**我用 base64 包裝前端 JS**（`eval(atob(...))`），
> 徹底避開 Python 字串轉義地獄。這是一個更穩健的模式，
> 已套用到 DOM 型 XSS 的實作。

---

## 七、OWASP 涵蓋狀態（補強後）

| 類別 | 補強前 | 補強後 |
|---|---|---|
| A01 存取控制 | ✅ | ✅ ➕ CSRF（CWE-352） |
| A02 安全設定 | ✅ | ✅ |
| A03 供應鏈 | ✅ | ✅ |
| A04 加密失效 | ✅ | ✅ |
| **A05 注入** | ⚠️ 只有 SQLi/CMDi | ✅ **完整**（➕ XSS 三型、CSRF、XXE） |

**A05 現在已完整涵蓋**：
```
伺服器端：SQL injection、Command injection
客戶端  ：反射型 / 存儲型 / DOM 型 XSS
解析器  ：XXE
狀態改變：CSRF
```

---

## 八、檔案與複現

```
vuln-lab/xsslab/
├── xsslab.py              # 靶場（5 個漏洞）
├── verify_xsslab.py       # 驗證（5/5，五種不同驗證方式）
└── findings/
    └── xsslab_verification.txt
```

**複現**：
```powershell
python vuln-lab/xsslab/xsslab.py 8925
python vuln-lab/xsslab/verify_xsslab.py 8925
```

**手動練習**：
```
反射型：http://127.0.0.1:8925/search?q=<script>alert(1)</script>
存儲型：POST /comment 後 GET /comments
DOM 型：http://127.0.0.1:8925/#<img src=x onerror=alert(3)>
CSRF  ：POST /transfer → GET /me 觀察餘額
XXE   ：POST /xml（含外部實體）
```

---

## 九、本專案剩餘缺口（誠實列出）

| 缺口 | 狀態 | 說明 |
|---|---|---|
| **XSS / CSRF / XXE** | ✅ **已完成** | 本檔 |
| **認證後 fuzzing** | ✅ **已完成** | `--cookie` / `--header` |
| **真實瀏覽器自動化** | ⚠️ 未做 | DOM 型 XSS 僅以靜態分析證明 sink；100% 確認需 Playwright |
| **大型路徑字典** | ⚠️ 未引入 | 目前 31 條教學字典，實務應用 SecLists |
| **HTTP/2、WebSocket** | ❌ 未涵蓋 | 架構性限制（需專門函式庫） |

---

*本文件為教育用途的實作記錄。XSS 載荷一律為無害的 `alert()`，
不涉及竊取 cookie 或對外連線。所有測試均在本機自建靶場完成。*
