# S1 補充練習：A02 安全設定錯誤

> 補上 **OWASP Top 10:2025 A02** 的完整實作 —— 這是本專案**最後一個「部分涵蓋」的類別**。
>
> 對應研究報告 **CH06 第一階段（S1）**、**CH02.1（發現與驗證分離）**、**CH02.4（修補驗證）**。

- 演練日期：2026-10-15
- 靶場：`configlab/configlab.py`（設定缺陷版）＋ `configlab/configlab_patched.py`（修補版）
- 驗證結果：**問題 6/6**｜**修補後攻擊失效 6/6、功能保留 5/5**

---

## 一、為什麼 A02 是最後一塊拼圖

| 面向 | 說明 |
|---|---|
| **排名** | 2025 版**從第 5 名躍升至第 2 名**——上升幅度最大的類別 |
| **性質** | 漏洞**不是「寫錯程式」，而是「設定沒做好」 |
| **涵蓋** | 本專案原本**完全沒有專門靶場**，是唯一「部分涵蓋」的類別 |

### A02 的獨特性質（本次練習最重要的洞察）

```
漏洞版與修補版的「程式邏輯幾乎相同」——差別只在設定。
```

這正是官方強調的重點：
**同一份程式碼，正確的設定就是安全的。**

這也讓 A02 的**驗證方式**與先前所有練習都不同：

| 漏洞類型 | 驗證要看什麼 |
|---|---|
| 注入類 | HTTP **回應內容**（body） |
| A09 日誌類 | **日誌檔案** |
| A06 競態類 | **併發請求** |
| A04 加密類 | 已知值反查／重現性 |
| **A02 設定類** | **回應標頭 + 允許的方法 + 端點是否存在** |

> **第五種驗證型態**——你必須讀 header，而不是讀 body。

---

## 二、六個問題

| # | 問題 | OWASP | CWE | 驗證方式 |
|---|---|---|---|---|
| C1 | **DEBUG 模式開啟**（洩漏 traceback 與檔案路徑） | A02 | CWE-489 | 檢查回應是否含 `File "...py", line N` |
| C2 | **缺少 6 個安全標頭** | A02 | CWE-693 | 讀**回應標頭** |
| C3 | **CORS 萬用字元 + credentials** | A02 | CWE-942 | 讀 `Access-Control-Allow-Origin` |
| C4 | **預設憑證未變更**（admin/admin、root/root、guest/guest） | A02 | CWE-1392 | 用預設值登入 |
| C5 | 允許危險 HTTP 方法（PUT/DELETE） | A02 | CWE-749 | 直接送 PUT |
| C6 | 設定與密鑰洩漏（AWS key、DB 密碼） | A02 | CWE-200 | 讀 `/env` |

### 驗證結果（6/6）

```
C1 DEBUG 洩漏堆疊追蹤         traceback=True，檔案路徑+行號=True
C2 缺少安全標頭               缺少 6/6，Server 暴露版本 'ConfigLab/1.0'
C3 CORS 萬用字元              ACAO='*' 且 ACAC='true'
C4 預設憑證可登入              admin:admin, root:root, guest:guest
C5 危險 HTTP 方法             PUT → 200、DELETE → 200
C6 密鑰洩漏                   AWS_SECRET_ACCESS_KEY、JWT_SECRET、
                             DATABASE_URL、STRIPE_KEY 全部明文出現
```

**C3 的組合特別危險**：`Access-Control-Allow-Origin: *` **同時** `Allow-Credentials: true`
——這讓任意外站都能代表使用者發送已認證的請求。
（註：現代瀏覽器會拒絕這個組合，但這正是它「設定錯誤」的典型樣貌，
且不同實作與舊環境的行為不一致。）

**C4 附帶發現**：錯誤訊息區分「帳號不存在」與「密碼錯誤」——
可據此**列舉有效帳號**（也連帶關聯 A07）。

---

## 三、修補實作：只改設定，不改邏輯

| 問題 | 修補方式 |
|---|---|
| C1 | `DEBUG_MODE = False`；錯誤只回**錯誤代碼**（真實例外寫 stderr） |
| C2 | 加入 6 個安全標頭；`server_version = "web"`（移除版本資訊） |
| C3 | 改用**來源白名單** `ALLOWED_ORIGINS`；不在白名單就不回 ACAO |
| C4 | 移除全部預設帳號；改用 PBKDF2 儲存；**錯誤訊息統一** |
| C5 | 實作 `do_PUT`/`do_DELETE`/`do_POST` → **405 Method Not Allowed** |
| C6 | **移除 `/env`**，改為只回 `status: ok` 的 `/health` |

### 修補後的實際標頭

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Server: web
```

### C3 修補的行為驗證

```
Origin=http://127.0.0.1:8909（白名單）    → ACAO 回傳該來源 ✓
Origin=http://evil.example.com（非白名單）→ 不回 ACAO     ✓
無 credentials: *                          ✓
```

### 修補驗證結果

```
攻擊失效 : 6/6 ✓
功能保留 : 5/5 ✓（文件讀取、文件列表、正確憑證登入、健康檢查、API 查詢）
```

---

## 四、A02 的排查方法論（可複用的清單）

本次排查建立了一份可複用的 A02 檢查清單：

| 檢查項 | 方法 |
|---|---|
| DEBUG 模式 | 觸發錯誤，看是否回 traceback |
| 安全標頭 | 讀回應 header（6 個標準標頭） |
| 版本洩漏 | 讀 `Server` / `X-Powered-By` |
| CORS | 送不同 `Origin`，觀察 ACAO |
| 預設憑證 | 嘗試常見預設組合 |
| HTTP 方法 | 送 OPTIONS，看 `Allow`；實際送 PUT/DELETE |
| 目錄列表 | 存取目錄路徑看是否列出檔案 |
| 偵錯端點 | 嘗試 `/env`、`/debug`、`/config`、`/actuator` |
| 錯誤訊息 | 觀察是否區分帳號存在性（使用者列舉） |
| 綁定位址 | 檢查是否綁 `0.0.0.0`（本專案全部綁 `127.0.0.1`） |

### 這份清單的意義（連結 AI for vulnerability discovery）

這類檢查**幾乎完全可自動化**——而且不需要「理解程式語意」：

| 面向 | AI 的價值 |
|---|---|
| 標頭檢查、方法檢查、預設憑證 | **規則式工具即可**，不需要 LLM |
| 判斷「這些設定在此業務情境下是否真的有害」 | **需要 LLM 的脈絡理解** |
| 從組態檔推斷跨服務的信任關係 | LLM 有優勢 |

> 對應報告 CH02 的論點：**架構比模型更關鍵**——
> A02 這類問題用簡單 script 就能掃，不需要動用 frontier model。
> 把 LLM 用在「需要語意理解」的地方，才是有效的資源配置。

---

## 五、OWASP Top 10:2025 最終涵蓋率

| 類別 | 狀態 |
|---|---|
| A01 存取控制失效 | ✅ 充分（水平 + 垂直越權） |
| **A02 安全設定錯誤** | ✅ **充分（本次補上，6 問題）** |
| A03 軟體供應鏈失效 | ✅ 充分（掃描 + SBOM + 簽章） |
| A04 加密失效 | ✅ 充分（6 漏洞） |
| A05 注入 | ✅ 充分 |
| A06 不安全的設計 | ✅ 充分（3 設計缺陷） |
| A07 認證失效 | ✅ 充分（7 漏洞） |
| A08 完整性失效 | ✅ 充分（pickle） |
| A09 日誌與警報 | ✅ 充分（6 缺口） |
| A10 異常條件處理 | ✅ 充分（fail-open + 6 CWE） |

**十個類別全部「充分涵蓋」**——從最初「3 類完全未涵蓋」到現在全數補齊。

---

## 六、檔案與複現

```
vuln-lab/
├── configlab/
│   ├── configlab.py                    # 設定缺陷版（6 個 A02 問題）
│   ├── configlab_patched.py            # ★ 修補版（只改設定，不改邏輯）
│   ├── verify_configlab.py             # 問題驗證（6/6，讀標頭）
│   └── verify_configlab_patched.py     # ★ 修補驗證（6/6 + 5/5）
└── findings/
    ├── configlab_verification.txt
    └── configlab_patched_verification.txt
```

**複現**：
```powershell
python vuln-lab/configlab/configlab.py 8908
python vuln-lab/configlab/verify_configlab.py 8908

python vuln-lab/configlab/configlab_patched.py 8909
python vuln-lab/configlab/verify_configlab_patched.py 8909
```

---

## 七、剩餘缺口（非 OWASP Top 10 類別，但屬深度不足）

| 缺口 | 說明 |
|---|---|
| A03 間接依賴樹 | 只掃 requirements.txt，未含 transitive dependencies |
| **A03 非對稱簽章** | 最值得補——HMAC 只做「完整性」，做不到「來源可信」 |
| A03 信任鏈 / PKI、CI 整合 | 需基礎設施（憑證、CI 環境） |
| 五種驗證型態的整合 | 目前是五個獨立靶場，尚未整合成單一自動化管線 |

---

*本文件為教育用途的練習記錄。所有測試均在本機自建靶場完成。*
