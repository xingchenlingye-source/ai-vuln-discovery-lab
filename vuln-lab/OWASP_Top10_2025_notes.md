# OWASP Top 10:2025 學習筆記

> 對應研究報告 **CH06 第一階段（S1：漏洞原理基礎）** 的分類體系，
> 並與本專案已完成的靶場實驗相互對照。
>
> 來源：<https://top10.owasp.org/2025/>（官方 2025 版，CC BY 3.0）

- 學習日期：2026-10-15
- 核實方式：直接抓取官方 2025 版頁面（含各分類的 CWE 對應、評分表、範例情境）

---

## 一、2025 完整清單

| # | 類別 | 與 2021 版的關係 |
|---|---|---|
| **A01** | Broken Access Control（存取控制失效） | 維持第 1 名 |
| **A02** | Security Misconfiguration（安全設定錯誤） | **↑ 從 2021 的 A05 升至第 2** |
| **A03** | **Software Supply Chain Failures（軟體供應鏈失效）** | **🆕 新類別**（2021 為「A06 易受攻擊與過時元件」） |
| **A04** | Cryptographic Failures（加密失效） | 2021 A02 → A04 |
| **A05** | Injection（注入） | **↓ 從 2021 A03 降至 A05**；合併了 XSS |
| **A06** | Insecure Design（不安全的設計） | 維持第 6 名（2021 新增） |
| **A07** | Authentication Failures（認證失效） | 2021 A07（原「識別與認證失效」） |
| **A08** | Software or Data Integrity Failures（軟體或資料完整性失效） | 維持第 8 名 |
| **A09** | Security Logging and **Alerting** Failures | 2021 為「Logging and **Monitoring**」；**改名並納入警報** |
| **A10** | **Mishandling of Exceptional Conditions（異常條件處理不當）** | **🆕 新類別**（24 個 CWE） |

### 兩個全新類別

**A03 軟體供應鏈失效**（由「已知漏洞元件」擴大）
- 社群調查中**恰好 50% 的受訪者將它排在第 1 名**
- **平均發生率最高的類別：5.19%**（官方數據）
- 範圍擴大：不只「有已知漏洞的元件」，而是**整個建置／發佈／更新流程的破壞**
- 對應 CWE：`CWE-447`（使用過時函式）、`CWE-1104`（使用無人維護的第三方元件）、`CWE-1329`（依賴無法更新的元件）、`CWE-1395`（依賴有漏洞的第三方元件）

**A10 異常條件處理不當**（全新）
- 涵蓋 **24 個 CWE**，焦點是**錯誤處理不當、邏輯錯誤、failing open**
- 官方說明：把原本歸在「poor code quality（程式碼品質不佳）」的 CWE 獨立出來，
  因為「那太籠統了」
- **三種失誤**：未預防異常狀況發生／發生時未識別／事後回應不良或未回應
- 對應 CWE（列舉重點）：`CWE-209`（錯誤訊息含敏感資訊）、`CWE-234`（未處理缺失參數）、
  `CWE-274`（權限不足處理不當）、`CWE-476`（NULL 指標解引用）、
  **`CWE-636`（Not Failing Securely / Failing Open）**、`CWE-248`（未捕捉的例外）、
  `CWE-252`（未檢查回傳值）、`CWE-369`（除以零）、`CWE-391`（未檢查的錯誤條件）、
  `CWE-484`（switch 遺漏 break）、`CWE-755`（異常處理不當）

---

## 二、與本專案實驗的直接對照（最有價值的部分）

### 2.1 我在 S3 發現的 CWE-209，現在是 OWASP Top 10 的正式類別

S3 的 LLM 審計實驗中，審計員 A **額外發現了 CWE-209（例外訊息洩漏）**，
我當時把它判定為**真陽性**（因為實際送出 `?q='` 確實回顯了 sqlite3 錯誤原文）。

**OWASP Top 10:2025 把 CWE-209 列為 A10 的首要 CWE 之一**：

> "Notable CWEs included in this category: **_CWE-209 Generation of Error Message
> Containing Sensitive Information_**..."

**這對我的實驗有兩層意義**：

1. **驗證了那項發現的價值**——它不是「低嚴重度的枝節」，而是新興 Top 10 類別的成員。
2. **也驗證了我判定它為真陽性的判斷是對的**——而非像 CWE-798/CWE-327 那樣被我判為誤報。

### 2.2 官方範例情境 #2 與我的靶場一模一樣

A10 的官方範例情境之一：

> **Scenario #2**: Sensitive data exposure via improper handling or database errors
> that reveals the full system error to the user. The attacker continues to force
> errors in order to use the sensitive system information to create a better SQL
> injection attack. The sensitive data in the user error messages are reconnaissance.

**這正是我靶場的實際情況**：
- `audit_target.py` 的 `/search` 在 SQL 錯誤時回顯原始例外（洩漏資料庫結構）
- 而 `/search` 同時有 SQL injection（A05）
- 兩者形成**「錯誤訊息洩漏 → 輔助 SQL 注入」的組合**，與官方情境完全對應

→ 我的靶場在不知情的情況下，重現了 OWASP 2025 官方舉例的攻擊鏈。

### 2.3 我的 C 靶場對應 A10 的另一個 CWE

`clab.c` 的案例 5（負索引寫入）與 Big Sleep 的 SQLite 案例，
機制上屬於 `CWE-476 NULL Pointer Dereference` 的近親（指標／索引處理不當）。
而 `CWE-476` 也被列在 A10 中。

另：`clab.c` 的案例 4（未初始化讀取）實際觸發的是整數溢位（UBSan），
也落在 A10 的 `CWE-190` 家族附近。

### 2.4 A09 改名為「Logging **and Alerting**」與我的觀察一致

A09 從 2021 的「Security Logging and Monitoring Failures」
改為 2025 的「Security Logging and **Alerting** Failures」。

這與我在 S2c/S2d 的發現相互呼應——
**日誌只是記錄，警報才是回應**。我在 fuzzer 實驗中特別實作了
「週期性 PROGRESS 輸出」與「death callback」，正是為了讓**異常狀態被即時看見**，
而不只是事後翻 log。

---

## 三、A10 的防禦原則（官方，值得記住）

官方對 A10 的「How to prevent」給出很具體的指引：

| 原則 | 說明 |
|---|---|
| **Expect the worst** | 規劃時就假設異常會發生 |
| **就地捕捉** | 在錯誤發生的**地方**處理，而非延後到高層 |
| **Fail closed（失敗即關閉）** | 交易中途出錯必須**完整回滾**，不可嘗試部分恢復 |
| **全域異常處理器** | 作為最後防線 |
| **集中化處理** | 一個應用不該有多套錯誤處理邏輯 |
| **速率限制與資源配額** | 「資訊科技裡沒有任何東西應該是無上限的」 |
| **警報與可觀測性** | 監控重複錯誤的模式（可能是攻擊徵兆） |

官方特別指出：
> "Attempting to recover a transaction part way through is often where we create
> unrecoverable mistakes."

**這個原則可以直接套用到我的 fuzzer 設計**：
我的 `on_death` callback 就是「fail closed」的實作——
崩潰時**立刻**寫出完整狀態（輸入 + 覆蓋率統計），不做部分恢復嘗試。

---

## 四、A03 供應鏈失效的實際案例（官方列舉）

| 年份 | 事件 | 意義 |
|---|---|---|
| 2019 | **SolarWinds** | 約 18,000 個組織受影響；「受信任廠商被植入惡意程式」的經典案例 |
| 2025 | **Bybit 被盜 15 億美元** | 錢包軟體的供應鏈攻擊，**只在特定錢包被使用時才執行** |
| 2025 | **Shai-Hulud**（npm 蠕蟲） | **首個成功自我傳播的 npm 蠕蟲**；用 post-install script 竊取資料並用 npm token 自動推送惡意版本，波及 **500+ 套件版本** |
| 2025 | **Glassworm / PhantomRaven** | 自我傳播的 VS Code 擴充套件與 npm 惡意套件活動 |
| 2017 | CVE-2017-5638（Struts 2 RCE） | 元件漏洞造成重大外洩 |
| 2021 | **CVE-2021-44228（Log4Shell）** | Log4j 零日 RCE；被用於勒索軟體與挖礦 |

**官方的重要觀察**：
> "by targeting developer machines it demonstrated **developers themselves are
> now prime targets** for supply chain attacks."

這與我報告 CH08 的倫理討論相呼應——
供應鏈攻擊的目標已從「生產環境」轉向「開發者機器」，
而開發者機器正是 AI coding agent 正在大量進駐的地方。

---

## 五、對本專案學習路徑的具體修正建議

原本報告 CH06 S1 建議「從 OWASP Top 10 出發」，現在應改為：

| 原本 | 修正後 |
|---|---|
| 引用 OWASP Top 10（未指定版本，實為 2021） | **明確標註 OWASP Top 10:2025** |
| 練習涵蓋 SQLi、XSS、path traversal、command injection | **新增 A01 存取控制失效**（目前靶場完全沒有） |
| 未涵蓋供應鏈 | **新增 A03 練習**：用 SBOM 工具掃描依賴、練習 staged rollout 概念 |
| 未涵蓋異常處理 | **新增 A10 練習**：強化已有的 CWE-209 案例，加入 fail-open 情境 |

### 建議的補充練習

1. **A01 存取控制失效**：在靶場加入「水平越權（IDOR）」情境——
   使用者 A 能讀取使用者 B 的資料。這是最容易實作且教學效果極強的練習。
2. **A10 fail-open**：設計一個「驗證失敗時預設允許通行」的函式，
   觀察它如何被繞過。這比 SQLi 更能訓練「邏輯漏洞」思維。
3. **A03 供應鏈**：用 `pip-audit` 或 `osv-scanner` 掃描本專案的依賴，
   體驗「自己的專案也是供應鏈的一環」。

---

## 六、更新對照表：本專案靶場 vs OWASP 2025

| OWASP 2025 類別 | 本專案已涵蓋 | 對應檔案 |
|---|---|---|
| A01 Broken Access Control | ❌ **未涵蓋** | — |
| A02 Security Misconfiguration | ⚠️ 部分（`/config` 資訊暴露已修補） | `audit/vulnapp`, `audit/audit_target.py` |
| A03 Software Supply Chain | ❌ 未涵蓋 | — |
| A04 Cryptographic Failures | ⚠️ 部分（`/hash` 弱演算法，但判為不過度推論） | `audit/audit_target.py` |
| **A05 Injection** | ✅ **充分涵蓋** | SQLi、command injection、path traversal（CWE-22 常歸此類） |
| A06 Insecure Design | ⚠️ 部分（檢查設計上的缺失） | 各靶場 |
| A07 Authentication Failures | ❌ 未涵蓋 | — |
| A08 Integrity Failures | ✅ `pickle` 反序列化（CWE-502） | `audit_target.py` `/import` |
| A09 Logging/Alerting | ⚠️ 部分（fuzzer 的 PROGRESS 與 death callback） | `fuzz_main.c` |
| **A10 Exceptional Conditions** | ✅ **涵蓋**（CWE-209 例外訊息洩漏） | `audit_target.py` 例外回顯 |

**涵蓋率：10 類中 3 類充分、5 類部分、3 類未涵蓋**（A01/A03/A07 完全沒有）。

---

## 七、參考來源

- OWASP Top 10:2025 首頁 — <https://top10.owasp.org/2025/>
- A03:2025 Software Supply Chain Failures — <https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/>
- A10:2025 Mishandling of Exceptional Conditions — <https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/>
- OWASP Top 10 GitHub（含舊版與 metadata） — <https://github.com/OWASP/www-project-top-ten>
- 授權：CC BY 3.0 Unported

---

*本文件為教育用途的學習筆記。所有內容引自 OWASP 官方 2025 版頁面。*
