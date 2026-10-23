# S1 補充練習：A01 IDOR 與 A10 fail-open

> 補足 **OWASP Top 10:2025** 在本專案的練習缺口（見 `OWASP_Top10_2025_notes.md` §6）。
>
> 對應研究報告 **CH06 第一階段（S1：漏洞原理基礎）** 與 **CH02.1（發現與驗證分離）**。

- 演練日期：2026-10-15
- 靶場：`authlab/authlab.py`（127.0.0.1，僅本機）
- 驗證結果：**6/6 漏洞經執行確認存在**

---

## 一、為什麼要補這兩個練習

原本的靶場（`audit/`、`clab/`、`fuzz/`）涵蓋：

| OWASP 2025 | 原本涵蓋 |
|---|---|
| A05 Injection | ✅ SQLi、command injection |
| A08 Integrity Failures | ✅ pickle 反序列化 |
| A10 Exceptional Conditions | ✅ CWE-209 |

但 **A01（存取控制失效）與 A10 的核心 CWE（fail-open）完全沒有**。
而 A01 是 **2025 版排名第 1** 的類別，A10 是**全新類別**——
兩者都是「注入類」之外的重要思維訓練。

**為什麼這兩個特別值得練**：

| | 注入類（SQLi/XSS） | A01 IDOR | A10 fail-open |
|---|---|---|---|
| 性質 | **語法**問題（輸入被當成指令） | **邏輯**問題（少了一個檢查） | **邏輯**問題（例外處理方向錯了） |
| 防禦 | 參數化、轉義 | 授權判斷 | fail closed |
| fuzzer 能否找到 | ✅ 常可（有 crash 訊號） | ❌ **幾乎不可能**（回應仍是 200） | ⚠️ 難（需觸發例外情境） |

> **最後一列是關鍵**：IDOR 與 fail-open **沒有 crash、沒有 sanitizer 訊號**。
> 這正是為什麼報告 CH05 說「AI 能找 0day」需要區分漏洞類型——
> 對這類邏輯漏洞，**可執行驗證的方式完全不同**（要比對「授權前後的行為差異」，
> 而不是等程式崩潰）。

---

## 二、靶場設計

### 2.1 六個漏洞

| # | 漏洞 | OWASP | CWE | 觸發方式 |
|---|---|---|---|---|
| V1 | IDOR 水平越權 | **A01** | CWE-639 | `?uid=1&doc=201`（alice 讀 bob 的文件） |
| V2 | 缺省允許 | **A01** | CWE-862 | `?doc=999999`（不存在的文件回 200） |
| V3 | 錯誤訊息洩漏 | A10 | CWE-209 | `?doc=abc`（回顯原始例外） |
| V4 | 資源未釋放 | A10 | CWE-460 | `?mode=bad`（例外路徑不關檔） |
| V5 | 未檢查回傳值 | A10 | CWE-252 / CWE-391 | `?uid=999`（失敗偽裝成空資料） |
| V6 | **fail-open 認證** | A10 | **CWE-636** | 權限服務故障時放行 |

### 2.2 模擬 session 的簡化

真實系統用 cookie/token，本靶場用 `?uid=` 模擬「已登入使用者」。
**這是刻意的簡化**：練習重點在**授權判斷**，不是 session 管理。
（這也是為什麼 V7「認證失效」不在本靶場範圍。）

---

## 三、驗證結果（6/6）

驗證腳本 `verify_authlab.py` 對每個漏洞要求**可觀察證據**：

```
V1 IDOR 水平越權     A01/CWE-639   ✅ HTTP 200 + FLAG{idor_read_bob_private_document}
V2 缺省允許          A01/CWE-862   ✅ 不存在的文件回 HTTP 200
V3 錯誤訊息洩漏      A10/CWE-209   ✅ 回應含 ValueError: invalid literal
V4 資源未釋放        A10/CWE-460   ✅ 例外路徑後未釋放計數 > 0
V5 未檢查回傳值      A10/CWE-252   ✅ 失敗回 HTTP 200 顯示「無資料」
V6 fail-open 認證    A10/CWE-636   ✅ 服務故障時回傳 True（放行）
```

**V6 的驗證方式值得說明**：它無法透過 HTTP 觸發（需要讓資料庫故障），
因此驗證腳本改用**單元級測試**——把 `DB_PATH` 指向不存在的路徑，
直接呼叫 `check_permission_fail_open()`，確認它回傳 `True`。

> 這示範了報告 CH02.1 的原則：**驗證方式要配合漏洞類型**。
> 注入類可用 HTTP 觸發；fail-open 需要**製造故障情境**才能觀察。

---

## 四、A03 供應鏈練習

### 4.1 工具缺口與替代

本環境**沒有** `osv-scanner`、`pip-audit`、`trivy`、`grype`。
因此自製 `scan_deps.py`，直接查詢 **OSV API**（`https://api.osv.dev/v1/query`）。

### 4.2 掃描結果

對 `requirements-vulnerable.txt`（8 個刻意選用歷史漏洞版本的套件）：

| 套件 | 版本 | 漏洞數 |
|---|---|---|
| Django | 2.2.0 | **75** |
| urllib3 | 1.24.1 | **26** |
| cryptography | 2.6.1 | 21 |
| Jinja2 | 2.10.1 | 10 |
| requests | 2.19.0 | 10 |
| lxml | 4.3.0 | 10 |
| PyYAML | 5.1 | 6 |
| Flask | 1.0 | 4 |

**合計：162 個漏洞，8/8 套件有漏洞（100%）**

### 4.3 這個練習的教學價值

1. **「有漏洞的依賴」不是罕見情況**——本清單 100% 命中。
   真實專案因版本較新，比例較低，但**間接依賴**常是盲區。
2. **Django 2.2.0 有 75 個漏洞**——這說明了為什麼「版本落後」是 A03 的核心風險。
3. **可自動化**：掃描只是查 API，可以放進 CI 每日執行。
4. **官方建議對照**：OWASP A03 的可行動項目中，本練習涵蓋
   「持續清查依賴版本」與「監控 OSV/CVE/NVD」兩項。

### 4.4 未涵蓋的 A03 面向（誠實記錄）

| 面向 | 為何未涵蓋 |
|---|---|
| SBOM 生成 | 需專門工具（CycloneDX/SPDX） |
| 簽章驗證 | 需 PKI 環境 |
| Staged rollout / canary | 需部署環境 |
| 間接依賴清查 | 需完整安裝依賴樹（本練習只掃 requirements.txt） |
| CI/CD 強化 | 需 CI 環境 |

---

## 五、與報告的連結

| 本次練習 | 對應章節 | 收穫 |
|---|---|---|
| IDOR 的「少一個檢查」 | CH01、CH06 S1 | 邏輯漏洞與語法漏洞的差異 |
| IDOR 不能被 fuzzer 找到 | CH05 | 為什麼漏洞類型決定驗證方式 |
| fail-open 的「方向錯了」 | CH06 S1、OWASP A10 | 例外處理是安全控制，不是錯誤處理 |
| 修補的「結構性」寫法 | CH02.3 | 「防護存在」≠「防護生效」 |
| 用單元測試驗證 fail-open | CH02.1 | 驗證方式必須配合漏洞類型 |
| 依賴掃描自動化 | CH04、OWASP A03 | 供應鏈清查是可自動化的工作 |

---

## 六、檔案與複現

```
vuln-lab/
├── authlab/
│   ├── authlab.py              # 靶場（6 個漏洞）
│   ├── verify_authlab.py       # 驗證腳本（確定性裁判）
│   └── PATCH_GUIDE.md          # ★ 修補對照（6 組漏洞版 → 修補版）
└── supplychain-lab/
    ├── requirements-vulnerable.txt  # 8 個歷史漏洞版本
    ├── scan_deps.py                 # 自製 OSV 掃描器
    └── scan_result.json             # 掃描結果
```

**複現**：
```powershell
# A01 / A10
python vuln-lab/authlab/authlab.py 8901
python vuln-lab/authlab/verify_authlab.py 8901

# A03
cd vuln-lab/supplychain-lab
python scan_deps.py requirements-vulnerable.txt
```

---

## 七、下一步建議

1. **加入「修補版」可執行檔**（目前只有 `PATCH_GUIDE.md` 的程式碼對照）——
   建立 `authlab_patched.py` 並用同一支驗證腳本確認 0/6。
2. **A07 認證失效**——目前完全未涵蓋，可加入「弱密碼策略」「session 固定」等情境。
3. **A01 垂直越權**——本次只做水平越權（同層級），可加入「使用者提升為 admin」。
4. **把依賴掃描放進 CI**——體驗官方建議的「持續清查」。

---

*本文件為教育用途的練習記錄。所有測試均在本機自建靶場完成，未涉及任何未經授權的系統。*
