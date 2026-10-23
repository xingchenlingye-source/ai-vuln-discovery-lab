# 貢獻指南

感謝你有興趣貢獻！本專案是**教學用的漏洞研究實驗室**，目標是讓學習者能在安全、
可重現的環境中理解漏洞原理。

---

## 最重要的規則

### 1. 只在本機執行靶場

**所有靶場只綁定 `127.0.0.1`**。任何能從外部存取的靶場都是安全漏洞，不是功能。

```python
# ✅ 正確
server = HTTPServer(("127.0.0.1", port), Handler)

# ❌ 錯誤（除非有非常明確的理由並在 PR 中說明）
server = HTTPServer(("0.0.0.0", port), Handler)
```

### 2. 不得提交真實憑證

**靶場內的所有「機密」都必須是假資料**：

```python
# ✅ 正確
FLAG = "FLAG{demo_lfi_read}"
DB_PASSWORD = "SuperSecretDbPass123"

# ❌ 錯誤
FLAG = "真實的 flag 值"
API_KEY = "sk-live-真實的 token"
```

CI 會自動掃描並拒絕含私鑰、token、Natas 密碼的提交。

### 3. 不得提供真實目標的攻擊指引

本專案**只**示範自建靶場上的攻擊。不接受：
- 針對真實網站/服務的攻擊步驟
- 未公開的 0-day 利用細節
- 違反平台規則（如 OverTheWire）的解法公開

---

## 如何新增一個靶場

### 目錄結構

```
vuln-lab/<labname>/
├── <labname>.py          # 主程式（漏洞版）
├── <labname>_patched.py  # 修補版（選用）
├── verify_<labname>.py   # 驗證腳本
├── <labname>_result.json # 驗證結果（由驗證腳本產生）
└── README.md             # 靶場說明（選用）
```

### 步驟

1. **建立主程式**：刻意留下一個明確的漏洞，並在註解標記 `# ★ 漏洞：...`
2. **建立修補版**（建議）：同樣功能但修掉漏洞
3. **建立驗證腳本**：必須同時驗證「漏洞版有漏洞」與「修補版無漏洞」
4. **加入 `run_all.py`**：在 `TARGETS` 清單註冊
5. **更新 `INDEX.md`**：執行 `python vuln-lab/summary.py`
6. **寫報告**：在 `vuln-lab/S<n>_<主題>.md` 記錄

### 驗證腳本規範

```python
# 驗證結果存成 JSON，讓 summary.py 能統計
results = [
    {"name": "漏洞項目", "cwe": "CWE-89", "present": True},
    {"name": "修補項目", "cwe": "防護", "present": False},
]
```

**`present: true`** = 漏洞存在（漏洞版應該全部 true）
**`present: false`** = 漏洞不存在（修補版應該全部 false）

---

## 程式碼風格

### Python

- **只用標準庫**（除非有非常明確的理由）
- 遵循 PEP 8，4 空格縮排
- 型別提示（`def scan(root: Path) -> list[dict]:`）
- 繁體中文註解，但**變數與函式名用英文**

```python
# ✅ 正確
def scan_targets(root: Path) -> list[dict]:
    """掃描靶場目錄。"""
    ...

# ❌ 錯誤
def 掃描(root):
    ...
```

### 測試

- 用 `unittest`（不用 pytest，避免額外依賴）
- 每個函式至少一個正常案例 + 一個邊界案例
- 測試檔放 `vuln-lab/tests/`

```bash
# 跑測試
python vuln-lab/tests/test_summary.py -v

# 跑全部靶場
python vuln-lab/run_all.py --quick
```

---

## PR 流程

1. **建立分支**：`git checkout -b feat/your-lab-name`
2. **實作**：遵循 TDD（先寫測試，看它失敗，再實作）
3. **本地驗證**：
   ```bash
   python vuln-lab/run_all.py --quick
   python vuln-lab/tests/test_summary.py
   python vuln-lab/summary.py  # 更新 INDEX.md
   ```
4. **確認無敏感資料**：
   ```bash
   git status
   git diff --cached  # 檢查有沒有不小心加入 .db / .phar / 密碼
   ```
5. **提交**：清楚的 commit message
   ```
   feat(vuln-lab): add SSRF lab with DNS rebinding
   
   - 新增 ssrflab/ssrflab.py（漏洞版）
   - 新增 ssrflab/verify_ssrflab.py
   - 在 run_all.py 註冊
   ```
6. **推送並開 PR**

---

## CI 會檢查什麼

| 檢查 | 說明 |
|---|---|
| `run_all.py --quick` | 9 個核心靶場必須全數通過 |
| `test_summary.py` | 單元測試必須通過 |
| `INDEX.md` 最新 | 若靶場變動未重跑 `summary.py` 會失敗 |
| 敏感資料掃描 | 私鑰、token、`.db`、`.phar`、`natas_pw` |
| 產品二進位 | `.db` / `.phar` 不得進版控 |

**CI 失敗時**，先看 artifact（`verification-results`）裡的 `pipeline_report.json`。

---

## 回報問題

- **Bug**：開 issue，附上重現步驟與 `python --version`
- **安全問題**：**不要**開公開 issue，見 [`SECURITY.md`](SECURITY.md)（若有）
- **新靶場想法**：開 issue 討論，先確認是否符合專案範圍

---

## 授權

貢獻的程式碼會在 [MIT License](LICENSE) 下發布。

**請確認你有權提交該程式碼**（原創或相容授權）。

---

## 最後

這個專案的目的不是「收集最多漏洞」，而是**讓每個漏洞都講清楚原理**。

一個寫得好的靶場 + 一份講清楚根因的報告，比十個只會跑 PoC 的靶場有價值。
