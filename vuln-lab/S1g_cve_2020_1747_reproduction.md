# 真實案例實測：CVE-2020-1747（PyYAML 反序列化 RCE）

> 從本專案掃描出的真實 CVE 中選一個，**實際下載原始碼、在本地複現**。
>
> 對應研究報告 **CH01（漏洞原理）**、**CH02.1（驗證分離）**、**CH06 S1（A03 供應鏈）**。

- 測試日期：2026-10-15
- 案例：**CVE-2020-1747**（CVSS **CRITICAL**，GHSA-6757-jp84-gxfx）
- 結果：**成功複現任意程式碼執行**，並在修補版上驗證防護生效

---

## 一、案例背景（官方資訊）

| 項目 | 內容 |
|---|---|
| **CVE** | CVE-2020-1747 |
| **別名** | GHSA-6757-jp84-gxfx、PYSEC-2020-96 |
| **嚴重度** | **CRITICAL** |
| **影響範圍** | `5.1b7` ～ `5.3.1`（OSV 標記；源碼比對後見 §六說明） |
| **衝擊** | **任意程式碼執行（RCE）** |
| **發現方式** | 本專案的供應鏈掃描（`scan_deps.py` / `analyze_tree2.py`）標記出的 166 個漏洞之一 |

**官方描述（OSV 原文）**：

> A vulnerability was discovered in the PyYAML library in versions before 5.3.1,
> where it is susceptible to arbitrary code execution when it processes untrusted
> YAML files through the **full_load** method or with the **FullLoader** loader.
> An attacker could use this flaw to execute arbitrary code on the system by
> abusing the **python/object/new** constructor.

**為什麼這個案例值得實測**：PyYAML 是極廣泛使用的套件（數百萬次下載），
且它出現在本專案掃描出的 `requirements-vulnerable.txt` 中——
**從「掃描發現」到「實際複現」的完整鏈條**。

---

## 二、測試方法（完全合法）

| 步驟 | 做法 |
|---|---|
| 1. 取得原始碼 | 從 **PyPI 官方**下載 PyYAML 5.1 / 5.2 / 5.3 / 5.3.1 的 sdist |
| 2. 解決相容性 | 舊版 PyYAML 有 `lib/`（Python 2）與 **`lib3/`（Python 3）** 兩份原始碼 → 用 `lib3/` |
| 3. 隔離載入 | 用 `sys.path` 隔離，逐版本載入 |
| 4. 送載荷 | 用 `full_load()` 解析含 `python/object/*` 標籤的 YAML |
| 5. 對照組 | 同一載荷改用 `safe_load()` 與 `unsafe_load()` |

### 安全邊界（嚴格遵守）

```
✅ 只在本機執行
✅ 使用從 PyPI 下載的官方原始碼
✅ 攻擊載荷僅執行無害指令：echo CVE-2020-1747-PROOF
✅ 不寫入檔案、不讀取檔案、不連網、不修改系統狀態
✅ 目的是證明「程式碼執行」這件事實，而非造成任何影響
```

---

## 三、複現結果

### 3.1 各版本行為對比

| 攻擊向量 | 5.1 | 5.2 | 5.3 | 5.3.1 |
|---|---|---|---|---|
| `object/apply` → `subprocess.check_output` | ○ 攔阻 | ○ 攔阻 | ○ 攔阻 | ○ 攔阻 |
| `object/apply` → `os.popen` | ○ 攔阻 | ○ 攔阻 | ○ 攔阻 | ○ 攔阻 |
| **`object/new` → `subprocess.Popen`** | ○ 攔阻 | **★ 執行** | **★ 執行** | ★ 執行 |
| **`object/new` + `state.__reduce__`** | — | — | **★ 執行** | **○ 攔阻** |

### 3.2 關鍵證據（5.3 vs 5.3.1）

**5.3（受影響）**：

```
[5. object/new + state.__reduce__]
    ★ 程式碼執行成功！ 行程物件已建立：Popen
```

**5.3.1（已修補）**：

```
[5. object/new + state.__reduce__]
    ○ 未執行 攔阻：ConstructorError —
      blacklisted key '__reduce__' in instance state found
```

> **這就是 CVE-2020-1747 的修補生效的直接證據**——
> 5.3.1 新增的 state 鍵黑名單（`['^extend$', '^__.*__$']`）攔下了 `__reduce__`。

### 3.3 `safe_load()` 從頭到尾都攔阻

```
[負向對照] 同樣載荷改用 safe_load（應被攔阻）
    🡒 ✓ 正確攔阻：ConstructorError
```

**這是最重要的結論**：問題**不是函式庫有缺陷**，而是
**開發者選錯了 API**。

---

## 四、源碼層級的證據（為什麼會這樣）

### 4.1 `full_load()` 的實作

```python
def full_load(stream):
    """Resolve all tags except those known to be unsafe on untrusted input."""
    return load(stream, FullLoader)
```

注意那句 docstring——**「except those known to be unsafe」** 是設計意圖，
但實際上 `FullLoader` 仍允許一整類危險標籤。

### 4.2 `FullConstructor` 註冊了哪些標籤

```python
FullConstructor.add_constructor(u'tag:yaml.org,2002:python/object:',
                                FullConstructor.construct_python_object)
FullConstructor.add_constructor(u'tag:yaml.org,2002:python/object/new:',
                                FullConstructor.construct_python_object_new)
```

### 4.3 真正的差異：5.3.1 新增的黑名單

**5.3**（無防護）：
```python
def set_python_instance_state(self, instance, state):
    if hasattr(instance, '__dict__'):
        instance.__dict__.update(state)      # ← 任意鍵都能寫入
```

**5.3.1**（新增防護）：
```python
def get_state_keys_blacklist(self):
    return ['^extend$', '^__.*__$']          # ← 阻擋 __reduce__ 等魔術方法

def check_state_key(self, key):
    if self.get_state_keys_blacklist_regexp().match(key):
        raise ConstructorError(None, None,
            "blacklisted key '%s' in instance state found" % (key,), None)

def set_python_instance_state(self, instance, state, unsafe=False):
    ...
    if not unsafe and state:
        for key in state.keys():
            self.check_state_key(key)        # ← 每個鍵都檢查
```

**這解釋了為什麼 `__reduce__` 在 5.3 成功、在 5.3.1 被攔阻。**

---

## 五、實務影響評估

### 為什麼這個漏洞危險

| 因素 | 說明 |
|---|---|
| **YAML 的普及** | 設定檔、CI 設定（GitHub Actions / GitLab CI）、K8s manifest、API 請求都常用 |
| **`full_load` 的誘惑** | 它的 docstring 說「resolve all tags except unsafe」，容易讓人誤以為安全 |
| **觸發條件低** | 只要應用用 `full_load` 解析**使用者可控**的 YAML 即可 |
| **後果嚴重** | 相當於在伺服器上執行任意程式碼 |

### 真實世界的攻擊場景

```
1. 應用提供「上傳 YAML 設定」功能
2. 後端用 yaml.full_load(user_input) 解析
3. 攻擊者上傳含 python/object/new 的 YAML
4. → 伺服器執行攻擊者指定的程式碼
```

---

## 六、本次實測發現的三件事（含對 OSV 資料的補充）

### 發現 1：`object/new` 在 5.3.1 **仍可** 建立 Popen 物件

實測顯示 `python/object/new:subprocess.Popen` 在 **5.3.1 也成功**。
這表示 5.3.1 只修了 `state.__reduce__` 這條路徑，而非全面封鎖 `object/new`。

**這與 OSV 標記「fixed: 5.3.1」有落差**——OSV 的 `fixed` 指的是
**該 CVE 的特定攻擊向量**被修補，不代表 `full_load` 從此安全。

> **教學重點**：CVE 的「修復版本」欄位要理解為
> 「**這個具體漏洞的這個向量**被修補了」，
> 而不是「這個 API 從此安全」。

### 發現 2：`object/apply` 早在 5.2 就被移除

5.3 的測試中 `object/apply` 已被攔阻（回 `could not determine a constructor`），
對應 5.1 的 CHANGES 記載：「Make FullLoader safer by removing
python/object/apply from the default FullLoader」。

### 發現 3：`lib3/` 是關鍵

舊版 PyYAML 有兩份原始碼：`lib/`（Python 2，用 `except X, e:` 語法）與
`lib3/`（Python 3）。**我一開始用錯目錄**，導致所有版本都因
`ModuleNotFoundError: No module named 'error'` 而無法匯入。

> 這也解釋了為什麼「下載舊套件來複現」常常失敗——
> **要先確認套件是否提供 Python 3 專用原始碼**。

---

## 七、防護建議（依有效性排序）

| 優先序 | 做法 | 說明 |
|---|---|---|
| **1** | **用 `yaml.safe_load()`** | 唯一建議的作法；只支援基本型別 |
| 2 | 確保 YAML 完全不受外部控制 | 若必須用 `full_load` |
| 3 | 升級 PyYAML **>= 5.4**（或 6.x） | 5.3.1 只修了部分面向 |
| 4 | **絕不用 `unsafe_load()`** | 處理任何不受信任的輸入都是自找麻煩 |
| 5 | 用 SAST 規則偵測 `yaml.load` / `full_load` | 例如 Semgrep 的 `python.lang.security.deserialization` |
| 6 | 供應鏈掃描納入 CI | 見本專案 `scan_deps.py` / `analyze_tree2.py` |

### 一個容易忽略的點

```python
yaml.load(data)                 # ⚠ PyYAML 5.1+ 會警告並用 FullLoader
yaml.load(data, Loader=yaml.FullLoader)   # ⚠ 同樣危險
yaml.load(data, Loader=yaml.SafeLoader)   # ✅ 安全
yaml.safe_load(data)                      # ✅ 安全（推薦）
```

**`yaml.load()` 不加 `Loader` 參數**在 5.1+ 會預設用 `FullLoader`——
這是最常見的誤用。

---

## 八、檔案與複現

```
vuln-lab/cve-lab/
├── cve_2020_1747_test.py       # 第一輪：多版本 × 多載荷初步掃描
├── cve_2020_1747_compare.py    # 第二輪：5.3 vs 5.3.1 精確對比
├── cve_2020_1747_proof.py      # 第三輪：可執行證明（預先導入模組）
├── cve_test_output.txt
├── cve_compare_output.txt
└── cve_proof_output.txt
```

**複現方式**：
```powershell
# 1. 下載官方原始碼（PyPI）
#    5.1 / 5.2 / 5.3 / 5.3.1 的 sdist

# 2. 執行三輪測試
python vuln-lab/cve-lab/cve_2020_1747_test.py
python vuln-lab/cve-lab/cve_2020_1747_compare.py
python vuln-lab/cve-lab/cve_2020_1747_proof.py
```

---

## 九、這個案例的教學價值

| 學到的 | 對應報告章節 |
|---|---|
| 從「掃描發現 CVE」到「實際複現」的完整流程 | CH02.1 |
| 「修復版本」的語意要精確理解（不是「從此安全」） | CH05 |
| 同一個 API，`safe_load` 安全、`full_load` 危險 → **API 選擇是安全決策** | CH01 |
| 下載舊套件複現要注意 `lib/` vs `lib3/` | CH06 S2 |
| CVE 的嚴重度（CRITICAL）與實際觸發條件需分開評估 | CH05 |
| 供應鏈掃描能找出真實的 RCE 風險 | CH06 S1（A03） |

> **最重要的收穫**：這個漏洞**不需要「0-day」等級的發現能力**——
> 它是一個**已知 CVE**，用現成的掃描工具就能找到，
> 而修補只是把 `full_load` 改成 `safe_load`。
>
> **真實世界的供應鏈風險，大多長這樣。**

---

*本文件為教育用途的漏洞複現記錄。所有測試均使用從 PyPI 下載的官方原始碼，
在本機隔離環境執行，攻擊載荷僅為無害的 echo 指令。*
