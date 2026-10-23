# S2 補強：LFI 與 XOR/known-plaintext 加密學攻擊

> 補強 OverTheWire Natas 實戰中發現的兩個缺口。
>
> 對應研究報告 **CH06 S1**，並延續 **S2b（Natas 續解）** 的發現。

- 日期：2026-10-19
- 新增靶場：`lfllab/`（LFI）、`cryptolab/`（加密學攻擊）
- **驗證結果：LFI 5/5、CryptoLab 6/6，合計 11/11 全部通過**

---

## 一、為什麼要補這兩個缺口

在 `S2b` 續解 Natas 時發現：

| natas 關卡 | 漏洞 | 本專案原有狀態 |
|---|---|---|
| **natas7** | **LFI**（本機檔案包含） | ❌ 有 SSRF 但**無 LFI** |
| **natas11** | **XOR 加密 cookie 逆向** | ❌ 有弱隨機但**無加密學攻擊** |

這兩個都是 Web 滲透中非常經典的類別，補強後本專案的漏洞覆蓋更完整。

---

## 二、LFI 靶場（lfllab/，5/5 通過）

### 2.1 靶場設計

```
lfllab/
├── lfllab.py           # 主程式（含漏洞版 /page 與安全版 /safe）
├── pages/              # 正常頁面
│   ├── home.php
│   ├── about.php
│   └── contact.php
└── secrets/            # ★ 敏感檔案（模擬）
    ├── config.txt      # DB 密碼、API key、ADMIN_TOKEN
    └── passwd.txt      # 模擬系統 passwd
```

### 2.2 五種 LFI 手法

| # | 手法 | CWE | 結果 |
|---|---|---|---|
| L1 | **基本路徑穿越** `?page=../secrets/config.txt` | CWE-22/98 | ✅ |
| L2 | **過濾繞過** `?page=....//secrets/config.txt` | CWE-22 | ✅ |
| L3 | **絕對路徑** `?page=/secrets/config.txt` | CWE-22 | ✅ |
| L4 | **`php://filter` 讀原始碼** | CWE-98 | ✅ |
| — | **安全對照** `/safe` 正確阻擋 | 防護驗證 | ✅ |

### 2.3 最重要的發現：`....//` 的層數要精確

我在開發時**第一版用錯了 payload**：

```
錯誤：....//....//secrets/config.txt
      → replace("../","") → ../../secrets/config.txt  → 過頭（跑出基準目錄）

正確：....//secrets/config.txt
      → replace("../","") → ../secrets/config.txt     → 正確穿越一層
```

**實測計算**：

```
....//secrets/config.txt   → filtered=../secrets/config.txt   → 存在 ✓
....//....//secrets/...    → filtered=../../secrets/...       → 不存在 ✗
```

> **教學點**：`....//` 的繞過**層數必須精確**——
> 多一層就會跑出目標範圍。這也說明為什麼「用字串取代做過濾」
> 是不可靠的：它的行為取決於輸入的精確結構。

### 2.4 L4：`php://filter` 為何特別危險

```
?page=php://filter/convert.base64-encode/resource=home.php
→ 回傳 base64 編碼的**原始碼**（而非執行結果）
```

**危害**：讀出原始碼後，攻擊者可以發現：
- 資料庫憑證
- 其他漏洞（SQL 注入、命令注入）
- 業務邏輯

### 2.5 安全對照的正確做法

```python
# ① basename 取檔名（去掉任何路徑）
base = os.path.basename(page)
# ② 白名單比對
if base not in ALLOWED_PAGES:
    return 403
# ③ realpath 驗證（確保解析後仍在允許目錄內）
real = os.path.realpath(target)
if not real.startswith(os.path.realpath(PAGES_DIR) + os.sep):
    return 403
```

**三層防護缺一不可**。

---

## 三、CryptoLab 靶場（cryptolab/，6/6 通過）

### 3.1 四個加密學漏洞

| # | 漏洞 | CWE | 結果 |
|---|---|---|---|
| X1 | **固定 XOR 金鑰**（known-plaintext 偽造） | CWE-327/330 | ✅ |
| X2 | **XOR 金鑰重用**（金鑰可被消掉） | CWE-323 | ✅ |
| X3 | **可預測 token**（時間戳 + 小隨機） | CWE-330 | ✅ |
| X4 | **加密但無完整性驗證**（可篡改） | CWE-353 | ✅ |
| — | 安全對照：HMAC 簽章 | 防護驗證 | ✅ |
| — | 安全對照：CSPRNG token | 防護驗證 | ✅ |

### 3.2 X1：known-plaintext 攻擊（本次最精彩）

**這正是 natas11 的手法**：

```
步驟 1  取得加密 cookie（base64）
步驟 2  已知明文 = {"user":"guest","role":"user","showflag":false}
步驟 3  ★ XOR(密文, 已知明文) → 推導金鑰（可看出週期 = 4 → key = "kBSw"）
步驟 4  用金鑰偽造 {"user":"admin","role":"admin","showflag":true}
步驟 5  帶上偽造 cookie → 伺服器接受 → 取得 FLAG
```

**實際驗證輸出**：
```
密文       = <base64>
已知明文   = {"user":"guest","role":"user","showflag":false}
推導 key   = b'kBSwkBSwkBSw...'（週期 4 → "kBSw"）
偽造 cookie = <base64>
伺服器接受 = {"user": "admin", "role": "admin", "showflag": true}
取得 FLAG  = True
```

> **XOR 不是加密，只是混淆。**
> 金鑰一旦被推導出來，整個機制就失效。

### 3.3 X2：XOR 金鑰重用

```
C1 = P1 ⊕ K
C2 = P2 ⊕ K
C1 ⊕ C2 = P1 ⊕ P2    ← 金鑰被完全消掉！
```

**實測**：已知 P1 開頭是 `FLAG{`，就能推出 P2 的對應位置。
逐步延伸（crib dragging）即可還原全部內容。

### 3.4 X3：可預測 token

```
token 格式：natas_crypto_<unix_ms>_<3-digit random>
問題：
  ① 時間戳可預測（與現在時間接近）
  ② 隨機只有 0-999（只需暴力 1000 次）
```

**驗證方式**：解析 token 中的時間戳，比對當前時間 → 證實可預測。

### 3.5 X4：加密但無完整性驗證

```
GET /echo?d=base64('hello')     → 解密為 "hello"
★ 篡改密文第一個位元
GET /echo?d=<tampered>          → 伺服器仍解密並接受
```

**危害**：bit-flipping attack——攻擊者可**可控地修改**解密後內容
（例如把 JSON 的 `false` 改成 `true`、修改金額欄位）。

**這正是「encrypt-only，沒有 authenticate」的典型問題。**

### 3.6 安全對照：Encrypt-then-MAC

```
cookie = base64(json) + "." + HMAC-SHA256(key, base64(json))
篡改 → 簽章不符 → 403
```

**對比 X4**：同樣是「改動密文」，X4 被接受，安全版被拒絕。

---

## 四、兩個靶場的驗證型態（新增兩種）

本專案的驗證型態已從 17 種增加到 **19 種**：

| # | 類型 | 驗證要看什麼 |
|---|---|---|
| … | （前面 17 種） | … |
| **18** | **LFI** | 回應中是否出現**只有目標檔案才有的內容** |
| **19** | **加密學攻擊** | **自己推出金鑰並偽造** / 金鑰可否被消掉 / token 可否預測 / 篡改是否被接受 |

> **加密學漏洞的驗證最特別**：它不看錯誤訊息、不看標頭，
> 而是**證明攻擊者能主動構造出有效但惡意的輸入**。

---

## 五、與 Natas 實戰的對應

| Natas | 手法 | 本專案靶場 | 狀態 |
|---|---|---|---|
| natas7 | `?page=/etc/natas_webpass/natas8` | **`lfllab` L1/L3** | ✅ 補強完成 |
| natas11 | XOR cookie + known-plaintext | **`cryptolab` X1** | ✅ 補強完成 |

**現在 Natas 中學到的技巧，在本專案都有對應的本機靶場可練習。**

---

## 六、檔案與複現

```
vuln-lab/
├── lfllab/
│   ├── lfllab.py              # LFI 靶場（5 種手法 + 安全對照）
│   ├── verify_lfllab.py       # 驗證（5/5）
│   ├── pages/                 # 正常頁面
│   └── secrets/               # 敏感檔案（模擬）
└── cryptolab/
    ├── cryptolab.py           # 加密學靶場（4 種漏洞 + 2 個安全對照）
    └── verify_cryptolab.py    # 驗證（6/6）
```

**複現**：
```powershell
python vuln-lab/lfllab/lfllab.py 8950
python vuln-lab/lfllab/verify_lfllab.py 8950

python vuln-lab/cryptolab/cryptolab.py 8951
python vuln-lab/cryptolab/verify_cryptolab.py 8951
```

**手動練習**：
```
LFI：
  http://127.0.0.1:8950/page?page=../secrets/config.txt
  http://127.0.0.1:8950/page-filtered?page=....//secrets/config.txt
  http://127.0.0.1:8950/page?page=php://filter/convert.base64-encode/resource=home.php
  安全對照：http://127.0.0.1:8950/safe?page=../secrets/config.txt

Crypto：
  http://127.0.0.1:8951/profile        # 觀察 XOR cookie
  http://127.0.0.1:8951/msg?id=1       # 金鑰重用
  http://127.0.0.1:8951/token          # 可預測 token
  http://127.0.0.1:8951/echo?d=...     # 無完整性驗證
  安全對照：http://127.0.0.1:8951/safe/profile、/safe/token
```

---

## 七、開發時踩到的坑

### 坑 1：LFI 的過濾邏輯把 L1 也擋掉了

第一版把「完全無過濾」（L1）和「有過濾可繞過」（L2）混在同一個端點，
結果過濾邏輯把 L1 的 `../secrets/config.txt` 也過濾成 `secrets/config.txt`（不存在）。

**修正**：拆成兩個端點——
- `/page`：**完全不處理**（L1/L3/L4）
- `/page-filtered`：有 `../` 過濾（L2）

### 坑 2：`....//` 的層數要精確

```
....//secrets/config.txt     → ../secrets/config.txt   ✓
....//....//secrets/...      → ../../secrets/...       ✗（過頭）
```

**這是一個很好的教學點**：字串過濾的行為**取決於輸入的精確結構**，
所以「用 replace 做安全過濾」本質上就不可靠。

---

## 八、結論

### 補強成果

| 缺口 | 靶場 | 驗證 |
|---|---|---|
| **LFI** | `lfllab`（5 種手法） | **5/5** |
| **XOR/known-plaintext** | `cryptolab`（4 種漏洞） | **6/6** |

### 三個核心學習

1. **LFI 的防護必須三層**：basename + 白名單 + realpath
2. **XOR 不是加密**：金鑰固定 + 明文可預測 → known-plaintext 即可攻破
3. **加密必須同時做認證**：encrypt-only 可被 bit-flipping 篡改

### 本專案現在的完整度

```
靶場：17 個（新增 lfllab、cryptolab）
驗證型態：19 種
報告：27 份
```

**Natas 實戰中學到的每一個技巧，現在都有對應的本機靶場可反覆練習。**

---

*本文件為教育用途的實作記錄。所有「敏感檔案」皆為本機模擬檔，
所有測試 100% 在本機自建靶場完成。*
