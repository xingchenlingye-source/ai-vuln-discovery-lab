# S1 補充：剩餘 7 類缺口補全

> 補全對照 Bilibili 84 集課程後發現的所有**可實作**缺口。
>
> 對應研究報告 **CH06 S1** 與 **CH08**。

- 日期：2026-10-15
- 靶場：`webvulnlab/`（一個檔案涵蓋 7 類漏洞）
- **驗證結果：7/7 全部通過**

---

## 一、補全清單

| # | 漏洞 | CWE | 課程對應 | 結果 |
|---|---|---|---|---|
| **U** | 文件上傳（黑名單不完整） | CWE-434 | P72–P77（6 集） | ✅ |
| **O** | CORS 配置錯誤（含內網探測） | CWE-942 | P15–P17、P80（4 集） | ✅ |
| **T** | SSTI 服務端模板注入 | CWE-1336 | P55 | ✅ |
| **Cr** | CRLF 注入（標頭注入） | CWE-113 | P51 | ✅ |
| **R** | URL 重定向（開放重導向） | CWE-601 | P52–P53 | ✅ |
| **J** | JSONP 劫持 | CWE-346 | P54 | ✅ |
| **A** | 未授權訪問（系統化） | CWE-862 | P18–P19、P65 | ✅ |

---

## 二、七種不同的驗證方式（本靶場的核心）

| 漏洞 | 驗證要看什麼 |
|---|---|
| U 文件上傳 | 伺服器是否**接受繞過的檔名** |
| O CORS | 回應標頭是否**反射任意 Origin** |
| T SSTI | 模板表達式是否**被求值**（`{{7*7}}` → `49`） |
| Cr CRLF | 回應標頭是否**被注入** |
| R URL 重定向 | **Location 標頭指向何處** |
| J JSONP | 回應是否**被 callback 包裝** |
| A 未授權 | **無憑證能否取得資料** |

> 加上先前的 7 種，本專案已累積 **14 種不同的驗證方式**——
> 這正是 CH02.1「驗證方式必須配合漏洞類型」的最完整實證。

---

## 三、★ 實測推翻了我自己的假設（最重要的收穫）

### 我原本以為「大小寫可繞過上傳黑名單」

**實測結果**：

```
shell.php    → 403 攔阻
shell.pHp    → 403 攔阻   ← 我的假設錯誤！
```

**原因**：靶場的黑名單用了 `fname.lower().endswith(...)`——
**有 `.lower()` 的實作下，大小寫根本無效**。

### 真正的繞過方式：黑名單本身不完整

實測 **8 種變體繞過成功**：

```
shell.php5      shell.phtml    shell.phar     shell.php.jpg
shell.pht       shell.shtml    shell.jspx     shell.asp;.jpg
```

**教訓**：
> 「大小寫繞過」是常見的教學說法，但**它只在黑名單未做正規化時有效**。
> 真正的結構性問題是：**PHP 可執行副檔名不只 `.php`**——
> 黑名單永遠列不完，這就是為什麼必須用**白名單**。

---

## 四、各漏洞的關鍵發現

### U · 文件上傳

| 檢查項 | 漏洞版 | 安全對照 |
|---|---|---|
| 黑名單 | ✅ 有（4 個副檔名） | 改用白名單 |
| 內容檢查 | ❌ 無 | ✅ magic bytes |
| 繞過結果 | **8/10 變體成功** | ✅ 全部攔阻 |

### O · CORS（三層問題疊加）

```
請求 1  GET /api/public               → ACAO: *           （萬用字元）
請求 2  GET /api/private (evil Origin) → ACAO: evil...      （反射任意來源）
                                        + ACAC: true        （允許憑證）
請求 3  GET /cors-probe?host=intranet.local → 取得內網內容
```

**「反射任意 Origin + 允許憑證」是最危險的組合**——任意外站都能帶上使用者憑證讀取回應。

### T · SSTI

```
GET /render?tpl={{7*7}} → output: "49"（引擎：jinja2）
安全對照 /render-safe   → 保持字面 "{{7*7}}"
```

**判定邏輯的關鍵**：不是看「有沒有報錯」，而是看**數學運算是否真的算出結果**。

> 本靶場刻意只做無害運算（`{{7*7}}`），**不示範 RCE 載荷**。
> 攻擊視角的教學影片會示範完整的 RCE 鏈，但那超出防禦性學習的範圍。

**環境註記**：Jinja2 原先未安裝，我最後安裝了 **3.1.6**（最新版，非漏洞版本）以呈現真實的 Jinja2 SSTI。

### Cr · CRLF 注入

```
注入成功後的標頭：
  Set-Cookie=lang=zh, X-Injected=yes; Path=/
                                  ↑ 注入的標頭
```

換行符（`%0d%0a`）讓使用者輸入逃出 `Set-Cookie`，變成一個**新的標頭**。

### R · URL 重定向

```
GET /login?next=https://evil.example.com/phish
  → HTTP 302, Location: https://evil.example.com/phish
對照：next=/dashboard → Location: /dashboard（相對路徑正常）
```

### J · JSONP 劫持

```
GET /api/user?callback=stealData
  → stealData({"id":1,...,"token":"session-token-FAKE-abc123"})
```

**為什麼這是漏洞**：`<script src>` **不受同源政策限制**——
任意外站只要載入這個 URL 就能讀取回應內容（含 session token）。

### A · 未授權訪問

```
GET /api/internal/users   → 200，洩漏使用者清單（不帶任何憑證）
GET /api/internal/config  → 200，洩漏 API key
```

---

## 五、開發時踩到的 bug（兩個）

### Bug 1：括號未閉合

```python
return self._send(200, PAGE.format(body=(
    "...%s..." % (out, eng)))     # ← 少一個 )
```

`self._send(` 與 `PAGE.format(` 各需一個閉括號。實際需要 `))))`。

### Bug 2：CSS 大括號轉義（第四次）

`PAGE` 中的 `{body}` 是真正的佔位符，而 CSS 的 `{...}` 需轉義。
**這次我先檢查再修改**，確認 `PAGE` 只有 `{body}` 一個佔位符、CSS 已正確轉義。

> **檢討**：同一個坑踩了四次（`frontendlab`、`xsslab`、`ssrflab`、這次）。
> 我應該建立一個**可重用的 HTML 樣板函式**，把 CSS 與動態內容分離，
> 而不是每次手寫 `.format()` 模板。

---

## 六、課程對照的最終狀態

### Bilibili 84 集課程：21 模組

| 狀態 | 模組數 |
|---|---|
| ✅ 已充分涵蓋 | **16**（新增 7 類） |
| ⚠️ 需額外條件 | 5 |

### 剩餘 5 項（需外部條件，非能力缺口）

| 缺口 | 為什麼無法在本機完整實作 |
|---|---|
| 雲安全（P26–P27） | 需真實雲帳號（已用模擬 metadata 部分涵蓋） |
| 框架漏洞（P28–P29） | 需部署 Spring Boot 等框架 |
| XSS 盲打平台（P39–P40） | 需架設接收端 + 模擬受害者瀏覽器 |
| 短信轟炸（P69） | 需簡訊服務（不可實作） |
| 帳號接管全鏈（P66–P68） | 我已有密碼重置的部分面向，但未做完整鏈 |

---

## 七、本專案最終狀態

### 靶場（13 個）

```
audit/        盲審實驗
clab/         C 記憶體安全
fuzz/         v1 fuzzer
fuzz_v2/      v2 fuzzer（edge + bucket + 格式感知）
authlab/      A01 IDOR + A10 fail-open + A07 認證
loglab/       A09 日誌與警報
buyLab/       A06 設計缺陷 + A04 加密
configlab/    A02 安全設定
supplychain/  A03 供應鏈（SBOM + 簽章 + 依賴樹）
cve-lab/      CVE-2020-1747 真實漏洞複現
frontendlab/  前端邏輯 + HTTP fuzzer
xsslab/       XSS / CSRF / XXE
ssrflab/      SSRF（雙埠）
webvulnlab/   7 類整合（本檔）
```

### 驗證型態（14 種）

```
1. 注入（SQLi/CMDi）    8. DOM 型 XSS
2. 日誌類（A09）        9. CSRF（缺少的防護）
3. 競態類（A06）       10. XXE（實體展開）
4. 加密類（A04）       11. SSRF（伺服器行為）
5. 設定類（A02）       12. 文件上傳（接受繞過檔名）
6. 反射型 XSS         13. CORS（標頭反射）
7. 存儲型 XSS         14. SSTI（表達式求值）
                       15. CRLF/重定向/JSONP/未授權
```

---

## 八、檔案與複現

```
vuln-lab/webvulnlab/
├── webvulnlab.py              # 靶場（7 類漏洞）
├── verify_webvulnlab.py       # 驗證（7/7）
├── uploads/                   # 上傳目錄（僅本機）
└── findings/
    └── webvulnlab_verification.txt
```

**複現**：
```powershell
python vuln-lab/webvulnlab/webvulnlab.py 8930
python vuln-lab/webvulnlab/verify_webvulnlab.py 8930
```

**手動練習**：
```
U  上傳    : POST /upload  {filename:"shell.php5", content:"TEST"}
O  CORS    : GET /api/private（帶 Origin: http://evil.example.com）
T  SSTI    : GET /render?tpl={{7*7}}  或  /greet?name={{7*7}}
Cr CRLF    : GET /setlang?lang=zh%0d%0aX-Injected:%20yes
R  重定向  : GET /login?next=https://evil.example.com
J  JSONP   : GET /api/user?callback=stealData
A  未授權  : GET /api/internal/config
```

---

*本文件為教育用途的實作記錄。上傳僅寫入本機 `uploads/`；
SSTI 僅做無害運算，不示範 RCE；所有測試 100% 在本機自建靶場完成。*
