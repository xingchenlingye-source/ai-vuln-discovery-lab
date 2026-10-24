# VDP / Bug Bounty 報告模板

> **使用前提**：你**只在授權範圍內**測試（有 scope 文件、有 `security.txt`、
> 或目標是開源專案且有 `SECURITY.md`）。
>
> **未授權的漏洞挖掘是犯罪**——台灣刑法 358–363、中國大陸刑法 285–287。
> 本模板不改變這個事實。

---

## 一、空白模板（直接複製）

```markdown
## Summary

[一句話說明漏洞。包含：受影響的功能、攻擊者能做什麼。]

## Affected Asset

- URL / Endpoint: `https://target.com/api/endpoint`
- HTTP Method: `POST`
- Authentication: [需要登入 / 不需要]
- Parameter: [受影響的參數名]

## Steps to Reproduce

1. 以普通使用者登入（帳號：`attacker@example.com`）
2. 前往 `https://target.com/settings`
3. 攔截請求並改成：
   ```
   POST /api/update-profile HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"user_id": 1234, "email": "attacker@example.com"}
   ```
4. 把 `user_id` 改成 `1235`（另一個使用者）
5. 觀察到：**伺服器回傳 200，且 1235 的 email 被改成 attacker@example.com**

## Impact

[這段最重要。回答三個問題：]

1. **誰受影響？** 所有已註冊使用者（約 X 萬）
2. **攻擊者能做什麼？** 修改任意使用者的 email → 接管帳號
3. **需要什麼條件？** 只需要一個普通帳號（免費註冊）

**嚴重度**：High（帳號接管）

## Proof of Concept

[截圖 / HTTP 回應片段 / 影片]

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "ok", "user_id": 1235, "email": "attacker@example.com"}
```

## Remediation

[建議修法，要具體]

- 在 `updateProfile` 中驗證 `user_id === session.userId`
- 或改用 `session.userId` 而非請求參數

## Timeline

- 2026-10-24 10:00 — 發現
- 2026-10-24 10:30 — 回報
- （等待回應）

## Additional Notes

[可選：你試過但沒成功的路徑、相關的類似漏洞、參考資料]
```

---

## 二、填好的範例（示範 Impact 怎麼寫）

> **⚠️ 這是虛構的例子**，只示範格式，不是真實漏洞。

```markdown
## Summary

`/api/v1/invoices/{id}` 缺少物件層級授權（IDOR），任何已登入使用者
都能讀取其他租戶的發票 PDF，包含客戶姓名、地址與金額。

## Affected Asset

- URL: `https://billing.example.com/api/v1/invoices/12345`
- Method: `GET`
- Auth: 需要登入（免費帳號即可）
- Parameter: `id`（路徑參數）

## Steps to Reproduce

1. 註冊帳號 A（tenant_id=100），登入
2. 建立一張發票，ID = 12345
3. 用 `curl` 取得自己的發票（正常）：
   ```
   curl -H "Cookie: session=<A>" https://billing.example.com/api/v1/invoices/12345
   ```
4. 註冊帳號 B（tenant_id=200），登入
5. 用 B 的 session 存取 A 的發票：
   ```
   curl -H "Cookie: session=<B>" https://billing.example.com/api/v1/invoices/12345
   ```
6. 觀察到：**B 成功取得 A 的發票 PDF**（HTTP 200，`Content-Type: application/pdf`）

## Impact

1. **誰受影響？** 所有使用 billing 服務的租戶
2. **攻擊者能做什麼？**
   - 讀取任意租戶的發票（客戶姓名、地址、金額、稅號）
   - 發票 ID 是遞增整數，可**列舉**所有租戶的資料
3. **需要什麼條件？** 一個免費註冊的帳號

**嚴重度**：High（跨租戶資料洩漏，PII）

## Proof of Concept

```
# 帳號 B 存取帳號 A 的發票
$ curl -s -H "Cookie: session=<B>" \
  https://billing.example.com/api/v1/invoices/12345 \
  -o leaked.pdf

$ file leaked.pdf
leaked.pdf: PDF document, version 1.4

$ pdftotext leaked.pdf - | head -3
INVOICE #12345
Bill To: Acme Corp, 123 Main St, Springfield
Amount: $12,500.00
```

## Remediation

在 `getInvoice` handler 中加上租戶檢查：

```python
# 修復前（漏洞）
invoice = db.get(Invoice, id)

# 修復後
invoice = db.get(Invoice, id)
if invoice.tenant_id != session.tenant_id:
    raise HTTPException(403)
```

**或**用查詢層級的授權：

```python
invoice = db.query(Invoice).filter(
    Invoice.id == id,
    Invoice.tenant_id == session.tenant_id,
).first()
```

## Timeline

- 2026-10-24 10:00 — 發現
- 2026-10-24 10:30 — 回報（security@example.com）
- 2026-10-25 09:00 — 廠商確認
- 2026-11-01 — 修復上線

## Additional Notes

- 我試過 `PUT /api/v1/invoices/{id}`，**也**缺少授權檢查（可修改他人發票），
  但這已包含在同一個根因內，不重複回報。
- 類似端點 `/api/v1/customers/{id}` 我還沒測，如果需要的話可以繼續。
```

---

## 三、Impact 分級參考

| 等級 | 定義 | 例子 |
|---|---|---|
| **Critical** | 無需互動的 RCE、大規模資料洩漏 | 反序列化 RCE、SQLi 拖庫 |
| **High** | 帳號接管、跨租戶資料存取、權限提升 | IDOR、認證繞過、SSRF 打內網 |
| **Medium** | 有限範圍的資料洩漏、需要使用者互動 | 儲存型 XSS、CSRF 改資料 |
| **Low** | 資訊洩漏、需要特殊條件 | 版本號洩漏、內部 IP |
| **Informative** | 無實際影響 | 缺少安全標頭、自簽憑證 |

**bounty 的錢和 impact 直接相關**——同樣的技術漏洞，impact 寫得好可能差 10 倍價格。

---

## 四、五個新手最常犯的錯

### 1. 只寫技術，不寫 impact

❌ **不好**：
> 我發現 `/api/invoices` 有 IDOR。

✅ **好**：
> 任何已登入使用者都能讀取**其他租戶**的發票 PDF，包含 PII（姓名、地址、
> 金額）。ID 是遞增整數，可列舉全部租戶的資料。

### 2. 沒有可重現的 PoC

❌ **不好**：
> 我改了一下請求，就看到了別人的資料。

✅ **好**：
> 附上完整的 `curl` 指令 + 回應片段 + 截圖。

### 3. 超出 scope

**每次都重讀 scope**。常見陷阱：
- scope 只寫 `*.example.com`，但 `api.example.com` 是第三方 → **可能不在範圍內**
- scope 寫「不包含 X 功能」，你測了 X → **out of scope**

### 4. 用掃描器猛打

**手動測試為主**。自動掃描器：
- 可能觸發 WAF/IDS → 被 ban
- 可能造成 DoS → 法律風險
- 產生的報告品質低 → triage 直接關掉

### 5. 找到小問題就報

**先問自己**：「這個漏洞有實際影響嗎？」

- 缺少 `X-Frame-Options` → **Informative**（幾乎不付錢）
- 所有使用者都能存取管理後台 → **High**（付錢）

---

## 五、回報前檢查清單

```
[ ] Scope 確認：目標在範圍內
[ ] 授權確認：有 security.txt / SECURITY.md / 平台 program
[ ] 重複確認：搜過 Hacktivity / 平台已公開報告
[ ] 可重現：照著步驟能 100% 重現
[ ] Impact 清楚：回答了「誰受影響、能做什麼」
[ ] 修復建議：具體到程式碼層級（如果可能）
[ ] 沒有破壞：沒有 DoS、沒有改真實資料、沒有橫向移動
[ ] 有時間記錄：發現時間、回報時間
```

---

## 六、常用工具（只用於授權範圍）

| 工具 | 用途 | 注意 |
|---|---|---|
| **Burp Suite Community** | 攔截/改請求 | 免費版夠用 |
| **curl / httpie** | 手動測試 API | 最可控 |
| **瀏覽器 DevTools** | 看前端邏輯 | 找隱藏端點 |
| **jq** | 解析 JSON 回應 | — |

**不需要**：Nmap、Nuclei、SQLMap 等自動掃描器（新手階段用不到，且容易踩線）。

---

## 七、這份模板的來源

本模板參考：
- [HackerOne 的報告指南](https://docs.hackerone.com/hackers/reporting.html)
- [Bugcrowd 的 Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
- 多份公開的 disclosed reports（Hacktivity）

**但每個 program 有自己的格式要求**——回報前**先讀該 program 的 submission guidelines**。

---

*本文件為教育用途，不構成任何授權。授權只能來自目標擁有者。*
