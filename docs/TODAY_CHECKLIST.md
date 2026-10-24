# 今天 4 件事 — HackerOne 起步 Checklist

> **目標**：今天結束前完成這 4 件事。
> **預估總時間**：35 分鐘。
> **不要做的事**：不要今天就去打 program。

---

## ☐ 1. 註冊 HackerOne 帳號（5 分鐘）

**連結**：https://hackerone.com/users/sign_up

**填寫**：

| 欄位 | 建議 |
|---|---|
| **Email** | 專門的信箱（不是日常信箱） |
| **Username** | `<你的暱稱>_sec`（**會公開顯示**，不要用真名） |
| **Password** | 密碼管理器產生，≥16 字元 |

**完成標準**：
- [ ] 收到驗證信並點擊連結
- [ ] 能登入 HackerOne 首頁

**卡點**：
- 如果 email 收不到 → 檢查垃圾郵件匣
- 如果 username 被佔用 → 加數字後綴

---

## ☐ 2. 開 2FA + 填 Profile（10 分鐘）

### 2a. 開 2FA（5 分鐘）

**路徑**：右上角頭像 → **Settings** → **Security** → **Two-Factor Authentication**

**用 TOTP**（Google Authenticator / 1Password / Authy）

> ⚠️ **必須做**。帳號被盜 = reputation 被毀，而且無法恢復。

### 2b. 填 Profile（5 分鐘）

**路徑**：Settings → **Profile**

| 欄位 | 建議填入 |
|---|---|
| **Bio** | `Learning web security. Building self-hosted labs.` |
| **Website** | `https://github.com/xingchenlingye-source/ai-vuln-discovery-lab` |
| **Twitter/X** | （可選，跳過） |

**完成標準**：
- [ ] 2FA 已啟用（登出再登入會要求 TOTP）
- [ ] Profile 的 Website 欄位指向你的 repo

**卡點**：
- 2FA 備份碼 → **存到密碼管理器**，不要只截圖

---

## ☐ 3. 讀 1 份 Disclosed Report（20 分鐘）

**路徑**：HackerOne → **Hacktivity** → 篩選 **`Disclosed`** + **`Web`**

**選一份 IDOR 或 XSS 的**（你看得懂的類型）

**讀完後，用這個格式記錄**（貼在下面）：

```markdown
### 報告：<標題>

**URL**: <報告連結>
**漏洞類型**: IDOR / XSS / ...
**Bounty**: $XXX（或無）

**Q1: Impact 怎麼寫的？**
（抄 1-2 句你覺得寫得好的）

**Q2: PoC 給了什麼？**
（curl？截圖？影片？步驟多詳細？）

**Q3: 標題怎麼寫？**
（技術名詞 vs 影響描述？）

**我的觀察**：
（這份報告讓我學到什麼？）
```

**完成標準**：
- [ ] 讀完 1 份
- [ ] 上面 4 個問題都有答案

**卡點**：
- 如果找不到 IDOR/XSS → 用 Hacktivity 的搜尋框打 `IDOR` 或 `XSS`

---

## ☐ 4. 寫下你的第一個觀察（5 分鐘）

**不是寫報告，是寫「我注意到什麼」**：

```markdown
## 我的觀察

讀完這份報告後，我發現：

1. Impact 段落通常寫 3-5 句，重點是「誰受影響 + 能做什麼」
2. PoC 用 curl 指令 + 回應片段，不用截圖
3. 標題格式：「[漏洞類型] in [端點] allows [影響]」

這跟我原本想的不一樣的地方：
（例如：我以為要寫很多技術細節，但其實 impact 更重要）
```

**完成標準**：
- [ ] 寫下至少 3 個觀察
- [ ] 誠實寫出「跟我原本想的不一樣」的地方

---

## 完成後：回報

**如果 4 項都打勾**，你已經完成了「從 0 到有帳號 + 知道報告長什麼樣」。

**下一步（明天/後天）**：
1. 再讀 4 份報告（湊滿 5 份）
2. 用你的 repo 裡的 [`VDP_REPORT_TEMPLATE.md`](VDP_REPORT_TEMPLATE.md) 對照
3. 挑 1 個 program（標準見 [`HACKERONE_GETTING_STARTED.md`](HACKERONE_GETTING_STARTED.md)）

**如果卡住了**：
- 卡在註冊 → 檢查 email/username
- 卡在 2FA → 用備份碼
- 卡在讀報告 → 換一份更短的（找 `< $500` 的）
- **卡在「不想做」** → 這是最常見的卡點，誠實面對它

---

## 進度追蹤

```
日期：2026-10-___

[ ] 1. 註冊完成
[ ] 2. 2FA + Profile 完成
[ ] 3. 讀完 1 份報告
[ ] 4. 寫下 3 個觀察

實際花了多少時間：____ 分鐘
```

---

*這份 checklist 的重點不是「完成任務」，是「跨過第一步」。*
*打開帳號比讀十份指南有用。*
