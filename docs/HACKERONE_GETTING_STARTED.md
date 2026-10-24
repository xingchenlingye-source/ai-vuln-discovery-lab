# HackerOne 入門：註冊 + 挑 Program 的具體步驟

> 給「已經會挖靶場、但沒打過真實目標」的人。
> 目標：**兩週內送出第一個 VDP 報告**，不是「成為 top hunter」。

---

## 第一階段：註冊（15 分鐘）

### Step 1：註冊帳號

1. 開 **https://hackerone.com/users/sign_up**
2. 用**專門的信箱**（不要用你日常信箱）
   - 建議：`<你的名字>.security@gmail.com` 或類似
   - **為什麼**：報告會寄到這裡，之後可能收到大量 program 通知
3. 使用者名稱（handle）：
   - **不要用真名**
   - 建議：`<nickname>_sec` 或你常用的 ID
   - **會公開顯示**（在 Hacktivity 上）
4. 密碼：密碼管理器產生（≥16 字元）

### Step 2：驗證 + 安全設定（5 分鐘）

1. **驗證 email**（點信裡的連結）
2. **開 2FA**（Settings → Security → Two-Factor Authentication）
   - 用 TOTP（Google Authenticator / 1Password / Authy）
   - **為什麼必須**：你的帳號被盜 = 你的 reputation 被毀
3. **填 profile**（Settings → Profile）
   - Bio：一句話（「Learning web security, focusing on access control」）
   - 網站：**填你的 GitHub repo**（`ai-vuln-discovery-lab`）
   - **這是你的第一個社會證明**

### Step 3：熟悉介面（10 分鐘）

| 區域 | 用途 |
|---|---|
| **Hacktivity** | 看別人公開的報告（**最重要**） |
| **Programs** | 找目標 |
| **Reports** | 你送出的報告 |
| **Leaderboard** | 排名（**新手不用看**） |

---

## 第二階段：前置作業（3-5 天，不要跳過）

### Step 4：讀 5 份 disclosed reports

**怎麼找**：
1. Hacktivity → 篩選 **`Disclosed`** + **`Web`**
2. 挑 **IDOR** 或 **XSS** 類的（你已經會）
3. 每份讀完，回答三個問題：

```
Q1: 他怎麼描述 Impact？（用幾句話？強調什麼？）
Q2: PoC 給了什麼？（curl？截圖？影片？）
Q3: 標題怎麼寫？（技術名詞 vs 影響描述？）
```

**推薦搜尋**（HackerOne 站內）：
- `IDOR` + `Disclosed`
- `XSS` + `Disclosed` + `Bounty`

**⚠️ 不要做的事**：
- 不要只看技術細節（你看得懂）
- **重點看「怎麼把技術變成別人看得懂的報告」**

### Step 5：寫一份「自己的模板」

**用 [`VDP_REPORT_TEMPLATE.md`](VDP_REPORT_TEMPLATE.md) 為基礎**，但根據你讀的 5 份報告調整：
- Impact 段落要寫幾句？
- 要不要附影片？
- 標題格式？

---

## 第三階段：挑 Program（30 分鐘）

### Step 6：篩選條件（按重要性）

**HackerOne → Programs → 用這些篩選**：

| 篩選條件 | 建議值 | 為什麼 |
|---|---|---|
| **Type** | `Bug Bounty` 或 `VDP` | VDP 無獎金但有記錄 |
| **Assets** | **≤ 3 個** | 多個 = 讀不完 |
| **Response efficiency** | ≥ 80% | 低於 80% 可能不理你 |
| **Offers bounties** | 新手先選 **有 bounty** 的 | 有 bounty 代表 program 認真 |
| **Has a safe harbor** | ✅ 必選 | 法律保護 |
| **Submit reports** | ✅ | 有回報管道 |

### Step 7：排除條件（重要）

**看到這些就跳過**：

| 警訊 | 原因 |
|---|---|
| **"No automated scanning"** | 你只能手動，但沒說清楚範圍 |
| **"Out of scope: everything except X"** | 範圍極窄，浪費時間 |
| **"We do not accept AI-assisted reports"** | **你的 AI 背景反而是風險** |
| **Response efficiency < 60%** | 可能幾個月不回 |
| **Assets > 10** | 讀不完 |
| **只有 wildcard `*.example.com`** | 範圍太大，新手迷路 |

### Step 8：選第一個 program 的具體標準

**用這個順序**：

```
1. 你在用它的產品（有 domain knowledge）
   ↓ 沒有？
2. Assets ≤ 3，且有明確的 API 文件
   ↓ 沒有？
3. 選 "VDP" 類型（無獎金，犯錯成本低）
   ↓ 還是沒有？
4. 從 "New programs" 排序（新 program 報告少）
```

**第一個 program 的建議類型**：
- **中小型 SaaS**（不是 Google/Meta）
- **有公開 API 文件**（你能看懂端點）
- **有 free tier**（你能註冊測試帳號）

---

## 第四階段：動手（第一週）

### Step 9：動手前的 10 項檢查（每次都要）

```
[ ] 1. 讀完 program 的 policy（不是只看 scope）
[ ] 2. 讀完 scope 的 in-scope / out-of-scope
[ ] 3. 確認有沒有 "no automated scanning" 條款
[ ] 4. 確認有沒有 "no AI-assisted reports" 條款
[ ] 5. 註冊測試帳號（用專門 email）
[ ] 6. 記錄開始時間
[ ] 7. 搜 Hacktivity 有沒有該 program 的已公開報告
[ ] 8. 只用**手動**測試（除非 policy 允許自動化）
[ ] 9. 不做 DoS / 資料破壞 / 橫向移動
[ ] 10. 準備好報告模板
```

### Step 10：測試策略（新手版）

**不要做的事**：
- ❌ 用掃描器猛打（多數 policy 禁止）
- ❌ 一次測所有端點（分散注意力）
- ❌ 找「技術上很酷」的漏洞（bounty 付的是 impact）

**要做的事**：
1. **先註冊兩個帳號**（A 和 B）
2. **用 A 的正常操作**，記錄所有 API 請求（DevTools → Network）
3. **用 B 的 session 重放 A 的請求**（改 ID、改 email）
4. **看有沒有越權**（IDOR 的核心）

**這是最高 ROI 的新手策略**——不需要讀程式碼，只需要「兩個帳號 + 改參數」。

### Step 11：送出報告

**用 [`VDP_REPORT_TEMPLATE.md`](VDP_REPORT_TEMPLATE.md)**。

**送出前**：
- ✅ 自己照步驟重現 3 次（100% 成功）
- ✅ Impact 回答了「誰受影響、能做什麼」
- ✅ 沒有超出 scope

**送出後**：
- 等 triage（通常 1-7 天）
- **不要催**（催了會被扣分）
- 如果 7 天沒回，可以在報告留言問進度

---

## 常見錯誤（新手 Top 5）

| 錯誤 | 後果 |
|---|---|
| **超出 scope** | 被 ban，甚至法律風險 |
| **只寫技術不寫 impact** | 被 triage 為 informative（$0） |
| **重複報告** | duplicate（$0） |
| **用掃描器** | 被 ban |
| **催 triage** | reputation 扣分 |

---

## 時間預期（誠實版）

| 階段 | 時間 |
|---|---|
| 註冊 + 設定 | 15 分鐘 |
| 讀 5 份報告 | 3-5 天（每天 1 小時） |
| 挑 program | 30 分鐘 |
| 第一個 VDP 報告 | **1-2 週**（可能找不到） |
| 第一個 bounty | **3-6 個月**（如果持續） |

**第一年賺不到錢是常態**——這是統計事實，不是打擊。

**但如果你把目標設成「3 個月內送出 3 份 VDP 報告」**（不是賺錢），達成率會高很多。

---

## 對照：你現在的位置

| 能力 | 狀態 |
|---|---|
| 挖靶場 | ✅ 22 個自建 + Natas 34 關 |
| 讀程式碼 | ✅ 能讀 Python/TS |
| 寫報告 | ⚠️ 有模板但沒實戰 |
| 平台經驗 | ❌ 零 |
| 真實目標經驗 | ❌ 零 |

**你缺的不是技術，是「平台流程 + 報告寫作」。**

**這兩件事只能靠打真實 program 學。**

---

## 下一步（今天就做）

1. **開 https://hackerone.com/users/sign_up**（5 分鐘）
2. **驗證 email + 開 2FA**（5 分鐘）
3. **填 profile，把 GitHub repo 放上去**（5 分鐘）
4. **Hacktivity → 篩 Disclosed + Web → 讀 1 份**（20 分鐘）

**今天只做這四件事，不要跳到「打 program」。**

---

*本文件為教育用途。所有測試必須在 program 明確授權的範圍內進行。*
