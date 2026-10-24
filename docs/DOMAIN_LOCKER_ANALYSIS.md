# `domain-locker` 程式碼結構分析

> 分析日期：2026-10-24
> 目標：`lissy93/domain-locker` @ `main`（1,551 stars）
> 方法：**本地 clone + 靜態閱讀**（未對生產環境送出任何請求）
> 授權依據：專案有 `SECURITY.md`（明確的漏洞回報管道）

---

## 一、技術棧

| 層 | 技術 |
|---|---|
| **框架** | Angular 19 + **Analog.js**（Angular 的 SSR 框架，基於 Nitro/H3） |
| **語言** | TypeScript（415 個 `.ts`） |
| **認證** | **Supabase**（managed 模式）／**自建 HMAC session**（self-hosted 模式） |
| **資料庫** | **better-sqlite3** 或 **PostgreSQL**（透過 **Kysely** query builder） |
| **前端 UI** | PrimeNG + Tailwind |
| **測試** | Vitest + Angular TestBed |

**規模**：716 個檔案（不含 `node_modules`），415 個 TypeScript。

---

## 二、目錄結構

```
src/
├── app/                    # Angular 前端
│   ├── pages/              # 頁面（含 (auth)/ 群組）
│   ├── services/           # API client
│   ├── utils/              # auth.interceptor.ts
│   └── components/
├── server/                 # Analog.js 後端（SSR + API）
│   ├── lib/                # ★ 核心：handler.ts, auth.ts, errors.ts
│   ├── routes/             # ★ API endpoints（file-based routing）
│   │   ├── v1/             # 版本化 API
│   │   │   ├── admin/      # ← 管理端點
│   │   │   ├── auth/       # ← 登入/登出/狀態
│   │   │   ├── domains/    # ← 域名 CRUD
│   │   │   ├── assets/     # ← 統計資料
│   │   │   ├── links/      # ← 連結
│   │   │   ├── subdomains/ # ← 子域名
│   │   │   ├── tags/       # ← 標籤
│   │   │   └── uptime/     # ← 監控資料
│   │   └── *.ts            # 其他端點
│   ├── db/                 # Kysely repos
│   └── utils/
├── shared/                 # 前後端共用型別
└── types/
```

---

## 三、認證架構（關鍵）

### 雙模式設計

```typescript
const IS_MANAGED = import.meta.env['DL_ENV_TYPE'] === 'managed';
```

| 模式 | 認證方式 | 資料儲存 |
|---|---|---|
| **Managed**（官方託管） | **Supabase JWT**（`Authorization: Bearer <token>`） | Supabase |
| **Self-hosted**（自架） | **單一密碼**（`DL_AUTH_PASSWORD`）+ HMAC session cookie | 本地 SQLite/Postgres |

### Self-hosted 的 session 機制（`src/server/lib/auth.ts`）

```typescript
// Cookie: dl_session = <expiresAt>.<nonce>.<signature>
function signingKey(): Buffer {
  const explicit = process.env['DL_AUTH_SECRET'];
  if (explicit) return Buffer.from(explicit);
  // 否則用 password 派生
  return scryptSync(password, 'domain-locker:session', 32);
}
```

**安全設計良好**：
- ✅ `timingSafeEqual`（防時序攻擊）
- ✅ `scryptSync` 派生簽章金鑰
- ✅ `httpOnly` cookie
- ✅ `sameSite: 'lax'`
- ✅ API key 也用 `timingSafeEqual`

### ⚠️ 但有一個關鍵設計

```typescript
export function isAuthorised(event: H3Event): boolean {
  return !isAuthEnabled() || hasValidSession(event) || hasValidApiKey(event);
}
```

**如果沒有設 `DL_AUTH_PASSWORD`** → `isAuthEnabled()` = false → **`isAuthorised()` 永遠 true**。

**這是刻意的設計**（註解寫：「Optional: self-hosted instances stay open unless a password is configured」）。

**風險**：如果使用者部署到公網但忘了設密碼 → **完全開放**。

**但這是「部署配置問題」，不是程式碼漏洞**。

---

## 四、授權模型（核心發現）

### `defineApiRoute` 的預設保護

```typescript
// src/server/lib/handler.ts
if (!options.public) requireAuth(event);
```

**所有 API 預設需要登入** ✓

### ❗️ 但沒有「角色」概念

**搜尋 `isAdmin` / `requireAdmin` / `role` / `app_metadata`**：

```
(無)
```

**專案完全沒有角色檢查。**

### Admin 端點實際長怎樣

```typescript
// src/server/routes/v1/admin/delete-data.post.ts
export default defineApiRoute({ write: true, body: schema }, async ({ db, body }) => {
  const allowed = new Set<string>(db.admin.deletableTables);
  const tables = body.tables?.filter((table) => allowed.has(table));
  await db.admin.deleteAllData(tables?.length ? tables : undefined);
  return { deleted: true };
});
```

**只有 `requireAuth`（預設），沒有 admin 檢查。**

**為什麼這不是漏洞**：
- `v1/*` 端點**只在 self-hosted 模式下提供**（見下方程式碼）
- self-hosted 是**單一使用者**設計（一個密碼）
- 「admin」和「使用者」是同一個人

```typescript
// src/server/lib/handler.ts
if (!usesSelfHostedData(process.env)) {
  throw new ApiError('forbidden', 'This API is only served by self-hosted instances');
}
```

**Managed 模式（多使用者）用前端直接連 Supabase，不走這些 API。**

---

## 五、高價值端點（如果要做進一步分析）

| 端點 | 方法 | 功能 | 值得看嗎 |
|---|---|---|---|
| `/api/v1/admin/delete-data` | POST | 刪除所有資料 | ⚠️ 無 admin 檢查，但設計如此 |
| `/api/v1/admin/database` | GET | DB 結構資訊 | 同上 |
| `/api/v1/export` | GET | 匯出所有資料 | 看是否洩漏超出預期 |
| `/api/v1/domains/[id]` | GET/PUT/DELETE | 域名 CRUD | **無 owner 檢查**（單租戶合理） |
| `/api/v1/auth/login` | POST | 登入 | ✅ 有 `timingSafeEqual` |
| `/api/v1/share-target` | — | 分享功能 | **值得看**（跨使用者？） |

---

## 六、誠實結論：這個專案**不適合新手第一個目標**

### 為什麼

| 因素 | 評估 |
|---|---|
| **設計品質** | 高（timing-safe、scrypt、httpOnly、sameSite） |
| **架構清晰** | 是（handler 統一包裝 auth + validation） |
| **角色模型** | 無（self-hosted 單租戶）→ **沒有 IDOR 可挖** |
| **已有報告** | 1,551 stars，作者活躍 → 可能已有人看過 |
| **新手切入點** | 少（沒有明顯的授權缺口） |

### 真正可能的方向（如果你要繼續）

1. **`share-target` 端點**——分享功能通常涉及跨使用者，值得看
2. **`export.get.ts`**——匯出功能是否洩漏超出預期的資料
3. **Nitro/Analog 的 SSR 渲染**——模板注入？
4. **依賴套件**——`package.json` 的 `overrides` 很多（作者在處理 CVE），但仍可能有漏

### 我的建議

**換一個「多租戶」的目標**——只有多租戶才會有 IDOR/權限提升的空間。

**這不是說 domain-locker 不安全**——恰恰相反，**它設計得很好，所以難挖**。

**對新手來說，「難挖」不是好事**——你會花很多時間卻找不到東西，容易打擊信心。

---

## 七、從這個專案學到的東西

即使沒找到漏洞，這個專案的架構值得學習：

1. **統一的 handler 包裝**（`defineApiRoute`）——auth、validation、error 一次處理
2. **雙模式設計**（managed vs self-hosted）——用一個環境變數切換
3. **timing-safe 比較**——`safeEquals` 用在密碼和 API key
4. **scrypt 派生金鑰**——即使沒設 secret，簽章金鑰也不是可預測的
5. **明確的 read-only 模式**——`DL_DISABLE_WRITE_METHODS`

**這些都是寫安全程式碼的好範例。**

---

## 八、下一步建議

**如果你想繼續分析 domain-locker**：
- 讀 `src/server/routes/share-target.ts`
- 讀 `src/server/routes/v1/export.get.ts`
- 讀 `src/server/db/repos/` 的查詢（看有沒有 SQL 拼接）

**如果你想找「好挖」的目標**：
- 換成**多租戶 SaaS**（有 `tenant_id` 概念的）
- 或**年輕的專案**（<1k stars，程式碼未經審視）
- 或**明確寫「歡迎新手」的專案**

**但還是不建議**一開始就打 bounty——先讀 5 份 disclosed reports 再動手。

---

*本分析為授權範圍內的靜態閱讀（本地 clone），未對任何生產環境送出請求。*
