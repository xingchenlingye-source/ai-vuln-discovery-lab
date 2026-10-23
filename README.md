# AI 輔助漏洞挖掘 — 學習筆記與自建靶場

> **教育用途的漏洞研究專案。所有測試只在 `127.0.0.1` 的自建靶場上進行，未接觸任何真實外部目標。**

本專案記錄「AI 輔助漏洞挖掘」的完整學習路徑：從 OWASP Top 10 理論、自建靶場實作、
到受公開教學案例啟發的漏洞重現。

> 註：本專案曾以 OverTheWire Natas 作為練習平台。依其平台規則，**通關密碼與解法細節不公開**，
> 相關內容已從本倉庫中抽離。

---

## 內容結構

| 路徑 | 內容 |
|---|---|
| `ai-vuln-discovery-report.html` | **主研究報告**（九章 + 參考文獻，單檔自包含） |
| `vuln-lab/` | **22 個自建靶場**、34 份實作報告、驗證腳本 |
| `vuln-lab/INDEX.md` | 靶場索引（由 `summary.py` 自動產生） |
| `docs/superpowers/plans/` | 開發計畫文件 |
| `evidence/` | 外部資料擷取證據（原始 HTML／文字） |

### 主報告章節

1. 研究背景與方法
2. AI 輔助漏洞挖掘的理論基礎
3. 工具與技術棧
4. OWASP Top 10:2025 對照
5. 自建靶場方法論
6. 實作記錄（S1／S2／S3 系列）
7. 量化結果（fuzzing 命中率、盲注加速比）
8. 限制與倫理
9. 結論與展望
10. 參考文獻（含完整 URL）

---

## 快速開始

```bash
# 需要 Python 3.12（標準庫即可）
cd vuln-lab

# 跑全部靶場驗證（9 個核心靶場）
python run_all.py

# 重新產生靶場索引
python summary.py
```

部分靶場需要額外環境（見各目錄說明）：

| 靶場 | 額外需求 |
|---|---|
| `phplab` / `pharlab` | PHP 8.x |
| `perllab` | Perl 5.40+ |
| `ecblab` | `pycryptodome` |

---

## 靶場清單

完整清單見 **[`vuln-lab/INDEX.md`](vuln-lab/INDEX.md)**（自動產生，含主程式／驗證腳本／結果 JSON）。

涵蓋的漏洞類型：

- **注入類**：SQLi（含盲注）、命令注入、LFI、SSTI、XXE
- **加密類**：ECB block splicing、padding oracle、JWT 弱點
- **反序列化**：PHP unserialize、PHAR metadata、Python pickle
- **Web 邏輯**：IDOR、CSRF、XSS、SSRF、競態條件
- **供應鏈**：依賴混淆、簽章繞過
- **AI 特有**：prompt injection、RAG 資料洩漏

---

## 安全與倫理聲明

### 這是教學專案，不是攻擊工具

- ✅ 所有靶場只綁定 `127.0.0.1`
- ✅ 所有「機密」都是假資料（`FLAG{...}`、`DB_PASSWORD=SuperSecretDbPass123` 等）
- ✅ 所有 payload 只觸發驗證，不執行外連、持久化或破壞
- ✅ OverTheWire Natas 部分遵守平台規則，**通關密碼不公開**（已從程式碼與報告中遮蔽）

### 如果你要使用本專案的程式碼

- **不要**把靶場暴露到公網
- **不要**把 payload 用在未授權目標上
- 未授權的漏洞挖掘在台灣可處 3 年以下有期徒刑（刑法 358–363），中國大陸為刑法 285–287

### 授權範圍

本專案的 Natas 實戰部分遵守 [OverTheWire 的規則](https://overthewire.org/rules/)：
Natas 明確授權學習者通關，但要求不公開密碼與解法細節。

---

## 驗證狀態

| 項目 | 狀態 |
|---|---|
| 核心靶場 `run_all.py` | 9/9 通過 |
| ECB 靶場 | 4/4 通過 |
| Perl 三缺口 | 3/3 通過 |
| PHAR 靶場 | 2/2 通過 |
| OverTheWire Natas | 完成練習（解法與密碼不公開） |
| 報告完整性檢查 | div/li/table 全部平衡、0 失效錨點 |

---

## 授權

MIT License — 見 [`LICENSE`](LICENSE)。

**但請注意**：授權的是**程式碼**，不是「授權你攻擊任何目標」。
靶場程式碼可自由使用；漏洞利用知識的合法使用範圍由你自己的司法管轄區決定。

---

## 致謝

- [OverTheWire](https://overthewire.org/) — 練習平台（規則遵守：解法不公開）
- [OWASP](https://owasp.org/) — Top 10 與測試指南
- [obra/superpowers](https://github.com/obra/superpowers) — 開發流程 skills
