# vuln-lab INDEX 產生器 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 掃描 `vuln-lab/` 下所有靶場目錄，產生一份 Markdown 索引 `INDEX.md`，列出每個靶場的主程式、驗證腳本、結果 JSON 與通過項目數。

**Architecture:** 兩個純函式（`scan_targets` 掃描目錄、`render_index` 渲染 Markdown）加一個 CLI 入口。只讀取檔案系統，不執行任何靶場程式，因此可安全地在任何時候重跑。

**Tech Stack:** Python 3.12 標準庫（`pathlib`, `json`, `unittest`）；無第三方依賴。

**Spec:** 本計畫即為 small change 的規格（`brainstorming` 階段已於對話中確認：Python、只用標準庫、輸出 `vuln-lab/INDEX.md`）。

## Global Constraints

- 只使用 Python 標準庫（不得引入第三方套件）
- 繁體中文輸出（檔名與程式碼識別字用英文，說明文字用中文）
- 不執行任何靶場程式（純檔案掃描）
- 輸出檔案：`vuln-lab/INDEX.md`
- 測試框架：`unittest`（`pytest` 未安裝）

## Review Focus

- 靶場目錄含非 Python 主程式（如 `pharlab.php`）——掃描需接受 `.py` 與 `.php`
- 目錄含輔助程式（`gen_*.py`, `verify_*.py`, `run_all.py`, `summary.py` 自己）——需排除
- 結果 JSON 可能是 dict 或 list——`present: true` 的計數要兩種都能處理
- 目錄存在但完全沒有主程式（如 `.github`）——需跳過，不產生空列
- `INDEX.md` 重複產生時應覆蓋而非附加

---

## Task 1: `scan_targets(root) -> list[dict]`

**Files:**
- Create: `vuln-lab/summary.py`
- Create: `vuln-lab/tests/test_summary.py`

**Interfaces:**
- Produces: `scan_targets(root: Path) -> list[dict]`，每個 dict 含鍵：
  - `name: str` — 目錄名
  - `main_scripts: list[str]` — 主程式檔名（`.py`/`.php`，排除 `verify_*`/`gen_*`/`run_all.py`/`summary.py`）
  - `verify_scripts: list[str]` — `verify_*.py`
  - `result_json: str | None` — `*_result.json` 檔名
  - `passed: int | None` — JSON 中 `present: true` 的數量；無 JSON 則 `None`

- [ ] **Step 1: Write the failing test**

```python
import json
import tempfile
import unittest
from pathlib import Path

from summary import scan_targets


class TestScanTargets(unittest.TestCase):
    def test_finds_scripts_and_counts_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp) / "vuln-lab"
            d = lab / "demolab"
            d.mkdir(parents=True)
            (d / "demolab.py").write_text("", encoding="utf-8")
            (d / "verify_demolab.py").write_text("", encoding="utf-8")
            (d / "gen_helper.py").write_text("", encoding="utf-8")
            (d / "demolab_result.json").write_text(
                json.dumps([
                    {"name": "a", "present": True},
                    {"name": "b", "present": False},
                    {"name": "c", "present": True},
                ]), encoding="utf-8")

            targets = scan_targets(lab)

            self.assertEqual(len(targets), 1)
            t = targets[0]
            self.assertEqual(t["name"], "demolab")
            self.assertEqual(t["main_scripts"], ["demolab.py"])
            self.assertEqual(t["verify_scripts"], ["verify_demolab.py"])
            self.assertEqual(t["result_json"], "demolab_result.json")
            self.assertEqual(t["passed"], 2)

    def test_skips_dirs_without_main_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            (lab / ".github").mkdir()
            (lab / "empty").mkdir()
            self.assertEqual(scan_targets(lab), [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest vuln-lab.tests.test_summary -v`（從專案根目錄）
Expected: FAIL with `ModuleNotFoundError: No module named 'summary'`

- [ ] **Step 3: Implement `scan_targets` in `vuln-lab/summary.py`**

Signature: `def scan_targets(root: Path) -> list[dict]:`
- 走訪 `root` 下的直接子目錄
- 對每個目錄收集 `.py`/`.php` 檔名
- 主程式 = 排除 `verify_` 開頭、`gen_` 開頭、`run_all.py`、`summary.py`
- 驗證腳本 = `verify_` 開頭且 `.py` 結尾
- 結果 JSON = 檔名以 `_result.json` 結尾
- `passed`：讀 JSON，若 list 則計 `present is True`；若 dict 且有 `results` key 則同樣處理
- 無主程式的目錄跳過

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest vuln-lab.tests.test_summary -v`
Expected: `OK`（2 tests）

- [ ] **Step 5: Commit**

```bash
git add vuln-lab/summary.py vuln-lab/tests/test_summary.py
git commit -m "feat(vuln-lab): add scan_targets for INDEX generator"
```

---

## Task 2: `render_index(targets) -> str` 與 CLI

**Files:**
- Modify: `vuln-lab/summary.py`
- Modify: `vuln-lab/tests/test_summary.py`

**Interfaces:**
- Consumes: `scan_targets` 的輸出（Task 1）
- Produces: `render_index(targets: list[dict]) -> str`，回傳完整 Markdown 文件字串，含標題、說明、表格
- Produces: `main() -> int`，CLI 入口，寫出 `vuln-lab/INDEX.md`

- [ ] **Step 1: Write the failing test**

```python
from summary import render_index


class TestRenderIndex(unittest.TestCase):
    def test_renders_table_row(self):
        targets = [{
            "name": "demolab",
            "main_scripts": ["demolab.py"],
            "verify_scripts": ["verify_demolab.py"],
            "result_json": "demolab_result.json",
            "passed": 2,
        }]
        md = render_index(targets)
        self.assertIn("# vuln-lab 靶場索引", md)
        self.assertIn("| demolab |", md)
        self.assertIn("demolab.py", md)
        self.assertIn("verify_demolab.py", md)
        self.assertIn("2", md)

    def test_handles_missing_result(self):
        targets = [{
            "name": "nolab",
            "main_scripts": ["nolab.py"],
            "verify_scripts": [],
            "result_json": None,
            "passed": None,
        }]
        md = render_index(targets)
        self.assertIn("| nolab |", md)
        self.assertIn("—", md)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest vuln-lab.tests.test_summary -v`
Expected: FAIL with `ImportError: cannot import name 'render_index'`

- [ ] **Step 3: Implement `render_index` and `main` in `vuln-lab/summary.py`**

- `render_index`：產生標題 `# vuln-lab 靶場索引`、一行說明（自動產生）、表格（表頭：靶場 / 主程式 / 驗證腳本 / 結果 JSON / 通過項目）
- 多個主程式用 `, ` 連接；空欄位用 `—`
- `main()`：`root = Path(__file__).parent`；`targets = scan_targets(root)`；寫 `root / "INDEX.md"`（覆蓋）；印出摘要（`產生 N 個靶場索引 → INDEX.md`）；回傳 0

- [ ] **Step 4: Run all tests**

Run: `python -m unittest vuln-lab.tests.test_summary -v`
Expected: `OK`（4 tests）

- [ ] **Step 5: Run against the real vuln-lab and inspect**

Run: `python vuln-lab/summary.py`
Expected: 產生 `vuln-lab/INDEX.md`，內含 20+ 個靶場列

- [ ] **Step 6: Commit**

```bash
git add vuln-lab/summary.py vuln-lab/tests/test_summary.py vuln-lab/INDEX.md
git commit -m "feat(vuln-lab): render INDEX.md from scanned targets"
```

---

## Self-Review

**1. Spec coverage:** 兩個 Task 覆蓋掃描、渲染、CLI 與測試。✓

**2. Step scan:** 每個 step 只有一個動作與可檢查結果（寫測試→跑測試→實作→跑測試→commit）。✓

**3. Type consistency:** `scan_targets` 回傳的 dict 鍵（`name`/`main_scripts`/`verify_scripts`/`result_json`/`passed`）在 Task 2 的測試中一致使用。✓

**4. Review Focus:**
- `.php` 主程式 → Task 1 Step 3 明確要求接受 `.py`/`.php`，Step 1 測試未涵蓋，**補測試**：在 `test_finds_scripts_and_counts_passed` 加一個 `.php` 檔
- 輔助程式排除 → Step 3 明確
- JSON 兩種形態 → Step 3 明確
- 空目錄跳過 → Task 1 測試涵蓋
- 覆蓋而非附加 → Step 3 明確 `write_text`

**5. Proportion:** 計畫約 200 行，實作約 90 行，比例合理。✓
