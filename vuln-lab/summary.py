"""vuln-lab 靶場索引產生器。

掃描 vuln-lab/ 下的靶場目錄，收集主程式、驗證腳本與結果 JSON，
產生一份 Markdown 索引。純檔案掃描，不執行任何靶場程式。

用法：
    python vuln-lab/summary.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Windows CI（cp1252）輸出中文會 UnicodeEncodeError，強制 UTF-8
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# 不是「主程式」的檔名規則
_EXCLUDED_PREFIXES = ("verify_", "gen_")
_EXCLUDED_NAMES = {"run_all.py", "summary.py"}

# 工具目錄，不是靶場
_EXCLUDED_DIRS = {"tests", "findings", "targets", "__pycache__", "external-lab"}


def _is_main_script(name: str) -> bool:
    """判斷檔名是否為靶場主程式（.py 或 .php）。"""
    if not name.endswith((".py", ".php")):
        return False
    if name in _EXCLUDED_NAMES:
        return False
    if name.startswith(_EXCLUDED_PREFIXES):
        return False
    return True


def _count_passed(result_path: Path) -> int | None:
    """從結果 JSON 計算 present 為 true 的項目數；無法解析時回傳 None。"""
    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    entries = data
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        entries = data["results"]
    if not isinstance(entries, list):
        return None
    return sum(1 for e in entries if isinstance(e, dict) and e.get("present") is True)


def scan_targets(root: Path) -> list[dict]:
    """掃描 root 下的靶場目錄。

    Returns:
        每個靶場一個 dict，鍵為 name / main_scripts / verify_scripts /
        result_json / passed。
    """
    root = Path(root)
    if not root.is_dir():
        return []

    targets: list[dict] = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        if d.name in _EXCLUDED_DIRS:
            continue

        files = sorted(f.name for f in d.iterdir() if f.is_file())
        main_scripts = [n for n in files if _is_main_script(n)]
        if not main_scripts:
            continue

        verify_scripts = [
            n for n in files if n.startswith("verify_") and n.endswith(".py")
        ]
        result_json = next(
            (n for n in files if n.endswith("_result.json")), None
        )
        passed = _count_passed(d / result_json) if result_json else None

        targets.append({
            "name": d.name,
            "main_scripts": main_scripts,
            "verify_scripts": verify_scripts,
            "result_json": result_json,
            "passed": passed,
        })

    return targets

def render_index(targets: list[dict]) -> str:
    """把掃描結果渲染成 Markdown 索引文件。"""
    lines = [
        "# vuln-lab 靶場索引",
        "",
        "> 本檔案由 `vuln-lab/summary.py` 自動產生，請勿手動編輯。",
        "> 重新產生：`python vuln-lab/summary.py`",
        "",
        "| 靶場 | 主程式 | 驗證腳本 | 結果 JSON | 通過項目 |",
        "|---|---|---|---|---|",
    ]
    for t in targets:
        mains = ", ".join(t["main_scripts"]) or "—"
        verifies = ", ".join(t["verify_scripts"]) or "—"
        result = t["result_json"] or "—"
        passed = str(t["passed"]) if t["passed"] is not None else "—"
        lines.append(
            "| %s | %s | %s | %s | %s |"
            % (t["name"], mains, verifies, result, passed)
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    """CLI 入口：掃描同目錄下的靶場並寫出 INDEX.md。"""
    root = Path(__file__).resolve().parent
    targets = scan_targets(root)
    out = root / "INDEX.md"
    out.write_text(render_index(targets), encoding="utf-8")
    print("產生 %d 個靶場索引 → %s" % (len(targets), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
