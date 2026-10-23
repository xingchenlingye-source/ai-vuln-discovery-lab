"""vuln-lab summary 產生器的測試。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# summary.py 位於 vuln-lab/ 根目錄，測試位於 vuln-lab/tests/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from summary import render_index, scan_targets  # noqa: E402


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

    def test_accepts_php_main_script(self):
        """靶場主程式也可能是 .php（如 pharlab.php）。"""
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            d = lab / "phplab"
            d.mkdir()
            (d / "phplab.php").write_text("", encoding="utf-8")
            (d / "gen_helper.php").write_text("", encoding="utf-8")

            targets = scan_targets(lab)

            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0]["main_scripts"], ["phplab.php"])

    def test_skips_dirs_without_main_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            (lab / ".github").mkdir()
            (lab / "empty").mkdir()
            self.assertEqual(scan_targets(lab), [])

    def test_handles_missing_result_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            d = lab / "nolab"
            d.mkdir()
            (d / "nolab.py").write_text("", encoding="utf-8")

            targets = scan_targets(lab)

            self.assertEqual(len(targets), 1)
            self.assertIsNone(targets[0]["result_json"])
            self.assertIsNone(targets[0]["passed"])



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
        self.assertIn("demolab_result.json", md)
        self.assertRegex(md, r"\| demolab \|.*\| 2 \|")

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

    def test_empty_targets(self):
        md = render_index([])
        self.assertIn("# vuln-lab 靶場索引", md)



    def test_skips_tool_directories(self):
        """tests/ 與 findings/ 是工具目錄，不是靶場。"""
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            for name in ("tests", "findings", "targets", "external-lab"):
                d = lab / name
                d.mkdir()
                (d / "test_x.py").write_text("", encoding="utf-8")
            targets = scan_targets(lab)
            self.assertEqual(targets, [])

if __name__ == "__main__":
    unittest.main()
