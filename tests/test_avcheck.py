import json
import tempfile
import unittest
from pathlib import Path

import AVCheck


RULES = {
    "version": 1,
    "signatures": [
        {"process": "MsMpEng.exe", "products": ["Windows Defender"]},
        {"process": "agent.exe", "products": ["Product A", "Product B"]},
    ],
}


class AVCheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.rules = self.root / "rules.json"
        self.rules.write_text(json.dumps(RULES), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_matches_are_case_insensitive_and_deduplicated(self):
        signatures = AVCheck.load_signatures(self.rules)
        matches = AVCheck.find_matches(["msmpeng.EXE", "MSMPENG.exe", "other.exe"], signatures)
        self.assertEqual(matches, [{"process": "msmpeng.EXE", "rule_process": "MsMpEng.exe", "products": ["Windows Defender"]}])

    def test_parses_supported_input_formats(self):
        self.assertEqual(list(AVCheck.parse_processes("agent.exe\n", "process-list")), ["agent.exe"])
        self.assertEqual(list(AVCheck.parse_processes("agent.exe  42 Services\n", "tasklist")), ["agent.exe"])
        csv_text = "Image Name,PID,Session Name\nagent.exe,42,Services\n"
        self.assertEqual(list(AVCheck.parse_processes(csv_text, "auto")), ["agent.exe"])

    def test_invalid_rules_return_rules_error(self):
        invalid_rules = self.root / "invalid.json"
        invalid_rules.write_text("{", encoding="utf-8")
        input_file = self.root / "processes.txt"
        input_file.write_text("agent.exe\n", encoding="utf-8")
        self.assertEqual(AVCheck.main([str(input_file), "--rules", str(invalid_rules)]), AVCheck.EXIT_RULES_ERROR)

    def test_missing_input_returns_input_error(self):
        self.assertEqual(AVCheck.main([str(self.root / "missing.txt"), "--rules", str(self.rules)]), AVCheck.EXIT_INPUT_ERROR)


if __name__ == "__main__":
    unittest.main()
