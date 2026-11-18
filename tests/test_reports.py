import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import analysis
import finding_ai


class ReportTests(unittest.TestCase):
    def test_csv_formula_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.csv"
            analysis.export_csv([analysis.Finding("Medium", "Task", "=example")], path)
            with path.open(encoding="utf-8-sig", newline="") as stream:
                self.assertEqual(list(csv.DictReader(stream))[0]["Name"], "'=example")

    def test_explanation_with_local_model(self):
        replies = [{"models": [{"name": "llama3.1:8b", "size": 100}]}, {"response": "Review signature."}]
        finding = analysis.Finding("Medium", "Task", "test", command="private-command")
        with patch.dict("os.environ", {"SCANNER_OLLAMA_MODEL": "llama3.1:8b"}):
            with patch.object(finding_ai, "_request", side_effect=replies) as request:
                self.assertEqual(finding_ai.explain_finding(finding)[1], "Review signature.")
                self.assertNotIn(b"private-command", request.call_args.args[2])

    def test_redacted_export_excludes_untrusted_text(self):
        from review_tools import redacted_report
        finding = analysis.Finding("High", "Task", "Private name", command="private-command",
                                   reasons=["private path"])
        self.assertEqual(redacted_report([finding]), "Entry 001 | High | Task | Current")
