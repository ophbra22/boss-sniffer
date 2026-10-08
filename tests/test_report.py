import json
from pathlib import Path
import re
import tempfile
import unittest

import report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Path(self.temp.name) / "settings.dat"
        self.settings.write_text(
            "WORKERS = demo:127.0.0.1\n"
            "BLACKLIST = 203.0.113.10:blocked,203.0.113.20:other\n",
            encoding="utf-8",
        )

    def record(self, outgoing="True", app="browser.exe"):
        return [443, outgoing, 60, "Unknown", app, "00:00:00:00:00:01"]

    def test_incoming_and_outgoing_are_not_reversed(self):
        data = {"198.51.100.10": [self.record(), self.record(), self.record("False")]}
        stats = report.ip_statistic(data, self.settings)
        self.assertEqual(stats[:2], (1, 2))
        self.assertEqual(stats[2], [["198.51.100.10", 3]])
        self.assertEqual(stats[3], [(443, 3)])

    def test_no_blacklist_match_produces_no_alert(self):
        stats = report.ip_statistic({"198.51.100.10": [self.record()]}, self.settings)
        self.assertEqual(stats[-1], [])

    def test_later_nonmatch_does_not_erase_blacklist_match(self):
        stats = report.ip_statistic({"203.0.113.10": [self.record()]}, self.settings)
        self.assertEqual(stats[-1], ["demo:127.0.0.1"])

    def test_empty_and_small_reports_render_valid_chart_data(self):
        for data in ({}, {"198.51.100.10": [self.record()]}):
            with self.subTest(data=data):
                output = Path(self.temp.name) / "output" / "report.html"
                report.generate_report(data, output, self.settings)
                html = output.read_text(encoding="utf-8")
                self.assertNotRegex(html, r"%%[A-Z_]+%%")
                labels = re.findall(r"labels: (\[[^\n]*\]),", html)
                self.assertEqual(len(labels), 6)
                for label in labels:
                    self.assertIsInstance(json.loads(label), list)
                self.assertTrue((output.parent / "assets/css/style.css").is_file())
                self.assertIn("No blacklist matches", html)

    def test_labels_cannot_break_out_of_script(self):
        app = "</script><script>alert('x')</script>"
        output = Path(self.temp.name) / "report.html"
        report.generate_report({"198.51.100.10": [self.record(app=app)]}, output, self.settings)
        html = output.read_text(encoding="utf-8")
        self.assertNotIn(app, html)
        self.assertIn(r"\u003c/script\u003e", html)

    def test_invalid_records_are_rejected_before_aggregation(self):
        bad_records = [[443], [443, "maybe", 60, "Unknown", "app", "mac"],
                       [443, "True", -1, "Unknown", "app", "mac"]]
        for record in bad_records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                report.ip_statistic({"198.51.100.10": [record]}, self.settings)


if __name__ == "__main__":
    unittest.main()
