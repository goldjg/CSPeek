"""Tests for JSON, CSV, and SQLite output writers."""

import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from csp_scanner.scanner import scan_targets

from tests.fakes import FakeFetcher, html_response


def sample_results():
    fetcher = FakeFetcher({
        "https://a.test": html_response(csp="default-src *"),
        "https://b.test": html_response(),  # no CSP
    })
    return scan_targets(["https://a.test", "https://b.test"], fetcher=fetcher)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.results = sample_results()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_json_output(self):
        from csp_scanner.output import write_json

        path = self.dir / "out.json"
        write_json(self.results, str(path))
        data = json.loads(path.read_text())
        self.assertEqual(len(data), 2)
        first = data[0]
        self.assertEqual(first["input_url"], "https://a.test")
        self.assertEqual(first["csp"], "default-src *")
        self.assertTrue(first["has_csp"])
        self.assertIsInstance(first["risk_score"], int)
        self.assertTrue(first["findings"])
        self.assertIn("rule_id", first["findings"][0])
        self.assertFalse(data[1]["has_csp"])
        self.assertEqual(data[1]["risk_level"], "critical")

    def test_csv_output(self):
        from csp_scanner.output import CSV_FIELDS, write_csv

        path = self.dir / "out.csv"
        write_csv(self.results, str(path))
        with open(path, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(set(rows[0].keys()), set(CSV_FIELDS))
        self.assertIn("CSP-020", rows[0]["findings"])

    def test_sqlite_output(self):
        from csp_scanner.output import write_sqlite

        path = self.dir / "out.db"
        write_sqlite(self.results, str(path))
        conn = sqlite3.connect(path)
        try:
            rows = conn.execute(
                "SELECT input_url, final_url, status_code, csp, "
                "csp_report_only, has_csp, risk_score, risk_level, "
                "findings, error, scan_timestamp FROM scans ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 2)
        url, final, status, csp_value, ro, has_csp, score, level, findings, error, ts = rows[0]
        self.assertEqual(url, "https://a.test")
        self.assertEqual(status, 200)
        self.assertEqual(csp_value, "default-src *")
        self.assertEqual(has_csp, 1)
        self.assertGreater(score, 0)
        self.assertTrue(json.loads(findings))
        self.assertIsNone(error)
        self.assertTrue(ts)

    def test_sqlite_appends_to_existing_db(self):
        from csp_scanner.output import write_sqlite

        path = self.dir / "out.db"
        write_sqlite(self.results, str(path))
        write_sqlite(self.results, str(path))
        conn = sqlite3.connect(path)
        try:
            count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 4)


if __name__ == "__main__":
    unittest.main()
