"""Tests for ``cspeek report``: reading prior output without rescanning."""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from cspeek import cli
from cspeek.output import write_json, write_sqlite
from cspeek.report import (
    ReportError,
    load_json_report,
    load_sqlite_report,
    render_report_screen,
    summarise,
)
from cspeek.scanner import scan_targets

from tests.fakes import FakeFetcher, html_response


def sample_results():
    fetcher = FakeFetcher({
        "https://a.test": html_response(csp="default-src *"),
        "https://b.test": html_response(),  # no CSP
        "https://c.test": html_response(
            csp="default-src 'none'; script-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'"
        ),
    })
    return scan_targets(
        ["https://a.test", "https://b.test", "https://c.test"], fetcher=fetcher
    )


class ReportLoadingTests(unittest.TestCase):
    def setUp(self):
        self.results = sample_results()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_load_json_report_round_trips(self):
        path = self.dir / "out.json"
        write_json(self.results, str(path))
        loaded = load_json_report(str(path))
        self.assertEqual(len(loaded), 3)
        urls = [r.fetch.input_url for r in loaded]
        self.assertEqual(
            urls, ["https://a.test", "https://b.test", "https://c.test"]
        )
        self.assertEqual(loaded[0].assessment.level, "critical")

    def test_load_json_report_missing_file(self):
        with self.assertRaises(ReportError):
            load_json_report(str(self.dir / "missing.json"))

    def test_load_json_report_rejects_non_array(self):
        path = self.dir / "bad.json"
        path.write_text(json.dumps({"not": "a list"}))
        with self.assertRaises(ReportError):
            load_json_report(str(path))

    def test_load_sqlite_report_round_trips(self):
        path = self.dir / "out.db"
        write_sqlite(self.results, str(path))
        loaded = load_sqlite_report(str(path))
        self.assertEqual(len(loaded), 3)
        self.assertFalse(loaded[1].fetch.has_csp)

    def test_load_sqlite_report_missing_table(self):
        path = self.dir / "empty.db"
        conn = sqlite3.connect(path)
        conn.close()
        with self.assertRaises(ReportError):
            load_sqlite_report(str(path))

    def test_load_sqlite_report_missing_file(self):
        with self.assertRaises(ReportError):
            load_sqlite_report(str(self.dir / "missing.db"))


class SummariseTests(unittest.TestCase):
    def test_summarise_counts_are_correct(self):
        results = sample_results()
        report = summarise(results)
        self.assertEqual(report.total, 3)
        self.assertEqual(report.with_csp, 2)
        self.assertEqual(report.without_csp, 1)
        self.assertEqual(report.errors, 0)
        self.assertIn("critical", report.level_counts)
        self.assertIn("low", report.level_counts)
        self.assertGreater(sum(report.rule_counts.values()), 0)

    def test_render_report_screen_includes_summary_fields(self):
        report = summarise(sample_results())
        text = render_report_screen(report)
        self.assertIn("Total scanned:  3", text)
        self.assertIn("With CSP:       2", text)
        self.assertIn("Risk levels:", text)


class ReportCliTests(unittest.TestCase):
    def test_report_command_reads_json_without_rescanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            write_json(sample_results(), str(path))

            with mock.patch.object(cli, "scan_targets") as scan_mock:
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    code = cli.main(["report", "--json", str(path)])
                scan_mock.assert_not_called()
        self.assertEqual(code, 0)
        self.assertIn("Total scanned:  3", buffer.getvalue())

    def test_report_command_can_write_summary_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "out.json"
            dest = Path(tmp) / "summary.json"
            write_json(sample_results(), str(src))
            code = cli.main(
                ["report", "--json", str(src), "--output", str(dest), "--quiet"]
            )
            self.assertEqual(code, 0)
            summary = json.loads(dest.read_text())
            self.assertEqual(summary["total"], 3)

    def test_report_requires_a_source(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["report"])
        self.assertEqual(ctx.exception.code, 2)

    def test_report_missing_json_file_is_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["report", "--json", "/nonexistent/path.json"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
