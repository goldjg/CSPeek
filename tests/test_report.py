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
from cspeek.models import DuplicateFinalUrl, ScanMetadata, SkippedLink
from cspeek.output import write_json, write_sqlite
from cspeek.report import (
    ReportError,
    load_json_report,
    load_json_report_full,
    load_sqlite_report,
    load_sqlite_report_full,
    render_report_screen,
    summarise,
)
from cspeek.scanner import scan_targets, scan_targets_with_metadata

from tests.fakes import FakeFetcher, html_response, redirect_response


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


def sample_results_with_duplicates():
    """Four fetchable targets plus one that errors.

    ``a`` and ``b`` share an identical CSP string (the repeated-policy
    case); ``c`` is fully hardened and unique; ``d`` has no CSP at all;
    ``e`` is unreachable (fetch error, no assessment).
    """
    shared_csp = "default-src *"
    fetcher = FakeFetcher({
        "https://a.test": html_response(csp=shared_csp),
        "https://b.test": html_response(csp=shared_csp),
        "https://c.test": html_response(
            csp="default-src 'none'; script-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'"
        ),
        "https://d.test": html_response(),  # no CSP at all
    })
    return scan_targets(
        ["https://a.test", "https://b.test", "https://c.test", "https://d.test",
         "https://e.test"],
        fetcher=fetcher,
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

    def test_summarise_counts_fetch_errors(self):
        report = summarise(sample_results_with_duplicates())
        self.assertEqual(report.total, 5)
        self.assertEqual(report.errors, 1)

    def test_summarise_from_sqlite_loaded_results_includes_new_fields(self):
        """Backwards compatibility: SQLite-loaded results still aggregate."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.db"
            write_sqlite(sample_results_with_duplicates(), str(path))
            loaded = load_sqlite_report(str(path))
        report = summarise(loaded)
        self.assertEqual(report.total, 5)
        self.assertEqual(len(report.repeated_policies), 1)
        self.assertTrue(report.highest_risk_urls)
        self.assertTrue(report.remediation_themes)


class RepeatedPolicyGroupingTests(unittest.TestCase):
    def test_identical_csp_strings_are_grouped(self):
        report = summarise(sample_results_with_duplicates())
        self.assertEqual(len(report.repeated_policies), 1)
        group = report.repeated_policies[0]
        self.assertEqual(group.csp, "default-src *")
        self.assertEqual(group.count, 2)
        self.assertEqual(group.example_urls, ["https://a.test", "https://b.test"])
        self.assertIsNotNone(group.level)
        self.assertIn("CSP-020", group.rule_ids)

    def test_unique_policies_are_not_reported_as_repeated(self):
        report = summarise(sample_results_with_duplicates())
        csps = [g.csp for g in report.repeated_policies]
        self.assertNotIn(
            "default-src 'none'; script-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
            csps,
        )

    def test_no_repeated_policies_when_all_distinct(self):
        report = summarise(sample_results())
        self.assertEqual(report.repeated_policies, [])

    def test_repeated_policy_grouping_is_exact_string_match(self):
        """Equivalent-but-differently-formatted policies are NOT merged."""
        fetcher = FakeFetcher({
            "https://a.test": html_response(csp="default-src 'self'"),
            "https://b.test": html_response(csp="default-src  'self'"),
        })
        results = scan_targets(
            ["https://a.test", "https://b.test"], fetcher=fetcher
        )
        report = summarise(results)
        self.assertEqual(report.repeated_policies, [])


class HighestRiskUrlTests(unittest.TestCase):
    def test_highest_risk_urls_sorted_descending_by_score(self):
        report = summarise(sample_results_with_duplicates())
        scores = [u.score for u in report.highest_risk_urls]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_highest_risk_urls_excludes_errored_targets(self):
        report = summarise(sample_results_with_duplicates())
        urls = [u.url for u in report.highest_risk_urls]
        self.assertNotIn("https://e.test", urls)

    def test_highest_risk_urls_includes_level(self):
        report = summarise(sample_results_with_duplicates())
        top = report.highest_risk_urls[0]
        self.assertIn(top.level, ("low", "medium", "high", "critical"))


class AffectedUrlsPerRuleTests(unittest.TestCase):
    def test_rule_affected_urls_lists_every_matching_url(self):
        report = summarise(sample_results_with_duplicates())
        # CSP-020 (wildcard source) applies to a.test and b.test.
        affected = report.rule_affected_urls.get("CSP-020", [])
        self.assertEqual(affected, ["https://a.test", "https://b.test"])

    def test_rule_affected_urls_covers_missing_csp_rule(self):
        report = summarise(sample_results_with_duplicates())
        affected = report.rule_affected_urls.get("CSP-001", [])
        self.assertEqual(affected, ["https://d.test"])


class RemediationThemeTests(unittest.TestCase):
    def test_remediation_themes_group_by_remediation_text(self):
        report = summarise(sample_results_with_duplicates())
        remediations = {t.remediation: t for t in report.remediation_themes}
        wildcard_fix = "Replace '*' with an explicit allow-list of required origins."
        self.assertIn(wildcard_fix, remediations)
        theme = remediations[wildcard_fix]
        self.assertEqual(theme.affected_url_count, 2)
        self.assertEqual(theme.example_urls, ["https://a.test", "https://b.test"])
        self.assertIn("CSP-020", theme.rule_ids)

    def test_remediation_themes_sorted_by_affected_count_desc(self):
        report = summarise(sample_results_with_duplicates())
        counts = [t.affected_url_count for t in report.remediation_themes]
        self.assertEqual(counts, sorted(counts, reverse=True))


class HumanReadableReportSectionsTests(unittest.TestCase):
    def test_screen_includes_all_new_sections(self):
        report = summarise(sample_results_with_duplicates())
        text = render_report_screen(report)
        self.assertIn("Summary", text)
        self.assertIn("Top findings (by rule ID):", text)
        self.assertIn("Highest-risk URLs:", text)
        self.assertIn("Repeated CSP policies:", text)
        self.assertIn("Remediation themes:", text)
        self.assertIn("Fetch error details:", text)
        self.assertIn("https://e.test", text)

    def test_screen_omits_repeated_policies_section_when_none(self):
        report = summarise(sample_results())
        text = render_report_screen(report)
        self.assertNotIn("Repeated CSP policies:", text)

    def test_screen_omits_fetch_errors_section_when_none(self):
        report = summarise(sample_results())
        text = render_report_screen(report)
        self.assertNotIn("Fetch error details:", text)


class ReportJsonShapeTests(unittest.TestCase):
    def test_json_summary_includes_new_structured_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "out.json"
            dest = Path(tmp) / "summary.json"
            write_json(sample_results_with_duplicates(), str(src))
            code = cli.main(
                ["report", "--json", str(src), "--output", str(dest), "--quiet"]
            )
            self.assertEqual(code, 0)
            summary = json.loads(dest.read_text())
        for key in (
            "rule_affected_urls", "highest_risk_urls", "repeated_policies",
            "remediation_themes",
        ):
            self.assertIn(key, summary)
        self.assertEqual(len(summary["repeated_policies"]), 1)
        self.assertEqual(summary["repeated_policies"][0]["count"], 2)

    def test_json_summary_is_deterministic_across_runs(self):
        results = sample_results_with_duplicates()
        first = summarise(results).model_dump_json()
        second = summarise(results).model_dump_json()
        self.assertEqual(first, second)


class ReportCliTests(unittest.TestCase):
    def test_report_command_reads_json_without_rescanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            write_json(sample_results(), str(path))

            with mock.patch.object(cli, "scan_targets_with_metadata") as scan_mock:
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


def sample_results_with_status_issues():
    """A mix of success, non-2xx/3xx status, and fetch-error results."""
    fetcher = FakeFetcher({
        "https://ok.test": html_response(csp="default-src 'self'"),
        "https://missing.test": html_response(status=404),
        "https://broken.test": html_response(status=500),
        # https://down.test is unregistered -> connection error.
    })
    return scan_targets(
        ["https://ok.test", "https://missing.test", "https://broken.test",
         "https://down.test"],
        fetcher=fetcher,
    )


class StatusIssueReportTests(unittest.TestCase):
    def test_report_includes_status_code_counts(self):
        report = summarise(sample_results_with_status_issues())
        self.assertEqual(report.status_code_counts.get("200"), 1)
        self.assertEqual(report.status_code_counts.get("404"), 1)
        self.assertEqual(report.status_code_counts.get("500"), 1)

    def test_report_includes_non_success_urls(self):
        report = summarise(sample_results_with_status_issues())
        self.assertEqual(report.non_success_count, 3)
        urls_and_types = {(i.url, i.issue_type) for i in report.non_success_urls}
        self.assertIn(("https://missing.test", "http-status"), urls_and_types)
        self.assertIn(("https://broken.test", "http-status"), urls_and_types)
        self.assertIn(("https://down.test", "fetch-error"), urls_and_types)

    def test_status_issues_are_separate_from_csp_findings(self):
        """Status/fetch issues never appear in rule_counts (CSP scoring)."""
        report = summarise(sample_results_with_status_issues())
        # rule_counts only reflects CSP-scoring rule IDs.
        self.assertTrue(all(rid.startswith("CSP-") for rid in report.rule_counts))

    def test_screen_shows_http_status_summary_and_non_success_urls(self):
        report = summarise(sample_results_with_status_issues())
        text = render_report_screen(report)
        self.assertIn("HTTP status summary:", text)
        self.assertIn("404: 1 URL(s)", text)
        self.assertIn("Non-success URLs", text)
        self.assertIn("https://missing.test", text)
        self.assertIn("https://down.test", text)

    def test_screen_omits_status_sections_when_all_success(self):
        report = summarise(sample_results())
        text = render_report_screen(report)
        self.assertNotIn("Non-success URLs", text)


class DuplicateFinalUrlReportTests(unittest.TestCase):
    def test_summarise_surfaces_duplicate_final_urls_from_metadata(self):
        results = sample_results()
        metadata = ScanMetadata(
            duplicate_final_urls=[
                DuplicateFinalUrl(
                    input_url="https://www.a.test",
                    final_url="https://a.test",
                    duplicate_of="https://a.test",
                ),
            ],
        )
        report = summarise(results, metadata=metadata)
        self.assertEqual(len(report.duplicate_final_urls), 1)
        text = render_report_screen(report)
        self.assertIn("Duplicate final URL skips:", text)
        self.assertIn("https://www.a.test", text)

    def test_screen_omits_duplicate_section_when_none(self):
        report = summarise(sample_results())
        text = render_report_screen(report)
        self.assertNotIn("Duplicate final URL skips:", text)

    def test_scan_then_report_round_trips_duplicate_final_urls(self):
        """End-to-end: scan output (JSON) -> report includes the dedupe skip."""
        fetcher = FakeFetcher({
            "https://a.test/": html_response(csp="default-src 'self'"),
            "https://www.a.test/": redirect_response("https://a.test/"),
        })
        results, metadata = scan_targets_with_metadata(
            ["https://a.test/", "https://www.a.test/"], fetcher=fetcher,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            write_json(results, str(path), metadata=metadata)
            loaded_results, loaded_metadata = load_json_report_full(str(path))
        report = summarise(loaded_results, metadata=loaded_metadata)
        self.assertEqual(len(report.duplicate_final_urls), 1)
        self.assertEqual(
            report.duplicate_final_urls[0].input_url, "https://www.a.test/"
        )


class SkippedLinkReportTests(unittest.TestCase):
    def test_summarise_surfaces_skipped_links_from_metadata(self):
        metadata = ScanMetadata(
            skipped_links=[
                SkippedLink(
                    url="https://evil.test/", reason="cross-origin-not-allowed",
                    source_url="https://a.test/",
                ),
            ],
            skipped_link_count=1,
            discovered_url_count=2,
        )
        report = summarise(sample_results(), metadata=metadata)
        text = render_report_screen(report)
        self.assertIn("Skipped out-of-scope links", text)
        self.assertIn("https://evil.test/", text)
        self.assertIn("Crawl/discovery notes:", text)
        self.assertIn("discovered URLs: 2", text)

    def test_screen_omits_skipped_link_section_when_none(self):
        report = summarise(sample_results())
        text = render_report_screen(report)
        self.assertNotIn("Skipped out-of-scope links", text)
        self.assertNotIn("Crawl/discovery notes:", text)

    def test_crawl_limit_reached_is_shown_when_present(self):
        metadata = ScanMetadata(
            discovered_url_count=1,
            crawl_limit_reached=True,
            crawl_limit_reasons=["max-urls (5) reached"],
        )
        report = summarise(sample_results(), metadata=metadata)
        text = render_report_screen(report)
        self.assertIn("crawl limit reached: max-urls (5) reached", text)


class ReportBackwardCompatibilityTests(unittest.TestCase):
    def test_load_json_report_full_handles_legacy_bare_array(self):
        """Older scan JSON (a bare array) still loads with empty metadata."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            write_json(sample_results(), str(path))  # no metadata argument
            results, metadata = load_json_report_full(str(path))
        self.assertEqual(len(results), 3)
        self.assertEqual(metadata, ScanMetadata())

    def test_load_json_report_full_reads_new_object_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "new.json"
            _, metadata_in = scan_targets_with_metadata(
                ["https://a.test", "https://b.test"],
                fetcher=FakeFetcher({
                    "https://a.test": html_response(),
                    "https://b.test": html_response(),
                }),
            )
            write_json(sample_results(), str(path), metadata=metadata_in)
            results, metadata_out = load_json_report_full(str(path))
        self.assertEqual(len(results), 3)
        self.assertEqual(metadata_out.discovered_url_count, 2)

    def test_load_sqlite_report_full_handles_legacy_database(self):
        """A SQLite DB written before metadata tables existed still loads."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.db"
            write_sqlite(sample_results(), str(path))  # no metadata argument
            results, metadata = load_sqlite_report_full(str(path))
        self.assertEqual(len(results), 3)
        self.assertEqual(metadata.duplicate_final_urls, [])
        self.assertFalse(metadata.crawl_limit_reached)

    def test_report_reads_older_json_and_summarises_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            write_json(sample_results(), str(path))
            code = cli.main(["report", "--json", str(path), "--quiet"])
        self.assertEqual(code, 0)


class ReportJsonNewFieldsTests(unittest.TestCase):
    def test_json_summary_includes_status_and_metadata_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "out.json"
            dest = Path(tmp) / "summary.json"
            write_json(sample_results_with_status_issues(), str(src))
            code = cli.main(
                ["report", "--json", str(src), "--output", str(dest), "--quiet"]
            )
            self.assertEqual(code, 0)
            summary = json.loads(dest.read_text())
        for key in (
            "status_code_counts", "non_success_urls", "non_success_count",
            "discovered_url_count", "skipped_links", "skipped_link_count",
            "crawl_limit_reached", "crawl_limit_reasons", "duplicate_final_urls",
        ):
            self.assertIn(key, summary)
        self.assertEqual(summary["status_code_counts"]["404"], 1)
        self.assertEqual(summary["non_success_count"], 3)

    def test_json_summary_with_metadata_is_deterministic(self):
        results = sample_results_with_status_issues()
        metadata = ScanMetadata(
            skipped_links=[
                SkippedLink(url="https://x.test/", reason="non-http-scheme"),
            ],
            skipped_link_count=1,
        )
        first = summarise(results, metadata=metadata).model_dump_json()
        second = summarise(results, metadata=metadata).model_dump_json()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
