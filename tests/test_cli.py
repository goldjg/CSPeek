"""Tests for scan orchestration and CLI wiring (mocked HTTP only)."""

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from csp_scanner import cli
from csp_scanner.scanner import scan_targets

from tests.fakes import FakeFetcher, html_response


class ScannerTests(unittest.TestCase):
    def test_scan_records_errors_without_assessment(self):
        fetcher = FakeFetcher({})
        results = scan_targets(["https://down.test"], fetcher=fetcher)
        self.assertEqual(len(results), 1)
        self.assertIsNotNone(results[0].fetch.error)
        self.assertIsNone(results[0].assessment)

    def test_subdomain_discovery_adds_targets(self):
        fetcher = FakeFetcher({
            "https://example.test": html_response(csp="default-src 'self'"),
            "https://www.example.test/": html_response(),
        })
        results = scan_targets(
            ["https://example.test"],
            fetcher=fetcher,
            do_subdomains=True,
            resolver=lambda name: name == "www.example.test",
        )
        urls = [r.fetch.input_url for r in results]
        self.assertEqual(urls, ["https://example.test", "https://www.example.test/"])

    def test_crawl_disabled_by_default(self):
        fetcher = FakeFetcher({
            "https://a.test": html_response(body='<a href="/next">n</a>'),
        })
        results = scan_targets(["https://a.test"], fetcher=fetcher)
        self.assertEqual(len(results), 1)


class CliTests(unittest.TestCase):
    def _run(self, argv, fetcher):
        real_scan = scan_targets

        def patched(targets, **kwargs):
            kwargs["fetcher"] = fetcher
            return real_scan(targets, **kwargs)

        buffer = io.StringIO()
        with mock.patch.object(cli, "scan_targets", patched):
            with redirect_stdout(buffer):
                code = cli.main(argv)
        return code, buffer.getvalue()

    def test_scan_single_url_screen_report(self):
        fetcher = FakeFetcher({
            "https://a.test": html_response(csp="default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
        })
        code, out = self._run(["scan", "a.test"], fetcher)
        self.assertEqual(code, 0)
        self.assertIn("https://a.test", out)
        self.assertIn("LOW", out)

    def test_scan_error_returns_nonzero(self):
        fetcher = FakeFetcher({})
        code, out = self._run(["scan", "down.test", "--quiet"], fetcher)
        self.assertEqual(code, 1)

    def test_missing_target_is_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["scan"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
