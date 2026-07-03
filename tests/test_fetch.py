"""Tests for CSP header retrieval with mocked HTTP responses."""

import unittest

from csp_scanner.fetch import fetch_url

from tests.fakes import FakeFetcher, html_response, redirect_response


class FetchTests(unittest.TestCase):
    def test_extracts_csp_headers(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                csp="default-src 'self'", csp_ro="default-src 'none'"
            ),
        })
        result = fetch_url("https://a.test/", fetcher=fetcher)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.csp, "default-src 'self'")
        self.assertEqual(result.csp_report_only, "default-src 'none'")
        self.assertTrue(result.has_csp)
        self.assertIsNone(result.error)

    def test_report_only_without_enforced(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(csp_ro="default-src 'self'"),
        })
        result = fetch_url("https://a.test/", fetcher=fetcher)
        self.assertIsNone(result.csp)
        self.assertFalse(result.has_csp)
        self.assertEqual(result.csp_report_only, "default-src 'self'")

    def test_follows_redirects_and_records_final_url(self):
        fetcher = FakeFetcher({
            "https://a.test/": redirect_response("https://a.test/home"),
            "https://a.test/home": redirect_response("/final", status=301),
            "https://a.test/final": html_response(csp="default-src 'none'"),
        })
        result = fetch_url("https://a.test/", fetcher=fetcher)
        self.assertEqual(result.final_url, "https://a.test/final")
        self.assertEqual(result.redirects, 2)
        self.assertEqual(result.csp, "default-src 'none'")

    def test_redirect_limit(self):
        fetcher = FakeFetcher({
            "https://a.test/": redirect_response("https://a.test/"),
        })
        result = fetch_url("https://a.test/", fetcher=fetcher, max_redirects=3)
        self.assertIn("redirect limit", result.error)

    def test_connection_error_recorded(self):
        fetcher = FakeFetcher({})
        result = fetch_url("https://down.test/", fetcher=fetcher)
        self.assertIsNotNone(result.error)
        self.assertIn("OSError", result.error)

    def test_header_lookup_is_case_insensitive(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                extra_headers={"content-security-policy": "default-src 'self'"}
            ),
        })
        result = fetch_url("https://a.test/", fetcher=fetcher)
        self.assertEqual(result.csp, "default-src 'self'")


if __name__ == "__main__":
    unittest.main()
