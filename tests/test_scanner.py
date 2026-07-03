"""Tests for scan orchestration metadata: final-URL dedupe and discovery."""

import unittest

from cspeek.fetch import HttpResponse
from cspeek.scanner import scan_targets, scan_targets_with_metadata

from tests.fakes import FakeFetcher, html_response, redirect_response


class FinalUrlDedupeTests(unittest.TestCase):
    def test_different_inputs_redirecting_to_same_final_url_are_deduped(self):
        fetcher = FakeFetcher({
            "https://example.test/": html_response(csp="default-src 'self'"),
            "https://www.example.test/": redirect_response(
                "https://example.test/"
            ),
        })
        results, metadata = scan_targets_with_metadata(
            ["https://example.test/", "https://www.example.test/"], fetcher=fetcher,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].fetch.input_url, "https://example.test/")
        self.assertEqual(len(metadata.duplicate_final_urls), 1)
        dup = metadata.duplicate_final_urls[0]
        self.assertEqual(dup.input_url, "https://www.example.test/")
        self.assertEqual(dup.final_url, "https://example.test/")
        self.assertEqual(dup.duplicate_of, "https://example.test/")

    def test_scan_targets_wrapper_also_dedupes(self):
        """The plain `scan_targets` wrapper keeps returning just results."""
        fetcher = FakeFetcher({
            "https://example.test/": html_response(),
            "https://www.example.test/": redirect_response(
                "https://example.test/"
            ),
        })
        results = scan_targets(
            ["https://example.test/", "https://www.example.test/"], fetcher=fetcher,
        )
        self.assertEqual(len(results), 1)

    def test_error_results_are_not_deduped_away(self):
        """A URL that fails before a final URL is known keeps its error."""
        fetcher = FakeFetcher({
            "https://example.test/": html_response(),
            # https://down.test/ is unregistered -> connection error.
        })
        results, metadata = scan_targets_with_metadata(
            ["https://example.test/", "https://down.test/"], fetcher=fetcher,
        )
        self.assertEqual(len(results), 2)
        urls = {r.fetch.input_url for r in results}
        self.assertEqual(urls, {"https://example.test/", "https://down.test/"})
        self.assertIsNotNone(
            next(r for r in results if r.fetch.input_url == "https://down.test/")
            .fetch.error
        )
        self.assertEqual(metadata.duplicate_final_urls, [])

    def test_two_errors_sharing_a_final_url_are_both_kept(self):
        """Errors are never deduplicated, even if final URLs coincide."""

        def erroring_fetcher(url, timeout):
            raise OSError(f"connection refused: {url}")

        results, metadata = scan_targets_with_metadata(
            ["https://a.test/", "https://b.test/"], fetcher=erroring_fetcher,
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.fetch.error for r in results))
        self.assertEqual(metadata.duplicate_final_urls, [])

    def test_three_way_dedupe_keeps_first_input(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(),
            "https://b.test/": redirect_response("https://a.test/"),
            "https://c.test/": redirect_response("https://a.test/"),
        })
        results, metadata = scan_targets_with_metadata(
            ["https://a.test/", "https://b.test/", "https://c.test/"],
            fetcher=fetcher,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].fetch.input_url, "https://a.test/")
        duplicated_inputs = {d.input_url for d in metadata.duplicate_final_urls}
        self.assertEqual(duplicated_inputs, {"https://b.test/", "https://c.test/"})
        self.assertTrue(
            all(d.duplicate_of == "https://a.test/" for d in metadata.duplicate_final_urls)
        )


class DiscoveryMetadataTests(unittest.TestCase):
    def test_non_crawl_scan_records_discovered_urls(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(),
            "https://b.test/": html_response(),
        })
        _, metadata = scan_targets_with_metadata(
            ["https://a.test/", "https://b.test/"], fetcher=fetcher,
        )
        self.assertEqual(metadata.discovered_url_count, 2)
        self.assertEqual(metadata.skipped_links, [])
        self.assertFalse(metadata.crawl_limit_reached)

    def test_crawl_aggregates_skipped_links_and_limit_reasons(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="/next">n</a> <a href="https://evil.test/">e</a>'
            ),
            "https://a.test/next": html_response(),
        })
        _, metadata = scan_targets_with_metadata(
            ["https://a.test/"], fetcher=fetcher, do_crawl=True,
        )
        self.assertEqual(len(metadata.skipped_links), 1)
        self.assertEqual(metadata.skipped_links[0].reason, "cross-origin-not-allowed")

    def test_allow_cross_origin_changes_skip_behaviour(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="https://b.test/">b</a>'
            ),
            "https://b.test/": html_response(),
        })
        _, metadata = scan_targets_with_metadata(
            ["https://a.test/"],
            fetcher=fetcher,
            do_crawl=True,
            same_origin_only=False,
        )
        self.assertEqual(metadata.skipped_links, [])
        self.assertEqual(metadata.discovered_url_count, 2)


if __name__ == "__main__":
    unittest.main()
