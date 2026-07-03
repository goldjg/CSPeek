"""Tests for bounded crawling and conservative subdomain discovery."""

import unittest

from cspeek.discovery import (
    crawl,
    crawl_with_scope,
    enumerate_subdomains,
    extract_links,
    extract_links_with_skips,
    same_origin,
)
from cspeek.fetch import fetch_url

from tests.fakes import FakeFetcher, html_response


def make_fetch(fetcher):
    return lambda url: fetch_url(url, fetcher=fetcher)


class LinkExtractionTests(unittest.TestCase):
    def test_extracts_absolute_and_relative_links(self):
        html = '<a href="/a">A</a> <a href="https://other.test/b#frag">B</a>'
        links = extract_links("https://a.test/", html)
        self.assertEqual(links, ["https://a.test/a", "https://other.test/b"])

    def test_ignores_non_http_links(self):
        html = '<a href="mailto:x@y.test">m</a> <a href="javascript:void(0)">j</a>'
        self.assertEqual(extract_links("https://a.test/", html), [])

    def test_malformed_html_is_safe(self):
        self.assertIsInstance(extract_links("https://a.test/", "<a href='"), list)

    def test_extract_links_with_skips_reports_non_http_hrefs(self):
        html = '<a href="mailto:x@y.test">m</a> <a href="javascript:void(0)">j</a>'
        links, skipped = extract_links_with_skips("https://a.test/", html)
        self.assertEqual(links, [])
        self.assertEqual(skipped, ["mailto:x@y.test", "javascript:void(0)"])


class CrawlTests(unittest.TestCase):
    def test_same_origin_only_by_default(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="/next">n</a> <a href="https://evil.test/">e</a>'
            ),
            "https://a.test/next": html_response(),
        })
        results = crawl("https://a.test/", make_fetch(fetcher))
        urls = [r.input_url for r in results]
        self.assertEqual(urls, ["https://a.test/", "https://a.test/next"])

    def test_max_depth_bound(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(body='<a href="/1">1</a>'),
            "https://a.test/1": html_response(body='<a href="/2">2</a>'),
            "https://a.test/2": html_response(body='<a href="/3">3</a>'),
            "https://a.test/3": html_response(),
        })
        results = crawl("https://a.test/", make_fetch(fetcher), max_depth=1)
        urls = [r.input_url for r in results]
        self.assertEqual(urls, ["https://a.test/", "https://a.test/1"])

    def test_max_urls_bound(self):
        pages = {
            f"https://a.test/{i}": html_response(
                body=f'<a href="/{i + 1}">next</a>'
            )
            for i in range(10)
        }
        pages["https://a.test/"] = html_response(body='<a href="/0">0</a>')
        fetcher = FakeFetcher(pages)
        results = crawl("https://a.test/", make_fetch(fetcher), max_urls=3)
        self.assertEqual(len(results), 3)

    def test_does_not_revisit_urls(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(body='<a href="/">self</a>'),
        })
        results = crawl("https://a.test/", make_fetch(fetcher))
        self.assertEqual(len(results), 1)

    def test_error_pages_do_not_stop_crawl(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="/down">d</a> <a href="/ok">o</a>'
            ),
            "https://a.test/ok": html_response(),
        })
        results = crawl("https://a.test/", make_fetch(fetcher))
        self.assertEqual(len(results), 3)


class CrawlScopeTests(unittest.TestCase):
    """Coverage for crawl_with_scope: skip visibility and limit reporting."""

    def test_same_origin_crawl_records_skipped_cross_origin_links(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="/next">n</a> <a href="https://evil.test/">e</a>'
            ),
            "https://a.test/next": html_response(),
        })
        outcome = crawl_with_scope("https://a.test/", make_fetch(fetcher))
        self.assertEqual(
            [r.input_url for r in outcome.results],
            ["https://a.test/", "https://a.test/next"],
        )
        self.assertEqual(len(outcome.skipped_links), 1)
        skipped = outcome.skipped_links[0]
        self.assertEqual(skipped.url, "https://evil.test/")
        self.assertEqual(skipped.reason, "cross-origin-not-allowed")
        self.assertEqual(skipped.source_url, "https://a.test/")

    def test_non_http_links_are_skipped_and_recorded(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="mailto:x@y.test">m</a> <a href="/next">n</a>'
            ),
            "https://a.test/next": html_response(),
        })
        outcome = crawl_with_scope("https://a.test/", make_fetch(fetcher))
        reasons = {(s.url, s.reason) for s in outcome.skipped_links}
        self.assertIn(("mailto:x@y.test", "non-http-scheme"), reasons)

    def test_allow_cross_origin_follows_links_instead_of_skipping(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(
                body='<a href="https://b.test/">b</a>'
            ),
            "https://b.test/": html_response(),
        })
        outcome = crawl_with_scope(
            "https://a.test/", make_fetch(fetcher), same_origin_only=False
        )
        self.assertEqual(
            [r.input_url for r in outcome.results],
            ["https://a.test/", "https://b.test/"],
        )
        self.assertEqual(outcome.skipped_links, [])

    def test_discovered_urls_lists_every_fetched_url(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(body='<a href="/next">n</a>'),
            "https://a.test/next": html_response(),
        })
        outcome = crawl_with_scope("https://a.test/", make_fetch(fetcher))
        self.assertEqual(
            outcome.discovered_urls, ["https://a.test/", "https://a.test/next"]
        )

    def test_max_urls_limit_is_reported(self):
        pages = {
            f"https://a.test/{i}": html_response(body=f'<a href="/{i + 1}">next</a>')
            for i in range(10)
        }
        pages["https://a.test/"] = html_response(body='<a href="/0">0</a>')
        fetcher = FakeFetcher(pages)
        outcome = crawl_with_scope(
            "https://a.test/", make_fetch(fetcher), max_depth=20, max_urls=3
        )
        self.assertTrue(outcome.limit_reached)
        self.assertTrue(
            any("max-urls" in reason for reason in outcome.limit_reasons)
        )

    def test_max_depth_limit_is_reported_when_further_links_exist(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(body='<a href="/1">1</a>'),
            "https://a.test/1": html_response(body='<a href="/2">2</a>'),
        })
        outcome = crawl_with_scope(
            "https://a.test/", make_fetch(fetcher), max_depth=1
        )
        self.assertTrue(outcome.limit_reached)
        self.assertTrue(
            any("max-depth" in reason for reason in outcome.limit_reasons)
        )

    def test_no_limit_reported_when_crawl_completes_naturally(self):
        fetcher = FakeFetcher({
            "https://a.test/": html_response(),
        })
        outcome = crawl_with_scope("https://a.test/", make_fetch(fetcher))
        self.assertFalse(outcome.limit_reached)
        self.assertEqual(outcome.limit_reasons, [])


class SameOriginTests(unittest.TestCase):
    def test_same_origin(self):
        self.assertTrue(same_origin("https://a.test/x", "https://A.TEST/y"))
        self.assertFalse(same_origin("https://a.test/", "http://a.test/"))
        self.assertFalse(same_origin("https://a.test/", "https://b.test/"))


class SubdomainTests(unittest.TestCase):
    def test_wordlist_resolution_is_deterministic_and_bounded(self):
        calls = []

        def resolver(name):
            calls.append(name)
            return name in ("www.example.test", "api.example.test")

        found = enumerate_subdomains("https://example.test/", resolver=resolver)
        self.assertEqual(
            found,
            ["https://www.example.test/", "https://api.example.test/"],
        )
        # bounded by the fixed wordlist, no repeats
        self.assertEqual(len(calls), len(set(calls)))

    def test_skips_own_host_and_ip_addresses(self):
        found = enumerate_subdomains(
            "https://www.example.test/", resolver=lambda n: True
        )
        self.assertNotIn("https://www.example.test/", found)
        self.assertEqual(
            enumerate_subdomains("https://192.168.0.1/", resolver=lambda n: True),
            [],
        )


if __name__ == "__main__":
    unittest.main()
