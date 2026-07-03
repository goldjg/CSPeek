"""Tests for bounded crawling and conservative subdomain discovery."""

import unittest

from cspeek.discovery import crawl, enumerate_subdomains, extract_links, same_origin
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
