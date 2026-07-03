"""Optional discovery: bounded crawling and wordlist subdomain enumeration.

Both are disabled by default and deterministically bounded:
- crawl: max depth, max URLs, same-origin by default, per-request timeout;
- subdomains: fixed wordlist DNS resolution only (no active scanning).
"""

from __future__ import annotations

import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_URLS = 100

# Small, deterministic wordlist for safe passive-style enumeration.
SUBDOMAIN_WORDLIST = (
    "www", "mail", "api", "dev", "staging", "test", "admin", "app",
    "blog", "shop", "docs", "cdn", "static", "assets", "portal",
    "m", "beta", "support", "status", "vpn",
)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


def extract_links(base_url: str, html: str) -> list[str]:
    """Extract absolute http(s) links from an HTML document."""
    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 - malformed HTML must not abort a scan
        return []
    links: list[str] = []
    for href in parser.links:
        absolute = urljoin(base_url, href.strip())
        parsed = urlparse(absolute)
        if parsed.scheme in ("http", "https"):
            # strip fragments for de-duplication
            links.append(absolute.split("#", 1)[0])
    return links


def same_origin(url_a: str, url_b: str) -> bool:
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())


def crawl(
    start_url: str,
    fetch,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int = DEFAULT_MAX_URLS,
    same_origin_only: bool = True,
) -> list:
    """Breadth-first bounded crawl.

    *fetch* is a callable ``(url) -> FetchResult``. Returns the list of
    FetchResults in deterministic (BFS, insertion) order.
    """
    visited: set[str] = set()
    results = []
    queue: list[tuple[str, int]] = [(start_url, 0)]
    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        result = fetch(url)
        results.append(result)
        if result.error or depth >= max_depth:
            continue
        if "html" not in result.content_type.lower():
            continue
        for link in extract_links(result.final_url, result.body):
            if link in visited:
                continue
            if same_origin_only and not same_origin(start_url, link):
                continue
            queue.append((link, depth + 1))
    return results


def enumerate_subdomains(
    url: str,
    wordlist=SUBDOMAIN_WORDLIST,
    resolver=None,
) -> list[str]:
    """Return URLs for wordlist subdomains that resolve via DNS.

    *resolver* is a callable ``(hostname) -> bool`` used in tests; the
    default performs a single deterministic DNS lookup per candidate.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host or host.replace(".", "").isdigit():
        return []  # IP addresses have no subdomains to enumerate

    def _default_resolver(name: str) -> bool:
        try:
            socket.getaddrinfo(name, None)
            return True
        except OSError:
            return False

    resolve = resolver or _default_resolver
    # Use the registrable-ish base: strip a leading known subdomain label.
    base = host
    labels = host.split(".")
    if len(labels) > 2 and labels[0] in wordlist:
        base = ".".join(labels[1:])

    found: list[str] = []
    for word in wordlist:
        candidate = f"