"""Optional discovery: bounded crawling and wordlist subdomain enumeration.

Both are disabled by default and deterministically bounded:
- crawl: max depth, max URLs, same-origin by default, per-request timeout;
- subdomains: fixed wordlist DNS resolution only (no active scanning).
"""

from __future__ import annotations

import socket
from html.parser import HTMLParser
from typing import NamedTuple
from urllib.parse import urljoin, urlparse

from .models import SkippedLink

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
    return extract_links_with_skips(base_url, html)[0]


def extract_links_with_skips(base_url: str, html: str) -> tuple[list[str], list[str]]:
    """Extract absolute http(s) links, and note non-http(s) links skipped.

    Returns ``(links, skipped_hrefs)``. ``skipped_hrefs`` holds the
    resolved absolute form of any link whose scheme is not ``http``/
    ``https`` (e.g. ``mailto:``, ``javascript:``), so crawl scope can be
    reported rather than silently dropping them.
    """
    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 - malformed HTML must not abort a scan
        return [], []
    links: list[str] = []
    skipped: list[str] = []
    for href in parser.links:
        absolute = urljoin(base_url, href.strip())
        parsed = urlparse(absolute)
        if parsed.scheme in ("http", "https"):
            # strip fragments for de-duplication
            links.append(absolute.split("#", 1)[0])
        else:
            skipped.append(absolute.split("#", 1)[0])
    return links, skipped


def same_origin(url_a: str, url_b: str) -> bool:
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())


class CrawlOutcome(NamedTuple):
    """Full result of a bounded crawl: fetched pages plus scope bookkeeping."""

    results: list
    discovered_urls: list[str]
    skipped_links: list[SkippedLink]
    limit_reached: bool
    limit_reasons: list[str]


def crawl(
    start_url: str,
    fetch,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int = DEFAULT_MAX_URLS,
    same_origin_only: bool = True,
) -> list:
    """Breadth-first bounded crawl.

    *fetch* is a callable ``(url) -> FetchResult``. Returns the list of
    FetchResults in deterministic (BFS, insertion) order. See
    :func:`crawl_with_scope` for a variant that also reports discovered
    URLs, skipped out-of-scope links, and whether a crawl limit was hit.
    """
    return crawl_with_scope(
        start_url,
        fetch,
        max_depth=max_depth,
        max_urls=max_urls,
        same_origin_only=same_origin_only,
    ).results


def crawl_with_scope(
    start_url: str,
    fetch,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int = DEFAULT_MAX_URLS,
    same_origin_only: bool = True,
) -> CrawlOutcome:
    """Breadth-first bounded crawl with full scope/skip reporting.

    Same-origin scope is the default; cross-origin links are only
    followed when *same_origin_only* is ``False`` (the CLI's opt-in
    ``--allow-cross-origin``). Non-http(s) links, cross-origin links (when
    not allowed), and links beyond ``max_depth``/``max_urls`` are recorded
    as :class:`~cspeek.models.SkippedLink` entries rather than silently
    dropped.
    """
    visited: set[str] = set()
    results = []
    discovered: list[str] = []
    skipped: list[SkippedLink] = []
    limit_reasons: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    while queue:
        if len(visited) >= max_urls:
            limit_reasons.add(f"max-urls ({max_urls}) reached")
            break
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        discovered.append(url)
        result = fetch(url)
        results.append(result)
        if result.error:
            continue
        if "html" not in result.content_type.lower():
            continue
        links, non_http = extract_links_with_skips(result.final_url, result.body)
        for href in non_http:
            skipped.append(
                SkippedLink(
                    url=href, reason="non-http-scheme", source_url=result.final_url
                )
            )
        if depth >= max_depth:
            if links:
                limit_reasons.add(f"max-depth ({max_depth}) reached")
            continue
        for link in links:
            if link in visited:
                continue
            if same_origin_only and not same_origin(start_url, link):
                skipped.append(
                    SkippedLink(
                        url=link,
                        reason="cross-origin-not-allowed",
                        source_url=result.final_url,
                    )
                )
                continue
            queue.append((link, depth + 1))
    return CrawlOutcome(
        results=results,
        discovered_urls=discovered,
        skipped_links=skipped,
        limit_reached=bool(limit_reasons),
        limit_reasons=sorted(limit_reasons),
    )


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

    scheme = parsed.scheme or "https"
    found: list[str] = []
    for word in wordlist:
        candidate = f"{word}.{base}"
        if candidate == host:
            continue
        if resolve(candidate):
            found.append(f"{scheme}://{candidate}/")
    return found