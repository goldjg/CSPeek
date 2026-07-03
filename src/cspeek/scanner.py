"""Scan orchestration: fetch, assess, and collect results.

CSPeek is a defensive configuration-auditing tool. It only retrieves
HTTP response headers (and page bodies when crawling is explicitly
enabled) from user-supplied, authorised targets, and produces
deterministic CSP hygiene findings.
"""

from __future__ import annotations

from .assess import assess
from .discovery import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_URLS,
    crawl,
    enumerate_subdomains,
)
from .fetch import DEFAULT_TIMEOUT, fetch_url
from .models import FetchResult, ScanResult
from .output import now_iso


def scan_targets(
    targets: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    do_crawl: bool = False,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int = DEFAULT_MAX_URLS,
    same_origin_only: bool = True,
    do_subdomains: bool = False,
    fetcher=None,
    resolver=None,
) -> list[ScanResult]:
    """Scan every target (plus optional discovered URLs) deterministically."""

    def fetch(url: str) -> FetchResult:
        return fetch_url(url, timeout=timeout, fetcher=fetcher)

    all_targets = list(targets)
    if do_subdomains:
        for target in targets:
            for discovered in enumerate_subdomains(target, resolver=resolver):
                if discovered not in all_targets:
                    all_targets.append(discovered)

    fetch_results: list[FetchResult] = []
    seen: set[str] = set()
    for target in all_targets:
        if do_crawl:
            batch = crawl(
                target,
                fetch,
                max_depth=max_depth,
                max_urls=max_urls,
                same_origin_only=same_origin_only,
            )
        else:
            batch = [fetch(target)]
        for item in batch:
            if item.input_url in seen:
                continue
            seen.add(item.input_url)
            fetch_results.append(item)

    results: list[ScanResult] = []
    for item in fetch_results:
        assessment = None
        if item.error is None:
            assessment = assess(item.csp, item.csp_report_only)
        results.append(
            ScanResult(
                fetch=item,
                assessment=assessment,
                scan_timestamp=now_iso(),
            )
        )
    return results
