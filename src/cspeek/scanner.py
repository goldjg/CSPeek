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
    crawl_with_scope,
    enumerate_subdomains,
)
from .fetch import DEFAULT_TIMEOUT, fetch_url
from .models import DuplicateFinalUrl, FetchResult, ScanMetadata, ScanResult
from .output import now_iso

# Bound example lists in ScanMetadata so scan output stays readable
# regardless of scan size; the `_count` fields are never truncated.
MAX_METADATA_EXAMPLES = 50


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
    """Scan every target (plus optional discovered URLs) deterministically.

    Convenience wrapper around :func:`scan_targets_with_metadata` for
    callers that only need the per-URL results.
    """
    results, _ = scan_targets_with_metadata(
        targets,
        timeout=timeout,
        do_crawl=do_crawl,
        max_depth=max_depth,
        max_urls=max_urls,
        same_origin_only=same_origin_only,
        do_subdomains=do_subdomains,
        fetcher=fetcher,
        resolver=resolver,
    )
    return results


def scan_targets_with_metadata(
    targets: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    do_crawl: bool = False,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int = DEFAULT_MAX_URLS,
    same_origin_only: bool = True,
    do_subdomains: bool = False,
    fetcher=None,
    resolver=None,
) -> tuple[list[ScanResult], ScanMetadata]:
    """Scan every target and also return crawl-scope/dedupe metadata.

    Metadata records discovered URLs, out-of-scope links skipped while
    crawling (and why), whether a crawl limit was reached, and any
    duplicate-final-URL skips. It is separate from CSP risk scoring.
    """

    def fetch(url: str) -> FetchResult:
        return fetch_url(url, timeout=timeout, fetcher=fetcher)

    all_targets = list(targets)
    if do_subdomains:
        for target in targets:
            for discovered in enumerate_subdomains(target, resolver=resolver):
                if discovered not in all_targets:
                    all_targets.append(discovered)

    discovered_urls: list[str] = []
    skipped_links: list = []
    limit_reasons: set[str] = set()

    fetch_results: list[FetchResult] = []
    seen: set[str] = set()
    for target in all_targets:
        if do_crawl:
            outcome = crawl_with_scope(
                target,
                fetch,
                max_depth=max_depth,
                max_urls=max_urls,
                same_origin_only=same_origin_only,
            )
            batch = outcome.results
            discovered_urls.extend(outcome.discovered_urls)
            skipped_links.extend(outcome.skipped_links)
            limit_reasons.update(outcome.limit_reasons)
        else:
            batch = [fetch(target)]
            discovered_urls.append(target)
        for item in batch:
            if item.input_url in seen:
                continue
            seen.add(item.input_url)
            fetch_results.append(item)

    # Deduplicate by final URL: keep the first successful fetch that
    # resolved to a given final URL, and record the rest as duplicate
    # skips. Error results are never deduplicated away, since a final
    # URL may not be meaningfully known when a fetch fails.
    final_seen: dict[str, FetchResult] = {}
    duplicate_final_urls: list[DuplicateFinalUrl] = []
    deduped_fetch_results: list[FetchResult] = []
    for item in fetch_results:
        if item.error is None:
            owner = final_seen.get(item.final_url)
            if owner is not None:
                duplicate_final_urls.append(
                    DuplicateFinalUrl(
                        input_url=item.input_url,
                        final_url=item.final_url,
                        duplicate_of=owner.input_url,
                    )
                )
                continue
            final_seen[item.final_url] = item
        deduped_fetch_results.append(item)

    results: list[ScanResult] = []
    for item in deduped_fetch_results:
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

    metadata = ScanMetadata(
        discovered_urls=discovered_urls[:MAX_METADATA_EXAMPLES],
        discovered_url_count=len(discovered_urls),
        skipped_links=skipped_links[:MAX_METADATA_EXAMPLES],
        skipped_link_count=len(skipped_links),
        crawl_limit_reached=bool(limit_reasons),
        crawl_limit_reasons=sorted(limit_reasons),
        duplicate_final_urls=duplicate_final_urls,
    )
    return results, metadata
