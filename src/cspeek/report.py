"""Read prior JSON/SQLite scan output and summarise findings.

``cspeek report`` never issues network requests: it only reconstructs
typed models from a previous ``cspeek scan`` output (JSON file or the
SQLite ``scans`` table) and aggregates them into a :class:`ScanReport`.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import (
    Assessment,
    DuplicateFinalUrl,
    Finding,
    FetchResult,
    HighRiskURL,
    PolicyGroup,
    RemediationTheme,
    ScanMetadata,
    ScanReport,
    ScanResult,
    SkippedLink,
    StatusIssue,
)

# Bounds keep report output deterministic and readable regardless of how
# many URLs were scanned; they do not affect the underlying counts.
MAX_HIGH_RISK_URLS = 10
MAX_EXAMPLE_URLS = 5
MAX_NON_SUCCESS_URLS = 20
MAX_SKIPPED_LINK_EXAMPLES = 20


class ReportError(ValueError):
    """Raised when prior scan output cannot be read or is malformed."""


def _row_to_scan_result(row: dict) -> ScanResult:
    raw_findings = row.get("findings") or []
    if isinstance(raw_findings, str):
        raw_findings = json.loads(raw_findings) if raw_findings else []
    findings = [Finding(**f) for f in raw_findings]

    assessment = None
    if row.get("risk_score") is not None and row.get("risk_level") is not None:
        assessment = Assessment(
            score=row["risk_score"], level=row["risk_level"], findings=findings,
        )

    fetch = FetchResult(
        input_url=row["input_url"],
        final_url=row.get("final_url") or row["input_url"],
        status_code=row.get("status_code"),
        csp=row.get("csp"),
        csp_report_only=row.get("csp_report_only"),
        error=row.get("error"),
    )
    return ScanResult(
        fetch=fetch,
        assessment=assessment,
        scan_timestamp=row.get("scan_timestamp", ""),
    )


def load_json_report(path: str) -> list[ScanResult]:
    """Load prior scan results from a JSON file written by ``cspeek scan``."""
    return load_json_report_full(path)[0]


def load_json_report_full(path: str) -> tuple[list[ScanResult], ScanMetadata]:
    """Load prior scan results plus any scan metadata from a JSON file.

    Supports both JSON shapes written by ``cspeek scan``: a bare array of
    result rows (the original, still-supported shape with no metadata),
    and ``{"results": [...], "metadata": {...}}`` (written when metadata
    is available). Older files always load with empty/default metadata.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ReportError(f"JSON input file not found: {path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportError(f"invalid JSON in {path}: {exc}") from exc

    if isinstance(payload, list):
        rows = payload
        metadata = ScanMetadata()
    elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
        rows = payload["results"]
        metadata = ScanMetadata(**(payload.get("metadata") or {}))
    else:
        raise ReportError(
            f"expected a JSON array of results, or an object with a "
            f"'results' array, in {path}"
        )
    return [_row_to_scan_result(row) for row in rows], metadata


def load_sqlite_report(path: str) -> list[ScanResult]:
    """Load prior scan results from a SQLite database's ``scans`` table."""
    return load_sqlite_report_full(path)[0]


def load_sqlite_report_full(path: str) -> tuple[list[ScanResult], ScanMetadata]:
    """Load prior scan results plus any scan metadata from a SQLite file.

    Metadata tables (``scan_skipped_links``, ``scan_duplicate_final_urls``,
    ``scan_metadata``) are optional: databases written before this
    metadata existed simply yield an empty/default :class:`ScanMetadata`.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ReportError(f"SQLite input file not found: {path}")
    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                "SELECT scan_timestamp, input_url, final_url, status_code, "
                "csp, csp_report_only, risk_score, risk_level, findings, "
                "error FROM scans ORDER BY id"
            )
        except sqlite3.OperationalError as exc:
            raise ReportError(f"no 'scans' table in {path}: {exc}") from exc
        rows = [dict(r) for r in cursor.fetchall()]

        skipped_links: list[SkippedLink] = []
        try:
            cursor = conn.execute(
                "SELECT url, reason, source_url FROM scan_skipped_links ORDER BY id"
            )
            skipped_links = [
                SkippedLink(url=r["url"], reason=r["reason"],
                            source_url=r["source_url"] or "")
                for r in cursor.fetchall()
            ]
        except sqlite3.OperationalError:
            pass  # older database without metadata tables

        duplicate_final_urls: list[DuplicateFinalUrl] = []
        try:
            cursor = conn.execute(
                "SELECT input_url, final_url, duplicate_of "
                "FROM scan_duplicate_final_urls ORDER BY id"
            )
            duplicate_final_urls = [
                DuplicateFinalUrl(**dict(r)) for r in cursor.fetchall()
            ]
        except sqlite3.OperationalError:
            pass

        discovered_url_count = 0
        crawl_limit_reached = False
        crawl_limit_reasons: list[str] = []
        try:
            cursor = conn.execute(
                "SELECT discovered_url_count, skipped_link_count, "
                "crawl_limit_reached, crawl_limit_reasons FROM scan_metadata"
            )
            for r in cursor.fetchall():
                discovered_url_count += r["discovered_url_count"] or 0
                if r["crawl_limit_reached"]:
                    crawl_limit_reached = True
                if r["crawl_limit_reasons"]:
                    crawl_limit_reasons.extend(json.loads(r["crawl_limit_reasons"]))
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()

    metadata = ScanMetadata(
        discovered_urls=[],
        discovered_url_count=discovered_url_count,
        skipped_links=skipped_links[:MAX_SKIPPED_LINK_EXAMPLES],
        skipped_link_count=len(skipped_links),
        crawl_limit_reached=crawl_limit_reached,
        crawl_limit_reasons=sorted(set(crawl_limit_reasons)),
        duplicate_final_urls=duplicate_final_urls,
    )
    return [_row_to_scan_result(row) for row in rows], metadata


def _result_url(result: ScanResult) -> str:
    """The URL a result should be reported under (post-redirect when known)."""
    return result.fetch.final_url or result.fetch.input_url


def _highest_risk_urls(results: list[ScanResult]) -> list[HighRiskURL]:
    scored = [
        HighRiskURL(
            url=_result_url(r), score=r.assessment.score, level=r.assessment.level,
        )
        for r in results
        if r.assessment is not None
    ]
    scored.sort(key=lambda h: (-h.score, h.url))
    return scored[:MAX_HIGH_RISK_URLS]


def _repeated_policies(results: list[ScanResult]) -> list[PolicyGroup]:
    """Group results sharing an identical (exact-string) CSP header value.

    This is deliberately exact-string matching, not semantic CSP
    normalisation: two policies that are equivalent but written differently
    (whitespace, directive order, etc.) are treated as distinct groups.
    """
    groups: dict[str, list[ScanResult]] = {}
    for result in results:
        csp = result.fetch.csp
        if csp is None:
            continue
        groups.setdefault(csp, []).append(result)

    policy_groups: list[PolicyGroup] = []
    for csp, members in groups.items():
        if len(members) < 2:
            continue
        urls = sorted(_result_url(m) for m in members)
        rule_ids = sorted({
            f.rule_id
            for m in members
            if m.assessment is not None
            for f in m.assessment.findings
        })
        representative = next(
            (m.assessment for m in members if m.assessment is not None), None
        )
        policy_groups.append(PolicyGroup(
            csp=csp,
            count=len(members),
            score=representative.score if representative else None,
            level=representative.level if representative else None,
            rule_ids=rule_ids,
            example_urls=urls[:MAX_EXAMPLE_URLS],
        ))
    policy_groups.sort(key=lambda g: (-g.count, g.csp))
    return policy_groups


def _remediation_themes(results: list[ScanResult]) -> list[RemediationTheme]:
    """Group findings by remediation text across every affected URL."""
    remediation_rule_ids: dict[str, set[str]] = {}
    remediation_urls: dict[str, set[str]] = {}
    for result in results:
        if result.assessment is None:
            continue
        url = _result_url(result)
        for finding in result.assessment.findings:
            remediation_rule_ids.setdefault(finding.remediation, set()).add(
                finding.rule_id
            )
            remediation_urls.setdefault(finding.remediation, set()).add(url)

    themes = [
        RemediationTheme(
            remediation=remediation,
            rule_ids=sorted(remediation_rule_ids[remediation]),
            affected_url_count=len(urls),
            example_urls=sorted(urls)[:MAX_EXAMPLE_URLS],
        )
        for remediation, urls in remediation_urls.items()
    ]
    themes.sort(key=lambda t: (-t.affected_url_count, t.remediation))
    return themes


def _is_success_status(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 400


def _status_issues(
    results: list[ScanResult],
) -> tuple[dict[str, int], list[StatusIssue]]:
    """HTTP status code counts and non-2xx/3xx/fetch-error issues.

    Purely operational: derived from ``FetchResult`` status codes/errors,
    entirely separate from CSP risk scoring.
    """
    status_code_counts: dict[str, int] = {}
    issues: list[StatusIssue] = []
    for result in results:
        fetch = result.fetch
        if fetch.status_code is not None:
            key = str(fetch.status_code)
            status_code_counts[key] = status_code_counts.get(key, 0) + 1
        if fetch.error:
            issues.append(
                StatusIssue(
                    url=_result_url(result),
                    status_code=fetch.status_code,
                    error=fetch.error,
                    issue_type="fetch-error",
                )
            )
        elif not _is_success_status(fetch.status_code):
            issues.append(
                StatusIssue(
                    url=_result_url(result),
                    status_code=fetch.status_code,
                    error=None,
                    issue_type="http-status",
                )
            )
    return status_code_counts, issues


def summarise(
    results: list[ScanResult], metadata: ScanMetadata | None = None,
) -> ScanReport:
    """Aggregate scan results into a :class:`ScanReport` summary.

    *metadata* (crawl scope, skipped links, duplicate-final-URL skips) is
    optional so reports built from older scan output, which predates this
    metadata, still summarise successfully with empty/default values.
    """
    metadata = metadata or ScanMetadata()
    total = len(results)
    with_csp = sum(1 for r in results if r.fetch.has_csp)
    errors = sum(1 for r in results if r.fetch.error)

    level_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    rule_affected_urls: dict[str, set[str]] = {}
    for result in results:
        if result.assessment is None:
            continue
        level = result.assessment.level
        level_counts[level] = level_counts.get(level, 0) + 1
        url = _result_url(result)
        for finding in result.assessment.findings:
            rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
            rule_affected_urls.setdefault(finding.rule_id, set()).add(url)

    status_code_counts, non_success_issues = _status_issues(results)

    return ScanReport(
        total=total,
        with_csp=with_csp,
        without_csp=total - with_csp,
        errors=errors,
        level_counts=level_counts,
        rule_counts=rule_counts,
        rule_affected_urls={
            rule_id: sorted(urls) for rule_id, urls in rule_affected_urls.items()
        },
        highest_risk_urls=_highest_risk_urls(results),
        repeated_policies=_repeated_policies(results),
        remediation_themes=_remediation_themes(results),
        results=results,
        status_code_counts=status_code_counts,
        non_success_urls=non_success_issues[:MAX_NON_SUCCESS_URLS],
        non_success_count=len(non_success_issues),
        discovered_url_count=metadata.discovered_url_count,
        skipped_links=metadata.skipped_links[:MAX_SKIPPED_LINK_EXAMPLES],
        skipped_link_count=metadata.skipped_link_count,
        crawl_limit_reached=metadata.crawl_limit_reached,
        crawl_limit_reasons=metadata.crawl_limit_reasons,
        duplicate_final_urls=metadata.duplicate_final_urls,
    )


def render_report_screen(report: ScanReport) -> str:
    """Human-readable summary of a :class:`ScanReport`.

    Sections beyond the core summary only appear when there is relevant
    data to show; empty sections are omitted.
    """
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("Summary")
    lines.append(f"Total scanned:  {report.total}")
    lines.append(f"With CSP:       {report.with_csp}")
    lines.append(f"Without CSP:    {report.without_csp}")
    lines.append(f"Fetch errors:   {report.errors}")

    if report.level_counts:
        lines.append("-" * 72)
        lines.append("Risk levels:")
        for level in ("critical", "high", "medium", "low"):
            if level in report.level_counts:
                lines.append(f"  - {level}: {report.level_counts[level]}")

    if report.rule_counts:
        lines.append("-" * 72)
        lines.append("Top findings (by rule ID):")
        for rule_id in sorted(report.rule_counts):
            affected = report.rule_affected_urls.get(rule_id, [])
            lines.append(
                f"  - {rule_id}: {report.rule_counts[rule_id]} finding(s) "
                f"across {len(affected)} URL(s)"
            )

    if report.highest_risk_urls:
        lines.append("-" * 72)
        lines.append("Highest-risk URLs:")
        for entry in report.highest_risk_urls:
            lines.append(
                f"  - {entry.url}: {entry.level.upper()} (score {entry.score})"
            )

    if report.repeated_policies:
        lines.append("-" * 72)
        lines.append("Repeated CSP policies:")
        for group in report.repeated_policies:
            level = f"{group.level.upper()} (score {group.score})" if group.level else "n/a"
            lines.append(f"  - shared by {group.count} URLs, risk {level}")
            lines.append(f"    CSP: {group.csp}")
            if group.rule_ids:
                lines.append(f"    Findings: {', '.join(group.rule_ids)}")
            lines.append(f"    Examples: {', '.join(group.example_urls)}")

    if report.remediation_themes:
        lines.append("-" * 72)
        lines.append("Remediation themes:")
        for theme in report.remediation_themes:
            lines.append(
                f"  - {theme.remediation} "
                f"(affects {theme.affected_url_count} URL(s); "
                f"rules {', '.join(theme.rule_ids)})"
            )

    # Operational status/discovery sections below are separate from CSP
    # risk scoring; each is shown only when there is data to report.
    if report.status_code_counts:
        lines.append("-" * 72)
        lines.append("HTTP status summary:")
        for code in sorted(report.status_code_counts):
            lines.append(f"  - {code}: {report.status_code_counts[code]} URL(s)")

    if report.non_success_count:
        lines.append("-" * 72)
        lines.append(
            f"Non-success URLs ({report.non_success_count} total"
            + (
                f", showing {len(report.non_success_urls)}"
                if report.non_success_count > len(report.non_success_urls)
                else ""
            )
            + "):"
        )
        for issue in report.non_success_urls:
            detail = issue.error or f"status {issue.status_code}"
            lines.append(f"  - {issue.url}: {detail}")

    if report.skipped_link_count:
        lines.append("-" * 72)
        lines.append(
            f"Skipped out-of-scope links ({report.skipped_link_count} total"
            + (
                f", showing {len(report.skipped_links)}"
                if report.skipped_link_count > len(report.skipped_links)
                else ""
            )
            + "):"
        )
        for link in report.skipped_links:
            source = f" (found on {link.source_url})" if link.source_url else ""
            lines.append(f"  - {link.url}: {link.reason}{source}")

    if report.duplicate_final_urls:
        lines.append("-" * 72)
        lines.append("Duplicate final URL skips:")
        for dup in report.duplicate_final_urls:
            lines.append(
                f"  - {dup.input_url} -> {dup.final_url} "
                f"(duplicate of {dup.duplicate_of})"
            )

    if report.discovered_url_count or report.crawl_limit_reached:
        lines.append("-" * 72)
        lines.append("Crawl/discovery notes:")
        lines.append(f"  - discovered URLs: {report.discovered_url_count}")
        if report.crawl_limit_reached:
            reasons = ", ".join(report.crawl_limit_reasons) or "unknown"
            lines.append(f"  - crawl limit reached: {reasons}")

    if report.errors:
        lines.append("-" * 72)
        lines.append("Fetch error details:")
        for result in report.results:
            if result.fetch.error:
                lines.append(f"  - {result.fetch.input_url}: {result.fetch.error}")

    lines.append("=" * 72)
    return "\n".join(lines)


def write_report_json(report: ScanReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report.model_dump_json(indent=2))
