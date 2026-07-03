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
    Finding,
    FetchResult,
    HighRiskURL,
    PolicyGroup,
    RemediationTheme,
    ScanReport,
    ScanResult,
)

# Bounds keep report output deterministic and readable regardless of how
# many URLs were scanned; they do not affect the underlying counts.
MAX_HIGH_RISK_URLS = 10
MAX_EXAMPLE_URLS = 5


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
    file_path = Path(path)
    if not file_path.is_file():
        raise ReportError(f"JSON input file not found: {path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise ReportError(f"expected a JSON array of results in {path}")
    return [_row_to_scan_result(row) for row in payload]


def load_sqlite_report(path: str) -> list[ScanResult]:
    """Load prior scan results from a SQLite database's ``scans`` table."""
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
    finally:
        conn.close()
    return [_row_to_scan_result(row) for row in rows]


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


def summarise(results: list[ScanResult]) -> ScanReport:
    """Aggregate scan results into a :class:`ScanReport` summary."""
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
    )


def render_report_screen(report: ScanReport) -> str:
    """Human-readable summary of a :class:`ScanReport`."""
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
