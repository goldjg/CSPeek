"""Read prior JSON/SQLite scan output and summarise findings.

``cspeek report`` never issues network requests: it only reconstructs
typed models from a previous ``cspeek scan`` output (JSON file or the
SQLite ``scans`` table) and aggregates them into a :class:`ScanReport`.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Assessment, Finding, FetchResult, ScanReport, ScanResult


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


def summarise(results: list[ScanResult]) -> ScanReport:
    """Aggregate scan results into a :class:`ScanReport` summary."""
    total = len(results)
    with_csp = sum(1 for r in results if r.fetch.has_csp)
    errors = sum(1 for r in results if r.fetch.error)

    level_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for result in results:
        if result.assessment is None:
            continue
        level = result.assessment.level
        level_counts[level] = level_counts.get(level, 0) + 1
        for finding in result.assessment.findings:
            rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1

    return ScanReport(
        total=total,
        with_csp=with_csp,
        without_csp=total - with_csp,
        errors=errors,
        level_counts=level_counts,
        rule_counts=rule_counts,
        results=results,
    )


def render_report_screen(report: ScanReport) -> str:
    """Human-readable summary of a :class:`ScanReport`."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"Total scanned:  {report.total}")
    lines.append(f"With CSP:       {report.with_csp}")
    lines.append(f"Without CSP:    {report.without_csp}")
    lines.append(f"Fetch errors:   {report.errors}")
    if report.level_counts:
        lines.append("Risk levels:")
        for level in ("critical", "high", "medium", "low"):
            if level in report.level_counts:
                lines.append(f"  - {level}: {report.level_counts[level]}")
    if report.rule_counts:
        lines.append("Findings by rule:")
        for rule_id in sorted(report.rule_counts):
            lines.append(f"  - {rule_id}: {report.rule_counts[rule_id]}")
    lines.append("=" * 72)
    return "\n".join(lines)


def write_report_json(report: ScanReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report.model_dump_json(indent=2))
