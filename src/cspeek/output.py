"""Output writers: screen, JSON, CSV, SQLite."""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timezone

from .models import ScanMetadata, ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp TEXT NOT NULL,
    input_url TEXT NOT NULL,
    final_url TEXT,
    status_code INTEGER,
    csp TEXT,
    csp_report_only TEXT,
    has_csp INTEGER NOT NULL,
    risk_score INTEGER,
    risk_level TEXT,
    findings TEXT,
    error TEXT
);
"""

# Metadata tables are separate from `scans` so older readers that only
# know about `scans` keep working unchanged (backward compatible). Like
# `scans`, they are append-only across multiple writes to the same file.
METADATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_skipped_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    reason TEXT NOT NULL,
    source_url TEXT
);
CREATE TABLE IF NOT EXISTS scan_duplicate_final_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    duplicate_of TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discovered_url_count INTEGER NOT NULL,
    skipped_link_count INTEGER NOT NULL,
    crawl_limit_reached INTEGER NOT NULL,
    crawl_limit_reasons TEXT
);
"""


def result_to_dict(result: ScanResult) -> dict:
    """Flatten a ScanResult into a JSON-safe dict."""
    return {
        "scan_timestamp": result.scan_timestamp,
        "input_url": result.fetch.input_url,
        "final_url": result.fetch.final_url,
        "status_code": result.fetch.status_code,
        "csp": result.fetch.csp,
        "csp_report_only": result.fetch.csp_report_only,
        "has_csp": result.fetch.has_csp,
        "risk_score": result.assessment.score if result.assessment else None,
        "risk_level": result.assessment.level if result.assessment else None,
        "findings": (
            [f.model_dump() for f in result.assessment.findings]
            if result.assessment else []
        ),
        "error": result.fetch.error,
    }


def write_json(
    results: list[ScanResult], path: str, metadata: ScanMetadata | None = None,
) -> None:
    """Write scan results as JSON.

    With no *metadata*, writes a bare JSON array (the original,
    unchanged shape). When *metadata* is supplied, writes
    ``{"results": [...], "metadata": {...}}`` instead; ``cspeek report``
    reads both shapes, so older bare-array files remain fully
    compatible.
    """
    payload = [result_to_dict(r) for r in results]
    if metadata is not None:
        payload = {"results": payload, "metadata": metadata.model_dump()}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


CSV_FIELDS = [
    "scan_timestamp", "input_url", "final_url", "status_code", "csp",
    "csp_report_only", "has_csp", "risk_score", "risk_level", "findings",
    "error",
]


def write_csv(results: list[ScanResult], path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for result in results:
            row = result_to_dict(result)
            row["findings"] = "; ".join(
                f"{f['rule_id']}[{f['severity']}] {f['directive']}"
                for f in row["findings"]
            )
            writer.writerow(row)


def write_sqlite(
    results: list[ScanResult], path: str, metadata: ScanMetadata | None = None,
) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        for result in results:
            row = result_to_dict(result)
            conn.execute(
                """INSERT INTO scans (scan_timestamp, input_url, final_url,
                   status_code, csp, csp_report_only, has_csp, risk_score,
                   risk_level, findings, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    row["scan_timestamp"], row["input_url"], row["final_url"],
                    row["status_code"], row["csp"], row["csp_report_only"],
                    int(row["has_csp"]), row["risk_score"], row["risk_level"],
                    json.dumps(row["findings"]), row["error"],
                ),
            )
        if metadata is not None:
            conn.executescript(METADATA_SCHEMA)
            for link in metadata.skipped_links:
                conn.execute(
                    "INSERT INTO scan_skipped_links (url, reason, source_url) "
                    "VALUES (?, ?, ?)",
                    (link.url, link.reason, link.source_url),
                )
            for dup in metadata.duplicate_final_urls:
                conn.execute(
                    "INSERT INTO scan_duplicate_final_urls "
                    "(input_url, final_url, duplicate_of) VALUES (?, ?, ?)",
                    (dup.input_url, dup.final_url, dup.duplicate_of),
                )
            conn.execute(
                "INSERT INTO scan_metadata (discovered_url_count, "
                "skipped_link_count, crawl_limit_reached, crawl_limit_reasons) "
                "VALUES (?, ?, ?, ?)",
                (
                    metadata.discovered_url_count,
                    metadata.skipped_link_count,
                    int(metadata.crawl_limit_reached),
                    json.dumps(metadata.crawl_limit_reasons),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def render_screen(results: list[ScanResult]) -> str:
    """Human-readable report."""
    lines: list[str] = []
    for result in results:
        fetch = result.fetch
        lines.append("=" * 72)
        lines.append(f"URL:        {fetch.input_url}")
        if fetch.final_url != fetch.input_url:
            lines.append(f"Final URL:  {fetch.final_url}")
        if fetch.error:
            lines.append(f"ERROR:      {fetch.error}")
            continue
        lines.append(f"Status:     {fetch.status_code}")
        lines.append(f"CSP:        {fetch.csp or '(none)'}")
        if fetch.csp_report_only:
            lines.append(f"CSP-RO:     {fetch.csp_report_only}")
        if result.assessment:
            assessment = result.assessment
            lines.append(
                f"Risk:       {assessment.level.upper()} "
                f"(score {assessment.score})"
            )
            for finding in assessment.findings:
                lines.append(
                    f"  - {finding.rule_id} [{finding.severity}] "
                    f"{finding.directive}: {finding.explanation}"
                )
                lines.append(f"    Fix: {finding.remediation}")
    lines.append("=" * 72)
    return "\n".join(lines)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
