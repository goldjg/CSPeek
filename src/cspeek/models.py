"""Typed data models for scan results, findings, assessments, and reports.

These are Pydantic models so JSON (de)serialisation, validation, and
schema generation are consistent whether the data was just produced by
a scan or loaded back from a prior JSON/SQLite output for ``cspeek
report``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """One deterministic rule violation raised against a CSP."""

    rule_id: str
    severity: str
    directive: str
    explanation: str
    score: int
    remediation: str

    def to_dict(self) -> dict:
        return self.model_dump()


class Assessment(BaseModel):
    """The aggregate risk assessment for one CSP (and its findings)."""

    score: int
    level: str
    findings: list[Finding] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return self.model_dump()


class FetchResult(BaseModel):
    """Outcome of retrieving one URL."""

    input_url: str
    final_url: str
    status_code: int | None = None
    csp: str | None = None
    csp_report_only: str | None = None
    redirects: int = 0
    error: str | None = None
    body: str = ""
    content_type: str = ""

    @property
    def has_csp(self) -> bool:
        return self.csp is not None


class ScanResult(BaseModel):
    """One scanned URL: fetch outcome plus risk assessment."""

    fetch: FetchResult
    assessment: Assessment | None = None
    scan_timestamp: str


class HighRiskURL(BaseModel):
    """One URL surfaced in the highest-risk ranking."""

    url: str
    score: int
    level: str


class PolicyGroup(BaseModel):
    """A distinct CSP header value shared verbatim by one or more URLs."""

    csp: str
    count: int
    score: int | None = None
    level: str | None = None
    rule_ids: list[str] = Field(default_factory=list)
    example_urls: list[str] = Field(default_factory=list)


class RemediationTheme(BaseModel):
    """One remediation grouped across every finding that recommends it."""

    remediation: str
    rule_ids: list[str] = Field(default_factory=list)
    affected_url_count: int = 0
    example_urls: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Summary of a set of scan results, produced by ``cspeek report``.

    Built from prior JSON/SQLite output without rescanning any target.
    """

    total: int
    with_csp: int
    without_csp: int
    errors: int
    level_counts: dict[str, int] = Field(default_factory=dict)
    rule_counts: dict[str, int] = Field(default_factory=dict)
    rule_affected_urls: dict[str, list[str]] = Field(default_factory=dict)
    highest_risk_urls: list[HighRiskURL] = Field(default_factory=list)
    repeated_policies: list[PolicyGroup] = Field(default_factory=list)
    remediation_themes: list[RemediationTheme] = Field(default_factory=list)
    results: list[ScanResult] = Field(default_factory=list)
