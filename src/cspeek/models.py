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


class SkippedLink(BaseModel):
    """A link discovered while crawling that was not followed, and why."""

    url: str
    reason: str
    source_url: str = ""


class DuplicateFinalUrl(BaseModel):
    """An input URL whose final (post-redirect) URL duplicated another.

    Recorded when a fetch succeeds but its final URL matches a final URL
    already produced by an earlier input in the same scan, so the
    duplicate is skipped from the main results without losing the
    knowledge that it was scanned.
    """

    input_url: str
    final_url: str
    duplicate_of: str


class ScanMetadata(BaseModel):
    """Discovery/crawl-scope and dedupe bookkeeping for one scan run.

    This is separate from CSP risk scoring: it explains what was in
    scope, what was skipped and why, and which final URLs were
    deduplicated. Example lists are capped for readability; the `_count`
    fields always reflect the true total.
    """

    discovered_urls: list[str] = Field(default_factory=list)
    discovered_url_count: int = 0
    skipped_links: list[SkippedLink] = Field(default_factory=list)
    skipped_link_count: int = 0
    crawl_limit_reached: bool = False
    crawl_limit_reasons: list[str] = Field(default_factory=list)
    duplicate_final_urls: list[DuplicateFinalUrl] = Field(default_factory=list)


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


class StatusIssue(BaseModel):
    """One operational HTTP/fetch issue, separate from CSP findings.

    ``issue_type`` is ``"fetch-error"`` (connection failure, timeout,
    redirect-limit exceeded, etc.) or ``"http-status"`` (a non-2xx/3xx
    status code such as 404 or 500).
    """

    url: str
    status_code: int | None = None
    error: str | None = None
    issue_type: str


class ScanReport(BaseModel):
    """Summary of a set of scan results, produced by ``cspeek report``.

    Built from prior JSON/SQLite output without rescanning any target.

    The fields below `remediation_themes` are operational scan/report
    metadata (HTTP status issues, crawl scope, dedupe) and are entirely
    separate from the deterministic CSP risk-scoring model above. They
    default to empty/zero so reports built from older scan output
    (produced before this metadata existed) remain valid.
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

    # Operational status/discovery metadata (not part of CSP scoring).
    status_code_counts: dict[str, int] = Field(default_factory=dict)
    non_success_urls: list[StatusIssue] = Field(default_factory=list)
    non_success_count: int = 0
    discovered_url_count: int = 0
    skipped_links: list[SkippedLink] = Field(default_factory=list)
    skipped_link_count: int = 0
    crawl_limit_reached: bool = False
    crawl_limit_reasons: list[str] = Field(default_factory=list)
    duplicate_final_urls: list[DuplicateFinalUrl] = Field(default_factory=list)
