"""Deterministic, rule-based CSP risk assessment.

Every rule is data-driven and explainable: rule ID, severity, affected
directive, explanation, score contribution, and remediation guidance.
The same policy always yields the same findings and score. Policies are
derived from cARL security principles (deterministic, explainable,
bounded, no vague judgement).
"""

from __future__ import annotations

from .models import Assessment, Finding

SEVERITY_SCORES = {"low": 5, "medium": 10, "high": 20, "critical": 40}

LEVEL_THRESHOLDS = (  # (minimum score, level) evaluated top-down
    (40, "critical"),
    (25, "high"),
    (15, "medium"),
    (0, "low"),
)

FETCH_FALLBACK_DIRECTIVES = ("script-src", "object-src")


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Parse a CSP header value into {directive: [sources]}.

    The first occurrence of a directive wins, matching browser behaviour.
    """
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def _effective(directives: dict[str, list[str]], name: str) -> list[str] | None:
    """Resolve a fetch directive with default-src fallback."""
    if name in directives:
        return directives[name]
    if name in FETCH_FALLBACK_DIRECTIVES and "default-src" in directives:
        return directives["default-src"]
    return None


def _finding(rule_id, severity, directive, explanation, remediation) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        directive=directive,
        explanation=explanation,
        score=SEVERITY_SCORES[severity],
        remediation=remediation,
    )


def score_to_level(score: int) -> str:
    for minimum, level in LEVEL_THRESHOLDS:
        if score >= minimum:
            return level
    return "low"


def assess(csp: str | None, csp_report_only: str | None = None) -> Assessment:
    """Assess a CSP (and optional report-only CSP) deterministically."""
    findings: list[Finding] = []

    if csp is None:
        if csp_report_only:
            findings.append(_finding(
                "CSP-002", "high", "(header)",
                "Only Content-Security-Policy-Report-Only is present; the "
                "policy is observed but never enforced.",
                "Promote the report-only policy to an enforced "
                "Content-Security-Policy header once tuned.",
            ))
            findings.extend(_policy_findings(csp_report_only))
        else:
            findings.append(_finding(
                "CSP-001", "critical", "(header)",
                "No Content-Security-Policy header is present; the page has "
                "no CSP protection against XSS or injection.",
                "Add a restrictive Content-Security-Policy header, starting "
                "from default-src 'none' or 'self'.",
            ))
    else:
        findings.extend(_policy_findings(csp))

    score = sum(f.score for f in findings)
    return Assessment(score=score, level=score_to_level(score), findings=findings)


def _policy_findings(policy: str) -> list[Finding]:
    directives = parse_csp(policy)
    findings: list[Finding] = []

    default_src = directives.get("default-src")
    script_src = _effective(directives, "script-src")
    object_src = _effective(directives, "object-src")

    # unsafe-inline / unsafe-eval
    for name in ("default-src", "script-src", "style-src"):
        sources = directives.get(name)
        if sources and "'unsafe-inline'" in sources:
            has_nonce_or_hash = any(
                s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for s in sources
            )
            if name == "style-src":
                severity = "medium"
            else:
                severity = "high" if not has_nonce_or_hash else "medium"
            note = (
                " A nonce/hash is also present, which disables "
                "'unsafe-inline' in CSP2+ browsers." if has_nonce_or_hash else
                " No nonce or hash is present to constrain inline content."
            )
            findings.append(_finding(
                "CSP-010", severity, name,
                f"'unsafe-inline' in {name} allows inline scripts/styles, "
                f"largely defeating CSP XSS protection.{note}",
                "Remove 'unsafe-inline'; use nonces or hashes for required "
                "inline content.",
            ))
    for name in ("default-src", "script-src"):
        sources = directives.get(name)
        if sources and "'unsafe-eval'" in sources:
            findings.append(_finding(
                "CSP-011", "high", name,
                f"'unsafe-eval' in {name} allows eval()/Function() and "
                "similar dynamic code execution.",
                "Remove 'unsafe-eval' and refactor away from eval-style "
                "APIs.",
            ))

    # wildcard sources
    for name, sources in directives.items():
        if sources and "*" in sources:
            severity = "critical" if name in ("default-src", "script-src") else "medium"
            findings.append(_finding(
                "CSP-020", severity, name,
                f"Wildcard source '*' in {name} allows loading from any "
                "origin.",
                "Replace '*' with an explicit allow-list of required "
                "origins.",
            ))

    # overly broad default-src / script-src (scheme-only or wide host)
    if default_src is not None:
        broad = _broad_sources(default_src)
        if broad:
            findings.append(_finding(
                "CSP-021", "high", "default-src",
                f"default-src contains overly broad sources: "
                f"{', '.join(broad)}.",
                "Restrict default-src to 'self' or 'none' plus specific "
                "origins.",
            ))
    if "script-src" in directives:
        broad = _broad_sources(directives["script-src"])
        if broad:
            findings.append(_finding(
                "CSP-022", "high", "script-src",
                f"script-src contains overly broad sources: "
                f"{', '.join(broad)}.",
                "Restrict script-src to specific origins, nonces, or "
                "hashes.",
            ))

    # scheme-only sources anywhere (https:, http:)
    for name, sources in directives.items():
        scheme_only = [s for s in sources if s in ("https:", "http:")]
        if scheme_only and name not in ("default-src", "script-src"):
            findings.append(_finding(
                "CSP-023", "medium", name,
                f"Scheme-only source(s) {', '.join(scheme_only)} in {name} "
                "allow any host over that scheme.",
                "Replace scheme-only sources with explicit origins.",
            ))

    # data: in script-src or object-src (effective values)
    for name, sources in (("script-src", script_src), ("object-src", object_src)):
        if sources and "data:" in sources:
            findings.append(_finding(
                "CSP-030", "critical", name,
                f"data: URIs allowed in effective {name}; attacker-supplied "
                "data: payloads can execute.",
                f"Remove data: from {name}.",
            ))

    # missing hardening directives
    if object_src is None:
        findings.append(_finding(
            "CSP-040", "medium", "object-src",
            "Neither object-src nor default-src restricts plugin content; "
            "legacy plugin vectors remain open.",
            "Add object-src 'none'.",
        ))
    if "base-uri" not in directives:
        findings.append(_finding(
            "CSP-041", "medium", "base-uri",
            "base-uri is not restricted; injected <base> tags can redirect "
            "relative URLs.",
            "Add base-uri 'self' or 'none'.",
        ))
    if "frame-ancestors" not in directives:
        findings.append(_finding(
            "CSP-042", "medium", "frame-ancestors",
            "frame-ancestors is not set; the page may be framed for "
            "clickjacking.",
            "Add frame-ancestors 'none' or 'self'.",
        ))
    if default_src is None and "script-src" not in directives:
        findings.append(_finding(
            "CSP-043", "high", "script-src",
            "Neither default-src nor script-src is defined; script loading "
            "is unrestricted.",
            "Define default-src and/or script-src.",
        ))

    return findings


def _broad_sources(sources: list[str]) -> list[str]:
    """Return sources considered overly broad (scheme-only, bare wildcard-ish)."""
    broad = []
    for s in sources:
        if s in ("https:", "http:", "*"):
            if s != "*":  # '*' already reported by CSP-020
                broad.append(s)
        elif s.startswith("*."):
            broad.append(s)
    return broad
