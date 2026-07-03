<!-- version: 1.1.0 -->
# Current PR Contract

This contract constrains implementation scope for the active PR. Update
it when scope is explicitly amended. If a requested action falls outside
approved scope, stop and escalate before proceeding.

## Goal
Improve `cspeek report` so it produces a more useful human-facing
findings report: richer aggregation (highest-risk URLs, affected URLs
per rule, repeated/equivalent CSP policy grouping, remediation themes),
an improved human-readable screen layout, and a matching structured JSON
summary shape. Do not change scan behaviour, crawl/subdomain behaviour,
or the deterministic CSP risk-scoring rules.

## Contract status
active

## Non-goals
- No UI layers, dashboards, web APIs, or service daemons.
- No active/noisy subdomain scanning (wordlist DNS resolution only).
- No unbounded crawling.
- No AI/heuristic judgement in risk scoring — rules only.
- No heavyweight web/service frameworks.
- No semantic CSP normalisation for policy grouping (exact-string
  matching only in this PR).
- No change to `cspeek scan` behaviour, fetch behaviour, crawl behaviour,
  subdomain enumeration, or the scan JSON/CSV/SQLite output schema.

## Carry-forward rules
- The deterministic rule-based risk model in `.github/carl/memory.md`
  (fixed severity scores, level thresholds, rules CSP-001..CSP-043)
  applies unchanged.
- Durable invariants in `.github/carl/invariants.yml` apply unchanged
  except where explicitly amended below.
- `cspeek report` must remain network-free and must continue to read
  the existing `cspeek scan` JSON/SQLite output without requiring a scan
  output schema change.

## Approved scope
- Extend `src/cspeek/models.py`'s `ScanReport` (and add small supporting
  models: `HighRiskURL`, `PolicyGroup`, `RemediationTheme`) with:
  affected URLs per finding rule, highest-risk URLs, repeated/equivalent
  CSP policy groups (exact-string matching), and remediation themes
  grouped by remediation text.
- Extend `src/cspeek/report.py`'s `summarise()` to compute the new
  aggregations deterministically from existing `ScanResult` data, with
  no new network I/O.
- Update `render_report_screen()` to show Summary, Risk levels, Top
  findings, Highest-risk URLs, Repeated CSP policies, Remediation
  themes, and Fetch error details sections in plain terminal text (no
  rich UI/HTML/dashboard).
- Update `tests/test_report.py` with coverage for the new aggregation,
  JSON shape, human-readable sections, and continued JSON/SQLite
  backwards compatibility.
- Update `README.md` with `cspeek report` examples, an explanation of
  repeated CSP policy grouping (exact-string, not semantic), a
  human-readable summary example, and a brief JSON summary shape.
- Update cARL durable artefacts to record the new report aggregation
  behaviour and that grouping is exact-string matching for now.

## Intentional amendments
- None for this PR. The prior `pydantic` dependency amendment and the
  "no deprecation shim" decision from the CLI-packaging PR remain in
  effect as historical record but are not re-opened here.

## Forbidden scope
- Removing or rewriting the existing LICENSE.
- Adding further third-party runtime dependencies beyond `pydantic`
  without new explicit approval.
- Any network calls in tests (including `report` tests, which must only
  read fixture files).
- Modifying `.github/carl/runtime.json` manually.
- Changing the deterministic risk-scoring rules/weights (CSP-001..043,
  severity scores, level thresholds).
- Changing `cspeek scan` fetch/crawl/subdomain behaviour.
- Changing the scan JSON/CSV/SQLite output schema in
  `src/cspeek/output.py` in a backward-incompatible way.
- Semantic/normalised CSP comparison for policy grouping (exact-string
  matching only; normalisation is an explicit future follow-up).

## Architectural constraints
- `src/cspeek/` package layout; one module per concern (`inputs`,
  `fetch`, `assess`, `discovery`, `scanner`, `output`, `report`, `cli`,
  `models`).
- Typed models (Pydantic `BaseModel`) are the canonical representation
  for scan results, findings, assessments, and report summaries.
- Risk rules remain defined as data, evaluated deterministically.
- `cspeek report` must not perform any scanning/network I/O; it only
  reads and aggregates previously written output.
- New report aggregation must be pure/deterministic functions over
  already-loaded `ScanResult` data (no hidden state, no randomness).

## Security constraints
- Bounded network behaviour unchanged: timeouts, redirect caps, crawl
  caps, same-origin default for crawling.
- No secrets in code. Validate/normalise URLs; only http/https schemes.
- SSRF-adjacent behaviour must stay opt-in and bounded.
- `pydantic` version pinned to a `2.x` range with no known advisories at
  time of adoption; re-check the advisory database on future upgrades.

## Files expected to change
- `src/cspeek/models.py` (new report sub-models, extended `ScanReport`)
- `src/cspeek/report.py` (aggregation logic, screen rendering)
- `tests/test_report.py` (new/updated coverage)
- `README.md`
- `.github/carl/**` (cARL artefacts)

## Tests / validation
- `pip install -e .`
- `python -m unittest discover -s tests -v`
- `python -m py_compile src/cspeek/*.py`
- `cspeek --help` / `cspeek report --help` smoke checks.
- CodeQL review of changed files.

## Stop conditions
- Any requirement forces a dependency beyond `pydantic` without renewed
  approval.
- Tests would require live internet access.
- Risk-scoring or scan behaviour would change as a side effect of this
  report-focused change.

## Escalation triggers
- Ambiguity in risk-scoring weights that changes level boundaries.
- Any need to alter LICENSE or repository structure beyond scope.
- Any requirement to change the scan output schema in a way that is not
  backward-compatible.

## Context reset notes
Implementation: `ScanReport` aggregation (rule-affected URLs,
highest-risk URLs, repeated-policy grouping, remediation themes),
updated screen/JSON report output, expanded `tests/test_report.py`, and
README updates are done. Close this contract on merge. Follow-up
candidates remain recorded under "Open questions" in memory.md
(multi-header CSP merging, meta-tag CSP, strict-dynamic modelling, and
now optional semantic CSP normalisation for policy grouping).
