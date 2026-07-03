<!-- version: 1.2.0 -->
# Current PR Contract

This contract constrains implementation scope for the active PR. Update
it when scope is explicitly amended. If a requested action falls outside
approved scope, stop and escalate before proceeding.

## Goal
Improve scan/report transparency: deduplicate scan results by final URL
after fetch (without discarding useful error results), record crawl
scope (discovered URLs, skipped out-of-scope links and why, crawl-limit
reached), and surface HTTP/status issues in `cspeek report` output
separately from CSP risk scoring. Do not change the deterministic CSP
risk-scoring rules.

## Contract status
active

## Non-goals
- No UI layers, dashboards, web APIs, or service daemons.
- No active/noisy subdomain scanning (wordlist DNS resolution only).
- No unbounded crawling; no robots handling, browser automation, or
  JavaScript execution.
- No AI/heuristic judgement in risk scoring — rules only.
- No heavyweight web/service frameworks.
- No semantic CSP normalisation for policy grouping (still exact-string
  matching; unrelated to this PR).
- No change to the deterministic CSP-001..CSP-043 rule set, severity
  scores, or level thresholds.

## Carry-forward rules
- The deterministic rule-based risk model in `.github/carl/memory.md`
  (fixed severity scores, level thresholds, rules CSP-001..CSP-043)
  applies unchanged.
- Durable invariants in `.github/carl/invariants.yml` apply unchanged
  except where explicitly amended below.
- `cspeek report` must remain network-free.
- Prior report aggregation (highest-risk URLs, repeated CSP policies,
  remediation themes, affected URLs per rule) remains unchanged and is
  carried forward from the previous PR contract.

## Approved scope
- Extend `src/cspeek/models.py` with `SkippedLink`, `DuplicateFinalUrl`,
  `ScanMetadata`, `StatusIssue`, and extend `ScanReport` with
  status/discovery/dedupe fields, all optional/defaulted so older scan
  JSON/SQLite remain readable.
- Extend `src/cspeek/discovery.py` with `crawl_with_scope()` (skip
  visibility, crawl-limit reporting); keep `crawl()` as a compatible
  wrapper.
- Extend `src/cspeek/scanner.py` with `scan_targets_with_metadata()`
  (final-URL dedupe after fetch, discovery metadata aggregation); keep
  `scan_targets()` as a compatible wrapper.
- Extend `src/cspeek/output.py` writers with an optional `metadata`
  argument (JSON becomes `{"results": ..., "metadata": ...}` only when
  metadata is supplied; SQLite gains three additional append-only
  tables).
- Extend `src/cspeek/report.py` with metadata-aware loaders
  (`load_json_report_full`, `load_sqlite_report_full`), a `summarise()`
  `metadata` parameter, and new report sections (HTTP status summary,
  non-success URLs, skipped out-of-scope links, duplicate final URL
  skips, crawl/discovery notes) shown only when data is present.
- Update `src/cspeek/cli.py` to use the metadata-aware scan/report
  functions.
- Add/update tests across `tests/test_discovery.py`,
  `tests/test_scanner.py` (new), `tests/test_report.py`,
  `tests/test_cli.py` for dedupe, crawl-scope skip visibility, and
  backward-compatible report loading — all via local fixtures/mocked
  fetchers, no live network.
- Update `README.md` and `.github/carl/**` cARL artefacts.

## Intentional amendments
- None beyond what is described above. Prior PR contract amendments
  (pydantic dependency, no deprecation shim, exact-string CSP policy
  grouping) remain historical record and are not reopened.

## Forbidden scope
- Removing or rewriting the existing LICENSE.
- Adding further third-party runtime dependencies beyond `pydantic`
  without new explicit approval.
- Any network calls in tests (all fetchers/resolvers must be
  fixtures/mocks).
- Modifying `.github/carl/runtime.json` manually.
- Changing the deterministic risk-scoring rules/weights (CSP-001..043,
  severity scores, level thresholds).
- Aggressive/unbounded crawling, robots handling, browser automation, or
  JavaScript execution.
- Committing generated artefacts (`__pycache__`, `*.pyc`,
  `.pytest_cache`, build outputs, egg-info, local SQLite DBs, or local
  scan/report JSON files).

## Architectural constraints
- `src/cspeek/` package layout; one module per concern (`inputs`,
  `fetch`, `assess`, `discovery`, `scanner`, `output`, `report`, `cli`,
  `models`).
- Typed models (Pydantic `BaseModel`) are the canonical representation
  for scan results, findings, assessments, discovery/dedupe metadata,
  and report summaries.
- Risk rules remain defined as data, evaluated deterministically;
  status/discovery metadata is computed independently and must never
  feed into `assess.py`'s scoring.
- `cspeek report` must not perform any scanning/network I/O.
- New scan/report metadata must be pure/deterministic over already-
  fetched/loaded data (no hidden state, no randomness); example lists
  are capped for readability while count fields stay accurate.
- Backward compatibility: existing scan JSON/SQLite fields are stable;
  new metadata is additive and optional everywhere it is read.

## Security constraints
- Bounded network behaviour unchanged: timeouts, redirect caps, crawl
  caps, same-origin default for crawling, `--allow-cross-origin` remains
  explicit opt-in.
- No secrets in code. Validate/normalise URLs; only http/https schemes.
- SSRF-adjacent behaviour must stay opt-in and bounded.
- `pydantic` version pinned to a `2.x` range with no known advisories at
  time of adoption; re-check the advisory database on future upgrades.

## Files expected to change
- `src/cspeek/models.py`
- `src/cspeek/discovery.py`
- `src/cspeek/scanner.py`
- `src/cspeek/output.py`
- `src/cspeek/report.py`
- `src/cspeek/cli.py`
- `tests/test_discovery.py`, `tests/test_scanner.py`,
  `tests/test_report.py`, `tests/test_cli.py`
- `README.md`
- `.github/carl/**`

## Tests / validation
- `pip install -e .`
- `python -m unittest discover -s tests -v`
- `python -m py_compile src/cspeek/*.py`
- `cspeek --help` / `cspeek scan --help` / `cspeek report --help` smoke
  checks.
- CodeQL review of changed files.

## Stop conditions
- Any requirement forces a dependency beyond `pydantic` without renewed
  approval.
- Tests would require live internet access.
- The deterministic CSP risk-scoring rules would change as a side effect
  of this transparency-focused change.

## Escalation triggers
- Ambiguity in risk-scoring weights that changes level boundaries.
- Any need to alter LICENSE or repository structure beyond scope.
- Any requirement to change the scan output schema in a way that is not
  backward-compatible (i.e. that would make older scan JSON/SQLite
  unreadable by `cspeek report`).

## Context reset notes
Implementation: final-URL dedupe (`scan_targets_with_metadata`), crawl
scope visibility (`crawl_with_scope`, `SkippedLink`), HTTP status/fetch
issue reporting separate from CSP scoring (`StatusIssue`,
`_status_issues`), backward-compatible `ScanMetadata` persistence in
JSON/SQLite, new report sections, README/tests/cARL updates are done.
Close this contract on merge; the previous `cspeek report`
findings-aggregation contract's carry-forward rules remain in effect
unchanged.
