<!-- version: 1.1.0 -->
# Current PR Contract

This contract constrains implementation scope for the active PR. Update
it when scope is explicitly amended. If a requested action falls outside
approved scope, stop and escalate before proceeding.

## Goal
Refactor CSPeek into an installable Python CLI package: product command
`cspeek` (not `csp_scanner`), `src/cspeek/` package layout, a
`pyproject.toml` supporting `pip install -e .`, typed (Pydantic) models
for scan results/findings/assessments/reports, and a new `cspeek report`
command that summarises prior JSON/SQLite output without rescanning.
Preserve existing scanner behaviour and test coverage.

## Contract status
active

## Non-goals
- No UI layers, dashboards, web APIs, or service daemons.
- No active/noisy subdomain scanning (wordlist DNS resolution only).
- No unbounded crawling.
- No AI/heuristic judgement in risk scoring — rules only.
- No heavyweight web/service frameworks.
- No `python -m csp_scanner` deprecation shim: the maintainer explicitly
  requested a clean rename with no temporary compatibility path.

## Carry-forward rules
- The deterministic rule-based risk model in `.github/carl/memory.md`
  (fixed severity scores, level thresholds, rules CSP-001..CSP-043)
  applies unchanged; only the package/module location changed.
- Durable invariants in `.github/carl/invariants.yml` apply unchanged
  except where explicitly amended below.

## Approved scope
- Move `csp_scanner/` to a `src/cspeek/` package layout (setuptools
  `src` layout).
- Add `pyproject.toml` (setuptools build backend, `cspeek` console
  script, editable-install support).
- Add `src/cspeek/models.py` with Pydantic models: `Finding`,
  `Assessment`, `FetchResult`, `ScanResult`, `ScanReport`.
- Add `src/cspeek/report.py` and a `cspeek report` CLI subcommand that
  reads prior `scan` JSON/SQLite output and summarises findings/levels
  without issuing any network requests.
- Update `tests/` to import from `cspeek` and add coverage for the
  `report` command/module.
- Update `README.md` to use `cspeek`/`python -m cspeek` examples and
  document `cspeek report`.
- Update cARL durable artefacts to record the amended scope and the new
  `pydantic` dependency.
- Remove the `csp_scanner` package entirely (no deprecation shim).

## Intentional amendments
- **Third-party runtime dependency approved:** `pydantic>=2,<3` is added
  as a runtime dependency for typed scan/report models, explicitly
  requested by the maintainer ("Prefer Pydantic if appropriate"). This
  amends the prior "stdlib-only" constraint and the
  `no-unapproved-dependencies` default posture for this dependency only.
  Checked against the GitHub Advisory Database: no known vulnerabilities
  for the installed version at time of writing.
- **No deprecation shim:** the maintainer explicitly asked not to keep
  `python -m csp_scanner` temporarily; the old package is removed outright
  rather than retained with a deprecation warning.

## Forbidden scope
- Removing or rewriting the existing LICENSE.
- Adding further third-party runtime dependencies beyond `pydantic`
  without new explicit approval.
- Any network calls in tests (including `report` tests, which must only
  read fixture files).
- Modifying `.github/carl/runtime.json` manually.
- Changing the deterministic risk-scoring rules/weights (CSP-001..043,
  severity scores, level thresholds).

## Architectural constraints
- `src/cspeek/` package layout; one module per concern (`inputs`,
  `fetch`, `assess`, `discovery`, `scanner`, `output`, `report`, `cli`,
  `models`).
- Typed models (Pydantic `BaseModel`) are the canonical representation
  for scan results, findings, assessments, and report summaries.
- Risk rules remain defined as data, evaluated deterministically.
- `cspeek report` must not perform any scanning/network I/O; it only
  reads and aggregates previously written output.

## Security constraints
- Bounded network behaviour unchanged: timeouts, redirect caps, crawl
  caps, same-origin default for crawling.
- No secrets in code. Validate/normalise URLs; only http/https schemes.
- SSRF-adjacent behaviour must stay opt-in and bounded.
- `pydantic` version pinned to a `2.x` range with no known advisories at
  time of adoption; re-check the advisory database on future upgrades.

## Files expected to change
- `pyproject.toml` (new)
- `src/cspeek/**` (new; replaces `csp_scanner/**`)
- `csp_scanner/**` (removed)
- `tests/**` (updated imports; new `tests/test_report.py`)
- `README.md`
- `.github/carl/**` (cARL artefacts)

## Tests / validation
- `pip install -e .`
- `python -m unittest discover -s tests -v`
- `python -m py_compile src/cspeek/*.py`
- `cspeek --help` / `python -m cspeek --help` smoke checks.
- CodeQL review of changed files.

## Stop conditions
- Any requirement forces a dependency beyond `pydantic` without renewed
  approval.
- Tests would require live internet access.
- Risk-scoring behaviour would change as a side effect of the refactor.

## Escalation triggers
- Ambiguity in risk-scoring weights that changes level boundaries.
- Any need to alter LICENSE or repository structure beyond scope.

## Context reset notes
Implementation: `src/cspeek/` package, `pyproject.toml`, Pydantic models,
`cspeek report`, updated tests (64 passing) and README are done. Close
this contract on merge. Follow-up candidates remain recorded under "Open
questions" in memory.md (multi-header CSP merging, meta-tag CSP,
strict-dynamic modelling).
