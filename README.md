# CSPeek

CSPeek is a defensive Content-Security-Policy (CSP) configuration auditing
tool. It retrieves HTTP response headers from URLs you supply, inspects the
`Content-Security-Policy` and `Content-Security-Policy-Report-Only` headers,
and produces deterministic, explainable configuration hygiene findings with
a numeric risk score.

CSPeek helps defenders identify weak or missing CSP headers and improve
browser-side security configuration. It performs no exploitation, payload
generation, fuzzing, port scanning, or service fingerprinting.

## Authorised use only

Only scan URLs you own, operate, or have explicit permission to assess.
CSPeek issues ordinary HTTP GET requests with a clear `CSPeek/...`
User-Agent, bounded timeouts, and a redirect cap. Optional crawling and
subdomain discovery are disabled by default and strictly bounded when
enabled.

## Requirements

- Python 3.10+
- [Pydantic](https://docs.pydantic.dev/) 2.x (installed automatically as a
  dependency; used for typed scan/report models)

## Installation

Clone the repository and install it as a package (an editable install is
recommended for development):

```sh
git clone https://github.com/goldjg/CSPeek
cd CSPeek
pip install -e .
cspeek scan --help
```

This installs the `cspeek` console command. You can also run it as a
module without installing a console script:

```sh
python -m cspeek scan --help
```

## Usage

```sh
# Scan a single URL (missing scheme defaults to https://)
cspeek scan https://example.com
cspeek scan example.com

# Scan a file of URLs (one per line; blank lines and # comments ignored)
cspeek scan --input urls.txt

# Write results to JSON / CSV / SQLite (can be combined)
cspeek scan --input urls.txt --json results.json
cspeek scan --input urls.txt --csv results.csv
cspeek scan --input urls.txt --sqlite results.db

# Bounded same-origin crawl (opt-in)
cspeek scan https://example.com --crawl --max-depth 2 --max-urls 100

# Conservative wordlist-based subdomain discovery (opt-in)
cspeek scan example.com --enumerate-subdomains

# Summarise a prior scan's JSON or SQLite output without rescanning
cspeek report --json results.json
cspeek report --sqlite results.db --output summary.json --quiet
```

Flags for `cspeek scan`:

| Flag | Default | Purpose |
|---|---|---|
| `--input PATH` | — | File of URLs, one per line |
| `--json/--csv/--sqlite PATH` | — | Structured outputs |
| `--timeout SECONDS` | 10 | Per-request timeout |
| `--crawl` | off | Follow same-origin links on scanned pages |
| `--max-depth N` | 2 | Crawl depth bound |
| `--max-urls N` | 100 | Crawl URL count bound |
| `--allow-cross-origin` | off | Let the crawler leave the start origin |
| `--enumerate-subdomains` | off | Resolve a fixed wordlist of ~20 common subdomains via DNS |
| `--quiet` | off | Suppress the on-screen report |

Flags for `cspeek report`:

| Flag | Default | Purpose |
|---|---|---|
| `--json PATH` | — | Read prior JSON results (mutually exclusive with `--sqlite`) |
| `--sqlite PATH` | — | Read prior SQLite results (mutually exclusive with `--json`) |
| `--output PATH` | — | Write the summary as JSON to PATH |
| `--quiet` | off | Suppress the human-readable summary on stdout |

`cspeek report` never issues network requests; it only reads a previously
written `cspeek scan` output (JSON file or SQLite `scans` table) and
aggregates it into a human-facing findings summary: totals, CSP presence,
fetch errors, risk-level distribution, findings by rule (with affected
URLs), highest-risk URLs, repeated/equivalent CSP policies, and
remediation themes grouped across findings. It never rescans a target,
so it is safe to run repeatedly against the same scan output.

`cspeek report` also surfaces operational scan/report metadata that is
entirely separate from CSP risk scoring: HTTP status issues, crawl scope
(what was skipped and why), and duplicate-final-URL skips. See the
sections below.

### Final URL dedupe

Different input URLs can redirect to the same final URL — for example
`https://example.com` and `https://www.example.com` both resolving to
`https://example.com/`. When scanning multiple inputs, crawling, or
enumerating subdomains, `cspeek scan` deduplicates by **final URL after
fetch**: the first input to reach a given final URL is kept in the main
results, and later inputs that redirect to the same final URL are
recorded as duplicate-final-URL skips instead of being reported twice.

Fetch errors are never deduplicated this way, since a final URL may not
be meaningfully known when a fetch fails — every error result is always
kept. Duplicate-final-URL skips are written into the scan's JSON/SQLite
metadata and shown by `cspeek report` under "Duplicate final URL skips".

### Crawl scope visibility

Crawling (`--crawl`) remains same-origin by default and bounded by
`--max-depth`/`--max-urls`; cross-origin crawling is opt-in via
`--allow-cross-origin`. Rather than silently ignoring links outside the
crawl's scope, `cspeek scan` records:

- every URL discovered/fetched during the crawl;
- links skipped because they are cross-origin and cross-origin crawling
  was not allowed;
- links skipped because they use a non-http(s) scheme (`mailto:`,
  `javascript:`, etc.);
- whether a crawl limit (`max-depth` or `max-urls`) was reached.

This is bookkeeping only: it does not change what gets fetched, only
what gets reported. `cspeek report` shows "Skipped out-of-scope links"
and "Crawl/discovery notes" sections when this data is present.

### Status issues are not CSP findings

HTTP/status issues (404s, 500s, redirect loops, connection errors) are
operational scan findings, not CSP configuration findings, and never
affect the deterministic CSP risk score. `cspeek report` shows them
separately under "HTTP status summary" (status code counts) and
"Non-success URLs" (the specific non-2xx/3xx URLs and fetch errors).

### Repeated CSP policy grouping

Many sites serve an identical CSP across every page (a shared template,
CDN edge config, or framework default). `cspeek report` groups scanned
URLs that share the *exact same* `Content-Security-Policy` header string
and reports, per group: how many URLs share it, its risk score/level, the
rule IDs it triggers, and a handful of example URLs.

This grouping is deliberately exact-string matching, not semantic CSP
normalisation: `default-src 'self'` and `default-src  'self'` (extra
whitespace) or a policy with directives in a different order are treated
as distinct groups. Only groups with two or more URLs are reported as
"repeated" (a policy used by exactly one URL is not a duplicate).

### Example human-readable summary

```
========================================================================
Summary
Total scanned:  5
With CSP:       3
Without CSP:    2
Fetch errors:   1
------------------------------------------------------------------------
Risk levels:
  - critical: 3
  - low: 1
------------------------------------------------------------------------
Top findings (by rule ID):
  - CSP-020: 2 finding(s) across 2 URL(s)
  - CSP-041: 2 finding(s) across 2 URL(s)
------------------------------------------------------------------------
Highest-risk URLs:
  - https://a.example: CRITICAL (score 60)
  - https://b.example: CRITICAL (score 60)
------------------------------------------------------------------------
Repeated CSP policies:
  - shared by 2 URLs, risk CRITICAL (score 60)
    CSP: default-src *
    Findings: CSP-020, CSP-041, CSP-042
    Examples: https://a.example, https://b.example
------------------------------------------------------------------------
Remediation themes:
  - Replace '*' with an explicit allow-list of required origins. (affects 2 URL(s); rules CSP-020)
------------------------------------------------------------------------
HTTP status summary:
  - 200: 4 URL(s)
  - 404: 1 URL(s)
------------------------------------------------------------------------
Non-success URLs (2 total):
  - https://missing.example: status 404
  - https://e.example: OSError: connection refused
------------------------------------------------------------------------
Skipped out-of-scope links (1 total):
  - https://evil.example/: cross-origin-not-allowed (found on https://a.example/)
------------------------------------------------------------------------
Duplicate final URL skips:
  - https://www.a.example -> https://a.example (duplicate of https://a.example)
------------------------------------------------------------------------
Crawl/discovery notes:
  - discovered URLs: 6
------------------------------------------------------------------------
Fetch error details:
  - https://e.example: OSError: connection refused
========================================================================
```

Sections only appear when there is data to show: a scan with no crawling,
no dedupe skips, and only successful fetches omits the status/discovery
sections entirely.

Exit code is `0` on success, `1` if any target had a fetch error (`scan`
only), `2` for usage errors.

## Output formats

### Screen

A human-readable report per URL: final URL after redirects, status code,
raw CSP header(s), risk level/score, and each finding with remediation.

### JSON

When no scan-metadata is available to persist (the plain per-URL result
case), `cspeek scan --json` writes a bare array of result objects, the
same shape it has always written:

```json
[
  {
    "scan_timestamp": "2026-07-03T19:00:00+00:00",
    "input_url": "https://example.com",
    "final_url": "https://example.com/",
    "status_code": 200,
    "csp": "default-src 'self'",
    "csp_report_only": null,
    "has_csp": true,
    "risk_score": 30,
    "risk_level": "high",
    "findings": [
      {
        "rule_id": "CSP-041",
        "severity": "medium",
        "directive": "base-uri",
        "explanation": "base-uri is not restricted; ...",
        "score": 10,
        "remediation": "Add base-uri 'self' or 'none'."
      }
    ],
    "error": null
  }
]
```

`cspeek scan` always writes scan metadata (discovered/skipped URLs,
crawl-limit status, duplicate-final-URL skips) alongside the results, so
in practice the JSON written by `cspeek scan --json` is
`{"results": [...], "metadata": {...}}`, where `results` holds the same
row objects shown above. `cspeek report` transparently reads **both**
shapes — a bare array (older scan output, or JSON hand-written/produced
by another tool) and the `{"results": ..., "metadata": ...}` object — so
older scan JSON remains fully report-compatible with no migration step.

### `cspeek report --output` JSON summary

`cspeek report --json results.json --output summary.json` writes a
`ScanReport` object (brief shape shown; see `src/cspeek/models.py` for
the full schema):

```json
{
  "total": 5,
  "with_csp": 3,
  "without_csp": 2,
  "errors": 1,
  "level_counts": {"critical": 3, "low": 1},
  "rule_counts": {"CSP-020": 2, "CSP-041": 2},
  "rule_affected_urls": {"CSP-020": ["https://a.example", "https://b.example"]},
  "highest_risk_urls": [
    {"url": "https://a.example", "score": 60, "level": "critical"}
  ],
  "repeated_policies": [
    {
      "csp": "default-src *",
      "count": 2,
      "score": 60,
      "level": "critical",
      "rule_ids": ["CSP-020", "CSP-041", "CSP-042"],
      "example_urls": ["https://a.example", "https://b.example"]
    }
  ],
  "remediation_themes": [
    {
      "remediation": "Replace '*' with an explicit allow-list of required origins.",
      "rule_ids": ["CSP-020"],
      "affected_url_count": 2,
      "example_urls": ["https://a.example", "https://b.example"]
    }
  ],
  "results": ["... full per-URL ScanResult objects ..."],

  "status_code_counts": {"200": 4, "404": 1},
  "non_success_urls": [
    {"url": "https://missing.example", "status_code": 404, "error": null,
     "issue_type": "http-status"},
    {"url": "https://e.example", "status_code": null,
     "error": "OSError: connection refused", "issue_type": "fetch-error"}
  ],
  "non_success_count": 2,
  "discovered_url_count": 6,
  "skipped_links": [
    {"url": "https://evil.example/", "reason": "cross-origin-not-allowed",
     "source_url": "https://a.example/"}
  ],
  "skipped_link_count": 1,
  "crawl_limit_reached": false,
  "crawl_limit_reasons": [],
  "duplicate_final_urls": [
    {"input_url": "https://www.a.example", "final_url": "https://a.example",
     "duplicate_of": "https://a.example"}
  ]
}
```

The fields from `status_code_counts` onward are operational scan/report
metadata (HTTP status issues, crawl scope, final-URL dedupe) and are
entirely separate from the deterministic CSP risk-scoring fields above
them; they default to empty/zero/false when summarising older scan
output that predates this metadata.

`highest_risk_urls` and example-URL lists in `repeated_policies` /
`remediation_themes` are capped (10 and 5 entries respectively) so the
summary stays readable regardless of scan size; the underlying counts
(`count`, `affected_url_count`, `rule_counts`) are never truncated.
`non_success_urls` and `skipped_links` are similarly capped (20)
with accurate `non_success_count`/`skipped_link_count` totals.


### CSV

One row per URL with the same fields; `findings` is flattened to
`RULE[severity] directive` entries joined by `; `.

### SQLite

Results are appended to a durable `scans` table:

```sql
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp TEXT NOT NULL,   -- ISO-8601 UTC
    input_url TEXT NOT NULL,
    final_url TEXT,
    status_code INTEGER,
    csp TEXT,
    csp_report_only TEXT,
    has_csp INTEGER NOT NULL,       -- 0/1
    risk_score INTEGER,
    risk_level TEXT,
    findings TEXT,                  -- JSON array of finding objects
    error TEXT
);
```

Scan metadata (skipped links, duplicate-final-URL skips, discovery
counts) is appended to three additional tables, kept separate so older
databases without them remain fully readable by `cspeek report`:

```sql
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
    crawl_limit_reasons TEXT            -- JSON array of strings
);
```

## Risk scoring

Assessment is fully deterministic and rule-based: the same policy always
produces the same findings and score. Each finding contributes a fixed
score by severity:

| Severity | Score |
|---|---|
| low | 5 |
| medium | 10 |
| high | 20 |
| critical | 40 |

The total maps to a risk level:

| Total score | Level |
|---|---|
| 0–14 | low |
| 15–24 | medium |
| 25–39 | high |
| 40+ | critical |

### Rules

| Rule | Severity | Trigger |
|---|---|---|
| CSP-001 | critical | No CSP header at all |
| CSP-002 | high | Only `Content-Security-Policy-Report-Only` present (policy not enforced; the report-only policy is still assessed) |
| CSP-010 | high / medium | `'unsafe-inline'` in `default-src`/`script-src` (medium when a nonce/hash is also present, or in `style-src`) |
| CSP-011 | high | `'unsafe-eval'` in `default-src`/`script-src` |
| CSP-020 | critical / medium | Wildcard `*` source (critical in `default-src`/`script-src`) |
| CSP-021 | high | Overly broad `default-src` (`https:`, `http:`, `*.host`) |
| CSP-022 | high | Overly broad `script-src` |
| CSP-023 | medium | Scheme-only sources (`https:`/`http:`) in other directives |
| CSP-030 | critical | `data:` allowed in effective `script-src` or `object-src` |
| CSP-040 | medium | Neither `object-src` nor `default-src` set |
| CSP-041 | medium | `base-uri` not restricted |
| CSP-042 | medium | `frame-ancestors` not set |
| CSP-043 | high | Neither `default-src` nor `script-src` defined |

`script-src` and `object-src` fall back to `default-src` when absent,
matching browser behaviour. The first occurrence of a duplicated directive
wins.

HTTP/status issues (non-2xx/3xx responses, fetch errors, redirect loops)
never contribute to this score: they are operational scan/report data,
surfaced separately by `cspeek report` (see "Status issues are not CSP
findings" above), not CSP configuration findings.

## Discovery bounds

- **Crawling** (`--crawl`) is breadth-first, same-origin by default,
  bounded by `--max-depth` and `--max-urls`, obeys the per-request
  timeout, and never revisits a URL. Cross-origin links (when
  `--allow-cross-origin` is not set), non-http(s) links, and links beyond
  the depth/URL bounds are recorded as skipped rather than silently
  dropped — see "Crawl scope visibility" above.
- **Subdomain discovery** (`--enumerate-subdomains`) resolves a fixed
  wordlist of ~20 common labels (`www`, `api`, `dev`, ...) via a single
  DNS lookup each. It performs no zone transfers, brute forcing, or
  active scanning.

## Package layout

CSPeek is a `src/`-layout Python package (`src/cspeek/`) with typed
Pydantic models for fetch results, findings, assessments, scan results,
and report summaries in `cspeek.models`. Installation is managed through
`pyproject.toml` (setuptools backend); `pip install -e .` gives an
editable install for development.

## Development

```sh
pip install -e .
python -m unittest discover -s tests -v   # all tests use mocked HTTP
python -m py_compile src/cspeek/*.py
```

Tests never require live internet access.

## Known limitations

- Only the first `Content-Security-Policy` header value per response is
  assessed; multiple CSP headers are not merged.
- `<meta http-equiv>` CSP declarations are not inspected (headers only).
- The rule set covers common hygiene issues, not full CSP3 semantics
  (e.g. `strict-dynamic` interactions are not modelled).
- Subdomain discovery is wordlist-based and will not find uncommon names.
- JavaScript-rendered links are not discovered by the crawler.

## Governance

This repository is governed by [cARL](https://github.com/goldjg/cARL);
see `.github/carl/` for durable artefacts, invariants, and the active PR
contract.
