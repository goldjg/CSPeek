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
written `cspeek scan` output and aggregates it into a summary (totals,
CSP presence, risk-level distribution, and finding counts by rule).

Exit code is `0` on success, `1` if any target had a fetch error (`scan`
only), `2` for usage errors.

## Output formats

### Screen

A human-readable report per URL: final URL after redirects, status code,
raw CSP header(s), risk level/score, and each finding with remediation.

### JSON

An array of result objects:

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

## Discovery bounds

- **Crawling** (`--crawl`) is breadth-first, same-origin by default,
  bounded by `--max-depth` and `--max-urls`, obeys the per-request
  timeout, and never revisits a URL.
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
