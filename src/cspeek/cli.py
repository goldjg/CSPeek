"""Command-line interface for CSPeek.

Defensive CSP configuration auditing for authorised targets only.
"""

from __future__ import annotations

import argparse
import sys

from .discovery import DEFAULT_MAX_DEPTH, DEFAULT_MAX_URLS
from .fetch import DEFAULT_TIMEOUT
from .inputs import InputError, load_targets
from .output import render_screen, write_csv, write_json, write_sqlite
from .report import (
    ReportError,
    load_json_report_full,
    load_sqlite_report_full,
    render_report_screen,
    summarise,
    write_report_json,
)
from .scanner import scan_targets_with_metadata

EPILOG = (
    "CSPeek is a defensive configuration-auditing tool. Only scan URLs "
    "you own, operate, or have explicit permission to assess."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cspeek",
        description="Audit Content-Security-Policy response headers.",
        epilog=EPILOG,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan", help="Scan one URL or a file of URLs.", epilog=EPILOG
    )
    scan.add_argument("url", nargs="?", help="Target URL (scheme optional).")
    scan.add_argument(
        "--input", help="File containing URLs, one per line."
    )
    scan.add_argument("--json", metavar="PATH", help="Write JSON results.")
    scan.add_argument("--csv", metavar="PATH", help="Write CSV results.")
    scan.add_argument(
        "--sqlite", metavar="PATH", help="Write results to a SQLite database."
    )
    scan.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds (default {DEFAULT_TIMEOUT}).",
    )
    scan.add_argument(
        "--crawl", action="store_true",
        help="Also scan same-origin links found on target pages (bounded).",
    )
    scan.add_argument(
        "--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
        help=f"Maximum crawl depth (default {DEFAULT_MAX_DEPTH}).",
    )
    scan.add_argument(
        "--max-urls", type=int, default=DEFAULT_MAX_URLS,
        help=f"Maximum URLs to crawl per target (default {DEFAULT_MAX_URLS}).",
    )
    scan.add_argument(
        "--allow-cross-origin", action="store_true",
        help="Allow the crawler to follow cross-origin links "
             "(same-origin only by default).",
    )
    scan.add_argument(
        "--enumerate-subdomains", action="store_true",
        help="Conservatively check a fixed wordlist of common subdomains "
             "via DNS and include those that resolve.",
    )
    scan.add_argument(
        "--quiet", action="store_true",
        help="Suppress the human-readable report on stdout.",
    )

    report = sub.add_parser(
        "report",
        help="Summarise a prior JSON or SQLite scan output without rescanning.",
        epilog=EPILOG,
    )
    source = report.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--json", metavar="PATH", help="Read prior JSON results."
    )
    source.add_argument(
        "--sqlite", metavar="PATH", help="Read prior SQLite results."
    )
    report.add_argument(
        "--output", metavar="PATH",
        help="Write the summary as JSON to PATH.",
    )
    report.add_argument(
        "--quiet", action="store_true",
        help="Suppress the human-readable summary on stdout.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            targets = load_targets(url=args.url, input_file=args.input)
        except InputError as exc:
            parser.error(str(exc))
            return 2  # unreachable; parser.error exits

        results, metadata = scan_targets_with_metadata(
            targets,
            timeout=args.timeout,
            do_crawl=args.crawl,
            max_depth=args.max_depth,
            max_urls=args.max_urls,
            same_origin_only=not args.allow_cross_origin,
            do_subdomains=args.enumerate_subdomains,
        )

        if args.json:
            write_json(results, args.json, metadata=metadata)
        if args.csv:
            write_csv(results, args.csv)
        if args.sqlite:
            write_sqlite(results, args.sqlite, metadata=metadata)
        if not args.quiet:
            print(render_screen(results))

        had_errors = any(r.fetch.error for r in results)
        return 1 if had_errors else 0

    if args.command == "report":
        try:
            if args.json:
                results, metadata = load_json_report_full(args.json)
            else:
                results, metadata = load_sqlite_report_full(args.sqlite)
        except ReportError as exc:
            parser.error(str(exc))
            return 2  # unreachable; parser.error exits

        report = summarise(results, metadata=metadata)
        if args.output:
            write_report_json(report, args.output)
        if not args.quiet:
            print(render_report_screen(report))
        return 0

    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
