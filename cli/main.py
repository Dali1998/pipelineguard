"""
PipelineGuard CLI entry point.

Usage examples:
  pipelineguard scan .
  pipelineguard scan ./repo --format json --output report.json
  pipelineguard scan .gitlab-ci.yml --severity critical,high
  pipelineguard scan . --fail-on high
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from pipelineguard.core.scanner import Scanner
from pipelineguard.models.issue import Severity
from pipelineguard.reporting.console import print_report
from pipelineguard.reporting.json_report import print_json, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipelineguard",
        description="Security scanner for CI/CD pipeline definitions and Docker images.",
    )
    parser.add_argument("--version", action="version", version="pipelineguard 0.1.0")
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────
    scan = subparsers.add_parser("scan", help="Scan a file or directory for issues.")
    scan.add_argument(
        "path",
        type=Path,
        help="File or directory to scan.",
    )
    scan.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Output format (default: console).",
    )
    scan.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Write JSON report to this file (implies --format json).",
    )
    scan.add_argument(
        "--severity",
        default=None,
        metavar="LEVEL[,LEVEL...]",
        help="Comma-separated severities to report: critical,high,medium,low,info",
    )
    scan.add_argument(
        "--fail-on",
        default="critical",
        metavar="LEVEL",
        dest="fail_on",
        help="Exit code 1 if any issue is at or above this severity (default: critical).",
    )
    scan.add_argument(
        "--no-remediation",
        action="store_true",
        help="Suppress remediation hints from console output.",
    )

    # ── list-rules ────────────────────────────────────────────────────────
    list_rules = subparsers.add_parser("list-rules", help="List all available rules.")
    list_rules.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )

    return parser


def _parse_severities(raw: str | None) -> list[Severity] | None:
    if not raw:
        return None
    result = []
    for token in raw.split(","):
        token = token.strip().lower()
        try:
            result.append(Severity(token))
        except ValueError:
            print(f"[warn] Unknown severity '{token}' – ignoring.", file=sys.stderr)
    return result or None


def cmd_scan(args: argparse.Namespace) -> int:
    severity_filter = _parse_severities(args.severity)
    scanner = Scanner(severity_filter=severity_filter)
    result = scanner.scan(args.path)

    output_format = "json" if args.output else args.format

    if output_format == "json":
        if args.output:
            write_report(result, args.output)
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print_json(result)
    else:
        print_report(result, show_remediation=not args.no_remediation)

    # Determine exit code
    fail_severity = Severity(args.fail_on.lower()) if args.fail_on else Severity.CRITICAL
    _SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    fail_idx = _SEVERITY_ORDER.index(fail_severity)
    for issue in result.issues:
        if _SEVERITY_ORDER.index(issue.severity) <= fail_idx:
            return 1
    return 0


def cmd_list_rules(args: argparse.Namespace) -> int:
    import json as _json

    from pipelineguard.rules.registry import load_rules

    rules = load_rules()
    if args.format == "json":
        data = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": getattr(r, "severity", "n/a"),
                "category": getattr(r, "category", "n/a"),
            }
            for r in rules
        ]
        print(_json.dumps(data, indent=2, default=str))
    else:
        print(f"{'ID':<12} {'SEVERITY':<10} TITLE")
        print("-" * 60)
        for r in sorted(rules, key=lambda x: x.rule_id):
            sev = getattr(r, "severity", Severity.INFO)
            sev_val = sev.value if hasattr(sev, "value") else str(sev)
            print(f"{r.rule_id:<12} {sev_val:<10} {r.title}")
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    dispatch = {
        "scan": cmd_scan,
        "list-rules": cmd_list_rules,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
