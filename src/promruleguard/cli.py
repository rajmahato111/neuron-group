from __future__ import annotations

import argparse

from promruleguard.checks import run_checks
from promruleguard.loader import load_alert_rules
from promruleguard.reporting import filter_findings, render_json, render_text, should_fail


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promruleguard",
        description="Analyze Prometheus alerting rule files for noisy or brittle alerting patterns.",
    )
    parser.add_argument("paths", nargs="+", help="YAML rule files or directories to analyze.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for the findings report.",
    )
    parser.add_argument(
        "--min-severity",
        choices=("info", "warning", "error"),
        default="info",
        help="Only render findings at or above this severity.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "info", "warning", "error"),
        default="warning",
        help="Exit non-zero when findings exist at or above this severity.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    rules, load_findings = load_alert_rules(args.paths)
    findings = load_findings + run_checks(rules)
    visible = filter_findings(findings, args.min_severity)

    if args.format == "json":
        print(render_json(visible))
    else:
        print(render_text(visible))

    return 1 if should_fail(findings, args.fail_on) else 0
