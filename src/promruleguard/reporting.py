from __future__ import annotations

import json
from collections import Counter

from promruleguard.models import Finding

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}


def filter_findings(findings: list[Finding], min_severity: str) -> list[Finding]:
    minimum = SEVERITY_ORDER[min_severity]
    return [finding for finding in findings if SEVERITY_ORDER[finding.severity] >= minimum]


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    return bool(filter_findings(findings, fail_on))


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    counter = Counter(finding.severity for finding in findings)
    by_check = Counter(finding.check_id for finding in findings)
    hot_checks = ", ".join(f"{check_id}={count}" for check_id, count in by_check.most_common(5))
    lines = [
        f"Found {len(findings)} issue(s): "
        f"{counter.get('error', 0)} error(s), {counter.get('warning', 0)} warning(s), {counter.get('info', 0)} info finding(s).",
        f"Top finding types: {hot_checks}.",
    ]
    for finding in findings:
        location = f"{finding.path}:{finding.group_name}"
        if finding.alert_name:
            location = f"{location}:{finding.alert_name}"
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.check_id} @ {location}",
                finding.message,
                f"Why it matters: {finding.impact}" if finding.impact else None,
                f"Suggestion: {finding.suggestion}",
            ]
        )
    return "\n".join(line for line in lines if line is not None)


def render_json(findings: list[Finding]) -> str:
    payload = {
        "summary": {
            "total": len(findings),
            "errors": sum(1 for finding in findings if finding.severity == "error"),
            "warnings": sum(1 for finding in findings if finding.severity == "warning"),
            "info": sum(1 for finding in findings if finding.severity == "info"),
            "by_check": dict(sorted(Counter(finding.check_id for finding in findings).items())),
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)
