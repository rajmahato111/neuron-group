from __future__ import annotations

import re
from collections import defaultdict
from itertools import combinations

from promruleguard.models import AlertRule, Finding

SCOPING_LABELS = {"job", "service", "app", "namespace", "cluster", "team"}
VOLATILE_LABELS = {"instance", "pod", "pod_name", "container", "endpoint", "controller_revision_hash"}
FUNCTION_NAMES = {
    "sum",
    "min",
    "max",
    "avg",
    "count",
    "rate",
    "irate",
    "increase",
    "absent",
    "histogram_quantile",
    "round",
    "floor",
    "ceil",
    "label_replace",
    "label_join",
    "vector",
    "scalar",
    "clamp_max",
    "clamp_min",
    "topk",
    "bottomk",
    "sort",
    "sort_desc",
    "by",
    "without",
    "and",
    "or",
    "unless",
    "on",
    "ignoring",
    "group_left",
    "group_right",
    "bool",
}
PROMQL_KEYWORDS = FUNCTION_NAMES | {"true", "false", "offset"}
SEVERITY_ORDER = {"critical": 4, "page": 3, "warning": 2, "ticket": 1, "info": 0}
VALID_ALERT_SEVERITIES = frozenset(SEVERITY_ORDER)


def run_checks(rules: list[AlertRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(check_transient_condition(rule))
        findings.extend(check_missing_context(rule))
        findings.extend(check_rule_metadata(rule))
        findings.extend(check_selector_scope(rule))
    findings.extend(check_duplicate_alert_names(rules))
    findings.extend(check_duplicate_expressions(rules))
    findings.extend(check_overlapping_thresholds(rules))
    return sorted(findings, key=lambda finding: finding.sort_key())


def check_transient_condition(rule: AlertRule) -> list[Finding]:
    if not rule.duration:
        return [
            finding_for_rule(
                rule,
                check_id="transient-condition",
                severity="warning",
                message="Alert has no `for` clause, so it can fire on short-lived spikes or scrape glitches.",
                suggestion="Add a `for` duration so the condition must persist before paging anyone.",
                impact="Short spikes, scrape hiccups, or rollout churn can page responders even when the system self-recovers.",
            )
        ]

    seconds = parse_prometheus_duration(rule.duration)
    if seconds is None:
        return [
            finding_for_rule(
                rule,
                check_id="invalid-duration",
                severity="warning",
                message=f"Alert uses an unrecognized duration: {rule.duration}",
                suggestion="Use a Prometheus duration such as `5m` or `1h` for the `for` field.",
                impact="An invalid duration is easy to misread during review and may not behave the way the author intended.",
            )
        ]
    if seconds < 300:
        return [
            finding_for_rule(
                rule,
                check_id="transient-condition",
                severity="warning",
                message=f"Alert uses a short `for` window ({rule.duration}), which may still page on transient conditions.",
                suggestion="Consider a longer hold time such as `5m` unless the alert truly needs second-level sensitivity.",
                impact="Very short hold times often create noisy pages during brief spikes and deployment turbulence.",
            )
        ]
    return []


def check_missing_context(rule: AlertRule) -> list[Finding]:
    missing: list[str] = []
    if not str(rule.labels.get("severity", "")).strip():
        missing.append("labels.severity")
    if not any(str(rule.labels.get(key, "")).strip() for key in ("team", "service", "owner")):
        missing.append("owner label (team/service/owner)")
    if not str(rule.annotations.get("summary", "")).strip():
        missing.append("annotations.summary")
    if not str(rule.annotations.get("description", "")).strip():
        missing.append("annotations.description")
    if not str(rule.annotations.get("runbook_url", "")).strip():
        missing.append("annotations.runbook_url")
    if not missing:
        return []
    return [
        finding_for_rule(
            rule,
            check_id="missing-context",
            severity="warning",
            message=f"Alert is missing responder context: {', '.join(missing)}.",
            suggestion="Include severity, ownership, concise annotations, and a runbook so the next engineer knows how to respond.",
            impact="Incomplete alert metadata slows triage and increases time-to-mitigation during an incident.",
            details={"missing_fields": missing},
        )
    ]


def check_rule_metadata(rule: AlertRule) -> list[Finding]:
    severity = str(rule.labels.get("severity", "")).strip().lower()
    if not severity:
        return []
    if severity in VALID_ALERT_SEVERITIES:
        return []
    return [
        finding_for_rule(
            rule,
            check_id="invalid-severity",
            severity="warning",
            message=(
                f"Alert uses a non-standard severity label value: {rule.labels.get('severity')!r}."
            ),
            suggestion=(
                "Use a recognized severity such as `critical`, `warning`, `info`, `page`, or `ticket`, "
                "or document the custom taxonomy elsewhere."
            ),
            impact="Non-standard severities make routing, dashboards, and incident policies harder to reason about consistently.",
            details={"severity_value": rule.labels.get("severity")},
        )
    ]


def check_selector_scope(rule: AlertRule) -> list[Finding]:
    findings: list[Finding] = []
    metric_references = iter_metric_references(rule.expr)
    selectors = [matcher for _, matchers in metric_references for matcher in matchers]
    has_unscoped_metric = any(not matchers for _, matchers in metric_references)
    has_poorly_scoped_selector = any(
        matchers and not any(label in SCOPING_LABELS for label, _, _ in matchers)
        for _, matchers in metric_references
    )

    if has_unscoped_metric:
        findings.append(
            finding_for_rule(
                rule,
                check_id="broad-selector",
                severity="warning",
                message=(
                    "Expression includes one or more metric references with no label matchers, "
                    "so part of the alert can evaluate across every matching time series in the environment."
                ),
                suggestion="Scope each metric with labels such as job, service, cluster, or namespace when possible.",
                impact="Unscoped metrics can cause fleet-wide noise and make it harder to tell which service actually needs attention.",
            )
        )
    elif has_poorly_scoped_selector:
        findings.append(
            finding_for_rule(
                rule,
                check_id="broad-selector",
                severity="info",
                message=(
                    "Expression has label matchers, but at least one metric is not clearly scoped to a service, "
                    "job, cluster, or namespace."
                ),
                suggestion="Add a stable scoping label if the alert is intended for a subset of the fleet.",
                impact="Weak scoping makes alerts harder to route and increases the chance of paging the wrong team.",
            )
        )

    volatile_labels = sorted(
        {
            label
            for label, operator, _ in selectors
            if label in VOLATILE_LABELS and operator in {"=", "=~"}
        }
    )
    if volatile_labels:
        findings.append(
            finding_for_rule(
                rule,
                check_id="narrow-selector",
                severity="warning",
                message=f"Expression hard-codes volatile labels: {', '.join(volatile_labels)}.",
                suggestion="Prefer stable service-level labels so the alert survives reschedules and target churn.",
                impact="Alerts tied to volatile labels can disappear or churn as workloads reschedule, masking real problems.",
                details={"volatile_labels": volatile_labels},
            )
        )
    return findings


def check_duplicate_alert_names(rules: list[AlertRule]) -> list[Finding]:
    by_name: dict[tuple[str, str, str], list[AlertRule]] = defaultdict(list)
    for rule in rules:
        by_name[(str(rule.location.path), rule.location.group_name, rule.name)].append(rule)

    findings: list[Finding] = []
    for (_, _, name), related_rules in by_name.items():
        if len(related_rules) < 2:
            continue
        for rule in related_rules:
            findings.append(
                finding_for_rule(
                    rule,
                    check_id="duplicate-alert-name",
                    severity="warning",
                    message=(
                        f"Alert name `{name}` appears multiple times in the same group."
                    ),
                    suggestion="Rename duplicate alerts so each rule has a unique operational identity.",
                    impact="Duplicate names make Alertmanager routing, dashboards, and incident discussion more confusing.",
                    details={"occurrences": len(related_rules)},
                )
            )
    return findings


def check_duplicate_expressions(rules: list[AlertRule]) -> list[Finding]:
    by_expr: dict[str, list[AlertRule]] = defaultdict(list)
    for rule in rules:
        by_expr[normalize_expr(rule.expr)].append(rule)

    findings: list[Finding] = []
    for normalized_expr, related_rules in by_expr.items():
        if len(related_rules) < 2 or not normalized_expr:
            continue
        names = [rule.name for rule in related_rules]
        for rule in related_rules:
            findings.append(
                finding_for_rule(
                    rule,
                    check_id="duplicate-expression",
                    severity="warning",
                    message=f"Alert shares the same expression with other alerts: {', '.join(name for name in names if name != rule.name)}.",
                    suggestion="Consolidate duplicate alerts or document why separate alerts are still useful.",
                    impact="Multiple alerts on the exact same signal often create redundant pages without adding new information.",
                    details={"related_alerts": [name for name in names if name != rule.name]},
                )
            )
    return findings


def check_overlapping_thresholds(rules: list[AlertRule]) -> list[Finding]:
    threshold_groups: dict[tuple[str, str], list[tuple[AlertRule, float]]] = defaultdict(list)
    for rule in rules:
        parsed = parse_threshold_expression(rule.expr)
        if parsed is None:
            continue
        lhs, direction, threshold = parsed
        threshold_groups[(lhs, direction)].append((rule, threshold))

    findings: list[Finding] = []
    for (_, direction), group in threshold_groups.items():
        if len(group) < 2:
            continue
        ranked = sorted(group, key=lambda item: item[1], reverse=(direction == "gt"))
        for (rule_a, threshold_a), (rule_b, threshold_b) in combinations(ranked, 2):
            if threshold_a == threshold_b:
                continue
            if direction == "gt":
                stricter_rule, looser_rule = (
                    (rule_a, rule_b) if threshold_a > threshold_b else (rule_b, rule_a)
                )
            else:
                stricter_rule, looser_rule = (
                    (rule_a, rule_b) if threshold_a < threshold_b else (rule_b, rule_a)
                )
            severity_a = severity_rank(stricter_rule)
            severity_b = severity_rank(looser_rule)
            if severity_a < severity_b:
                continue
            findings.append(
                finding_for_rule(
                    stricter_rule,
                    check_id="overlapping-thresholds",
                    severity="info",
                    message=(
                        f"{stricter_rule.name} and {looser_rule.name} look like threshold tiers on the same signal and "
                        "can fire together unless relationships are handled elsewhere."
                    ),
                    suggestion="Use inhibition, mutually exclusive logic, or documented escalation so only the intended alert notifies.",
                    impact="Stacked threshold alerts can double-page responders and obscure which condition actually needs action.",
                    details={
                        "related_alert": looser_rule.name,
                        "stricter_threshold": threshold_for_rule(stricter_rule),
                        "looser_threshold": threshold_for_rule(looser_rule),
                    },
                )
            )
    return findings


def finding_for_rule(
    rule: AlertRule,
    *,
    check_id: str,
    severity: str,
    message: str,
    suggestion: str,
    impact: str,
    details: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,
        message=message,
        suggestion=suggestion,
        impact=impact,
        path=rule.location.path,
        group_name=rule.location.group_name,
        alert_name=rule.name,
        details=details or {},
    )


def parse_prometheus_duration(value: str) -> float | None:
    token_pattern = re.compile(r"(\d+)(ms|y|w|d|h|m|s)")
    units = {
        "y": 365 * 24 * 60 * 60,
        "w": 7 * 24 * 60 * 60,
        "d": 24 * 60 * 60,
        "h": 60 * 60,
        "m": 60,
        "s": 1,
        "ms": 0.001,
    }
    position = 0
    total = 0.0
    for match in token_pattern.finditer(value):
        if match.start() != position:
            return None
        amount, unit = match.groups()
        total += int(amount) * units[unit]
        position = match.end()
    if position != len(value):
        return None
    return total


def iter_label_matchers(expr: str) -> list[tuple[str, str, str]]:
    return [matcher for _, matchers in iter_metric_references(expr) for matcher in matchers]


def contains_metric_reference(expr: str) -> bool:
    return bool(iter_metric_references(expr))


def iter_metric_references(expr: str) -> list[tuple[str, list[tuple[str, str, str]]]]:
    references: list[tuple[str, list[tuple[str, str, str]]]] = []
    selector_pattern = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{([^}]*)\}")
    masked = expr

    for match in selector_pattern.finditer(expr):
        metric, body = match.groups()
        references.append((metric, parse_label_matchers(body)))
        masked = masked[: match.start()] + (" " * (match.end() - match.start())) + masked[match.end() :]

    masked = re.sub(r'"(?:[^"\\]|\\.)*"', lambda match: " " * len(match.group(0)), masked)
    masked = re.sub(r"\[[^\]]*\]", lambda match: " " * len(match.group(0)), masked)
    masked = re.sub(
        r"\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
        lambda match: " " * len(match.group(0)),
        masked,
    )

    for match in re.finditer(r"\b([a-zA-Z_:][a-zA-Z0-9_:]*)\b", masked):
        token = match.group(1)
        if token in PROMQL_KEYWORDS or token.isupper():
            continue
        next_char = next_non_space_char(masked, match.end())
        if next_char == "(":
            continue
        references.append((token, []))

    return references


def parse_label_matchers(body: str) -> list[tuple[str, str, str]]:
    return re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(!=|!~|=|=~)\s*"([^"]*)"', body)


def next_non_space_char(value: str, start: int) -> str | None:
    for char in value[start:]:
        if not char.isspace():
            return char
    return None


def normalize_expr(expr: str) -> str:
    expr = re.sub(r"\s+", " ", expr.strip())
    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1].strip()
    return expr


def parse_threshold_expression(expr: str) -> tuple[str, str, float] | None:
    cleaned = normalize_expr(expr)
    match = re.fullmatch(r"(.+?)\s*(>=|>|<=|<)\s*(-?\d+(?:\.\d+)?)", cleaned)
    if match:
        lhs, operator, rhs = match.groups()
        return normalize_expr(lhs), "gt" if operator in {">", ">="} else "lt", float(rhs)
    reverse = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(>=|>|<=|<)\s*(.+)", cleaned)
    if reverse:
        lhs_value, operator, rhs = reverse.groups()
        inverted = {">": "lt", ">=": "lt", "<": "gt", "<=": "gt"}[operator]
        return normalize_expr(rhs), inverted, float(lhs_value)
    return None


def severity_rank(rule: AlertRule) -> int:
    return SEVERITY_ORDER.get(str(rule.labels.get("severity", "")).lower(), -1)


def threshold_for_rule(rule: AlertRule) -> float | None:
    parsed = parse_threshold_expression(rule.expr)
    return parsed[2] if parsed else None
