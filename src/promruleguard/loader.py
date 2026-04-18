from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from promruleguard.models import AlertRule, Finding, RuleLocation

YAML_SUFFIXES = {".yml", ".yaml"}


def collect_rule_files(paths: Iterable[str]) -> list[Path]:
    discovered: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            discovered.append(path)
            continue
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and candidate.suffix.lower() in YAML_SUFFIXES:
                    discovered.append(candidate)
            continue
        if path.suffix.lower() in YAML_SUFFIXES:
            discovered.append(path)
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in discovered:
        resolved = path.resolve(strict=False)
        if resolved not in seen:
            unique.append(path)
            seen.add(resolved)
    return unique


def load_alert_rules(paths: Iterable[str]) -> tuple[list[AlertRule], list[Finding]]:
    files = collect_rule_files(paths)
    rules: list[AlertRule] = []
    findings: list[Finding] = []
    if not files:
        findings.append(
            Finding(
                check_id="no-input-files",
                severity="error",
                message="No YAML rule files were found in the provided paths.",
                suggestion="Pass one or more .yml or .yaml files, or a directory containing rule files.",
                impact="The analyzer cannot validate anything until it receives at least one rule file.",
                path=Path("."),
                group_name="",
            )
        )
        return rules, findings

    for path in files:
        if not path.exists():
            findings.append(
                Finding(
                    check_id="missing-file",
                    severity="error",
                    message=f"Input path does not exist: {path}",
                    suggestion="Fix the path or remove it from the CLI invocation.",
                    impact="A missing file can hide alerting gaps if the expected rules are never analyzed.",
                    path=path,
                    group_name="",
                )
            )
            continue
        try:
            content = path.read_text(encoding="utf-8")
            documents = [doc for doc in yaml.safe_load_all(content) if doc is not None]
        except yaml.YAMLError as exc:
            findings.append(
                Finding(
                    check_id="yaml-parse-error",
                    severity="error",
                    message=f"Failed to parse YAML: {exc}",
                    suggestion="Fix the YAML syntax before running analysis again.",
                    impact="Prometheus cannot load a broken rule file, so the alerts inside it are effectively unvalidated.",
                    path=path,
                    group_name="",
                )
            )
            continue

        for document in documents:
            if not isinstance(document, dict):
                findings.append(
                    Finding(
                        check_id="unexpected-document",
                        severity="warning",
                        message="YAML document is not a mapping and was skipped.",
                        suggestion="Use the Prometheus rule file structure with a top-level groups list.",
                        impact="Skipped documents can conceal alerts that never receive quality checks.",
                        path=path,
                        group_name="",
                    )
                )
                continue
            groups = document.get("groups")
            if not isinstance(groups, list):
                findings.append(
                    Finding(
                        check_id="missing-groups",
                        severity="warning",
                        message="Rule file does not contain a top-level groups list.",
                        suggestion="Use the standard Prometheus rule file format with groups[].rules[].",
                        impact="Without groups, the file does not match the structure Prometheus expects for alert rules.",
                        path=path,
                        group_name="",
                    )
                )
                continue
            for group_index, group in enumerate(groups, start=1):
                if not isinstance(group, dict):
                    findings.append(
                        Finding(
                            check_id="malformed-group",
                            severity="warning",
                            message=f"Group entry #{group_index} is not a mapping and was skipped.",
                            suggestion="Each item in `groups` should be an object with `name` and `rules` fields.",
                            impact="Malformed groups are ignored, which can drop alerts from evaluation.",
                            path=path,
                            group_name="",
                        )
                    )
                    continue
                group_name = str(group.get("name", "<unnamed-group>"))
                raw_rules = group.get("rules", [])
                if not isinstance(raw_rules, list):
                    findings.append(
                        Finding(
                            check_id="malformed-rules",
                            severity="warning",
                            message=f"Group `{group_name}` has a `rules` field that is not a list.",
                            suggestion="Use a list under `groups[].rules` so each rule can be analyzed.",
                            impact="An invalid `rules` block prevents every alert in that group from being checked.",
                            path=path,
                            group_name=group_name,
                        )
                    )
                    continue
                for index, raw_rule in enumerate(raw_rules, start=1):
                    if not isinstance(raw_rule, dict):
                        findings.append(
                            Finding(
                                check_id="malformed-rule-entry",
                                severity="warning",
                                message=(
                                    f"Rule entry #{index} in group `{group_name}` is not a mapping and was skipped."
                                ),
                                suggestion="Each rule should be an object containing fields such as `alert`, `expr`, and `labels`.",
                                impact="Skipped rule entries can hide broken or missing alerts from the report.",
                                path=path,
                                group_name=group_name,
                            )
                        )
                        continue
                    if "alert" not in raw_rule:
                        continue
                    raw_name = raw_rule.get("alert")
                    name = str(raw_name).strip() if raw_name is not None else ""
                    if not name:
                        findings.append(
                            Finding(
                                check_id="blank-alert-name",
                                severity="error",
                                message="Alert rule defines an empty `alert` name.",
                                suggestion="Give the alert a stable, descriptive name so it can be routed and referenced reliably.",
                                impact="Blank alert names make notifications hard to identify and can break operational conventions.",
                                path=path,
                                group_name=group_name,
                            )
                        )
                        continue
                    expr = str(raw_rule.get("expr", "")).strip()
                    if not expr:
                        findings.append(
                            Finding(
                                check_id="missing-expression",
                                severity="error",
                                message=f"Alert `{name}` does not define a usable `expr` field.",
                                suggestion="Add a valid PromQL expression so the alert can be evaluated and analyzed.",
                                impact="An alert without an expression can never trigger, even if the incident condition happens.",
                                path=path,
                                group_name=group_name,
                                alert_name=name,
                            )
                        )
                        continue
                    labels = raw_rule.get("labels") if isinstance(raw_rule.get("labels"), dict) else {}
                    annotations = (
                        raw_rule.get("annotations")
                        if isinstance(raw_rule.get("annotations"), dict)
                        else {}
                    )
                    rules.append(
                        AlertRule(
                            name=name,
                            expr=expr,
                            duration=str(raw_rule["for"]).strip() if raw_rule.get("for") else None,
                            labels=labels,
                            annotations=annotations,
                            location=RuleLocation(path=path, group_name=group_name, rule_index=index),
                            raw=raw_rule,
                        )
                    )
    return rules, findings
