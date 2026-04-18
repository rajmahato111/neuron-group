from __future__ import annotations

from pathlib import Path

from promruleguard.checks import parse_threshold_expression, run_checks
from promruleguard.loader import load_alert_rules


FIXTURE = Path(__file__).parent / "fixtures" / "sample_rules.yaml"


def test_loader_finds_alert_rules() -> None:
    rules, findings = load_alert_rules([str(FIXTURE)])
    assert not findings
    assert len(rules) == 5
    assert {rule.name for rule in rules} >= {"InstanceDown", "HighErrorRateCritical"}


def test_checks_cover_assignment_categories() -> None:
    rules, findings = load_alert_rules([str(FIXTURE)])
    assert not findings

    check_ids = {finding.check_id for finding in run_checks(rules)}
    assert "transient-condition" in check_ids
    assert "missing-context" in check_ids
    assert "broad-selector" in check_ids
    assert "narrow-selector" in check_ids
    assert "duplicate-expression" in check_ids
    assert "overlapping-thresholds" in check_ids


def test_rule_metadata_checks_cover_invalid_severity_and_duplicate_names(tmp_path: Path) -> None:
    fixture = tmp_path / "metadata.yaml"
    fixture.write_text(
        """groups:
  - name: prod
    rules:
      - alert: ApiLatencyHigh
        expr: up{job="api"} == 0
        for: 10m
        labels:
          severity: sev1
          service: api
          team: platform
        annotations:
          summary: first
          description: first
          runbook_url: https://runbooks.example.com/api
      - alert: ApiLatencyHigh
        expr: up{job="api"} == 1
        for: 10m
        labels:
          severity: warning
          service: api
          team: platform
        annotations:
          summary: second
          description: second
          runbook_url: https://runbooks.example.com/api
""",
        encoding="utf-8",
    )

    rules, findings = load_alert_rules([str(fixture)])
    assert not findings

    check_ids = [finding.check_id for finding in run_checks(rules)]
    assert "invalid-severity" in check_ids
    assert "duplicate-alert-name" in check_ids


def test_reversed_threshold_expression_is_parsed() -> None:
    parsed = parse_threshold_expression(
        '0.9 < histogram_quantile(0.99, sum by (le, job) (rate(http_request_duration_seconds_bucket{job="api"}[5m])))'
    )
    assert parsed == (
        'histogram_quantile(0.99, sum by (le, job) (rate(http_request_duration_seconds_bucket{job="api"}[5m])))',
        "gt",
        0.9,
    )
