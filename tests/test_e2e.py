from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "promruleguard", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_clean_file_end_to_end(tmp_path: Path) -> None:
    rule_file = tmp_path / "clean.yaml"
    rule_file.write_text(
        """groups:
  - name: prod
    rules:
      - alert: ApiLatencyHigh
        expr: histogram_quantile(0.99, sum by (le, job, namespace) (rate(http_request_duration_seconds_bucket{job="api",namespace="prod"}[5m]))) > 1
        for: 10m
        labels:
          severity: warning
          service: api
          team: platform
        annotations:
          summary: API p99 latency is elevated
          description: p99 latency is above 1s in prod
          runbook_url: https://runbooks.example.com/api-latency
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--fail-on", "none")

    assert result.returncode == 0
    assert result.stdout.strip() == "No findings."
    assert result.stderr == ""


def test_invalid_yaml_returns_error_finding(tmp_path: Path) -> None:
    rule_file = tmp_path / "invalid.yaml"
    rule_file.write_text(
        """groups:
  - name: broken
    rules:
      - alert: Broken
        expr: up == 0
        labels: [oops
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--format", "json", "--fail-on", "error")
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert payload["summary"]["errors"] == 1
    assert payload["findings"][0]["check_id"] == "yaml-parse-error"


def test_directory_scan_combines_multiple_files(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "one.yaml").write_text(
        """groups:
  - name: one
    rules:
      - alert: OneDown
        expr: up{job="one"} == 0
        for: 5m
        labels: {severity: critical, service: one, team: ops}
        annotations: {summary: s, description: d, runbook_url: r}
""",
        encoding="utf-8",
    )
    (nested / "two.yml").write_text(
        """groups:
  - name: two
    rules:
      - alert: TwoDown
        expr: up{job="two"} == 0
        for: 5m
        labels: {severity: critical, service: two, team: ops}
        annotations: {summary: s, description: d, runbook_url: r}
""",
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--format", "json", "--fail-on", "none")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["summary"]["total"] == 0


@pytest.mark.parametrize(
    ("filename", "expr_line"),
    [
        ("missing_expr.yaml", ""),
        ("empty_expr.yaml", '        expr: ""\n'),
    ],
)
def test_missing_expression_is_reported_as_error(
    tmp_path: Path, filename: str, expr_line: str
) -> None:
    rule_file = tmp_path / filename
    rule_file.write_text(
        f"""groups:
  - name: prod
    rules:
      - alert: MissingExpr
{expr_line}        for: 5m
        labels:
          severity: warning
          service: api
          team: platform
        annotations:
          summary: Missing expression
          description: Alert forgot expr
          runbook_url: https://runbooks.example.com/x
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--format", "json", "--fail-on", "none")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["summary"]["errors"] == 1
    assert payload["findings"][0]["check_id"] == "missing-expression"


def test_malformed_group_and_rules_shapes_are_reported(tmp_path: Path) -> None:
    rule_file = tmp_path / "malformed.yaml"
    rule_file.write_text(
        """groups:
  - not-a-map
  - name: prod
    rules: nope
  - name: okay
    rules:
      - plain-string
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--format", "json", "--fail-on", "none")
    payload = json.loads(result.stdout)
    check_ids = {finding["check_id"] for finding in payload["findings"]}

    assert result.returncode == 0
    assert {"malformed-group", "malformed-rules", "malformed-rule-entry"} <= check_ids


def test_fail_on_threshold_respects_severity_level(tmp_path: Path) -> None:
    rule_file = tmp_path / "warning_only.yaml"
    rule_file.write_text(
        """groups:
  - name: prod
    rules:
      - alert: MissingFor
        expr: up{job="api"} == 0
        labels:
          severity: warning
          service: api
          team: platform
        annotations:
          summary: Missing for
          description: Missing hold duration
          runbook_url: https://runbooks.example.com/x
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--fail-on", "error")

    assert result.returncode == 0
    assert "[WARNING] transient-condition" in result.stdout
    assert "Why it matters:" in result.stdout


def test_mixed_scoped_expression_still_reports_broad_selector(tmp_path: Path) -> None:
    rule_file = tmp_path / "mixed_scope.yaml"
    rule_file.write_text(
        """groups:
  - name: mixed
    rules:
      - alert: MixedScopeRatio
        expr: sum(rate(errors_total[5m])) / sum(rate(requests_total{job="api"}[5m])) > 0.1
        for: 10m
        labels:
          severity: warning
          service: api
          team: platform
        annotations:
          summary: Mixed scope ratio
          description: Numerator is unscoped, denominator is scoped
          runbook_url: https://runbooks.example.com/api
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--format", "json", "--fail-on", "none")
    payload = json.loads(result.stdout)
    check_ids = {finding["check_id"] for finding in payload["findings"]}

    assert result.returncode == 0
    assert "broad-selector" in check_ids


def test_reversed_and_forward_thresholds_are_linked(tmp_path: Path) -> None:
    rule_file = tmp_path / "relationship.yaml"
    rule_file.write_text(
        """groups:
  - name: rel
    rules:
      - alert: ErrorRatioCriticalForward
        expr: (sum(rate(errors_total{job="api"}[5m])) / sum(rate(requests_total{job="api"}[5m]))) > 0.10
        for: 10m
        labels:
          severity: critical
          service: api
          team: platform
        annotations:
          summary: critical
          description: critical
          runbook_url: https://runbooks.example.com/api
      - alert: ErrorRatioWarningReversed
        expr: 0.05 < (sum(rate(errors_total{job="api"}[5m])) / sum(rate(requests_total{job="api"}[5m])))
        for: 10m
        labels:
          severity: warning
          service: api
          team: platform
        annotations:
          summary: warning
          description: warning
          runbook_url: https://runbooks.example.com/api
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--format", "json", "--fail-on", "none")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert any(finding["check_id"] == "overlapping-thresholds" for finding in payload["findings"])


def test_blank_alert_name_is_reported_as_error(tmp_path: Path) -> None:
    rule_file = tmp_path / "blank_name.yaml"
    rule_file.write_text(
        """groups:
  - name: prod
    rules:
      - alert: ""
        expr: up{job="api"} == 0
        for: 10m
        labels:
          severity: critical
          service: api
          team: platform
        annotations:
          summary: blank
          description: blank
          runbook_url: https://runbooks.example.com/api
""",
        encoding="utf-8",
    )

    result = run_cli(str(rule_file), "--format", "json", "--fail-on", "none")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["summary"]["errors"] == 1
    assert payload["findings"][0]["check_id"] == "blank-alert-name"
