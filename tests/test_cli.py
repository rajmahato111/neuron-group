from __future__ import annotations

import json
from pathlib import Path

from promruleguard.cli import main
from promruleguard.loader import load_alert_rules
from promruleguard.reporting import filter_findings, render_text


FIXTURE = Path(__file__).parent / "fixtures" / "sample_rules.yaml"


def test_text_report_has_summary_and_location() -> None:
    rules, load_findings = load_alert_rules([str(FIXTURE)])
    text = render_text(filter_findings(load_findings, "info"))
    assert text == "No findings."

    exit_code = main([str(FIXTURE), "--fail-on", "warning"])
    assert exit_code == 1


def test_json_output(capsys) -> None:
    exit_code = main([str(FIXTURE), "--format", "json", "--fail-on", "none"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["total"] > 0
    assert "by_check" in payload["summary"]
    assert any(finding["check_id"] == "missing-context" for finding in payload["findings"])
    assert any(finding["impact"] for finding in payload["findings"])
