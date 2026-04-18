# PromRuleGuard

`promruleguard` is a small CLI that analyzes Prometheus alerting rule files and flags alerting patterns that are noisy, brittle, or hard to action during an incident.

## What it checks

- Alerts with no `for` window or a very short hold time.
- Missing responder context such as severity, ownership, summary, description, and runbook URL.
- Blank or duplicate alert names that make routing and triage harder.
- Non-standard severity labels that are difficult to route consistently.
- Broad selectors that are likely to scan too much of the fleet.
- Narrow selectors that pin alerts to volatile labels such as `pod` or `instance`.
- Duplicate expressions that create redundant notifications.
- Overlapping threshold tiers that may page twice unless inhibition or escalation rules exist.

## Usage

```bash
PYTHONPATH=src python3 -m promruleguard path/to/rules.yaml
PYTHONPATH=src python3 -m promruleguard path/to/rules/ --format json --fail-on info
```

## Output

- `text`: human-readable report for local review.
- `json`: machine-readable findings payload with a summary block and counts by finding type.

Each finding includes a short "Why it matters" explanation so the output is easier to use during reviews and interviews.

The CLI exits non-zero when findings meet the selected `--fail-on` threshold. The default is `warning`, which makes it useful in CI without failing on informational findings.

## Key decisions

- I chose Python because the local environment already had `PyYAML` and `pytest`, which let me focus on the analyzer instead of setup.
- The checks are intentionally heuristic rather than a full PromQL parser. That keeps the implementation small and explainable in a follow-up interview.
- Missing metadata is reported as one consolidated finding per alert to keep the output readable.
- The report now includes impact text and per-check counts so the findings are easier to prioritize quickly.
- Overlapping alert relationships are detected by comparing threshold expressions on the same normalized signal. This catches the common warning/critical ladder without requiring Alertmanager config.

## Tradeoffs

- The selector analysis is conservative and regex-based, so it can produce false positives on more advanced PromQL patterns.
- Relationship checks infer overlap from the rule expressions alone. They cannot see existing Alertmanager inhibition rules, so they report a suggestion instead of claiming the configuration is wrong.
- The tool ignores recording rules and focuses on `alert` entries because that is the assignment's operational focus.

## Testing

```bash
PYTHONPATH=src python3 -m pytest
```
