# QA Test Cases

## End-to-End CLI Coverage

| ID | Scenario | Input shape | Expected result |
| --- | --- | --- | --- |
| E2E-01 | Clean alert file | One valid rule file with complete metadata, scoped selectors, and `for: 10m` | Exit `0`, text output `No findings.` |
| E2E-02 | Invalid YAML | Broken YAML syntax | JSON output contains `yaml-parse-error`; exit `1` when `--fail-on error` |
| E2E-03 | Directory scan | Directory containing multiple valid `.yaml` and `.yml` files | All files are analyzed; clean directory returns zero findings |
| E2E-04 | Missing expression | Alert rule missing `expr` | `missing-expression` error is reported |
| E2E-05 | Empty expression | Alert rule with blank `expr` | `missing-expression` error is reported |
| E2E-06 | Malformed group entry | `groups` contains a non-object item | `malformed-group` warning is reported |
| E2E-07 | Malformed rules field | `groups[].rules` is not a list | `malformed-rules` warning is reported |
| E2E-08 | Malformed rule entry | `groups[].rules` contains a non-object item | `malformed-rule-entry` warning is reported |
| E2E-09 | Warning-only findings with strict failure gate | Findings are warnings only and CLI uses `--fail-on error` | Findings render, exit code stays `0` |
| E2E-10 | Error failure gate | At least one error finding and CLI uses `--fail-on error` | Exit code is `1` |
| E2E-11 | Mixed-scope expression | One metric in a ratio is unscoped while another is scoped | `broad-selector` warning is still reported |
| E2E-12 | Reversed threshold relationship | Warning and critical thresholds are written on opposite sides of the operator | `overlapping-thresholds` is reported |
| E2E-13 | Blank alert name | Alert has `alert: ""` | `blank-alert-name` error is reported |
| E2E-14 | Actionable text output | Text mode includes impact guidance | Each finding includes a `Why it matters` line |

## Rule Heuristic Coverage

| ID | Scenario | Expected finding |
| --- | --- | --- |
| RULE-01 | Alert missing `for` | `transient-condition` |
| RULE-02 | Alert with short `for` such as `1m` or `2m` | `transient-condition` |
| RULE-03 | Alert with invalid duration string | `invalid-duration` |
| RULE-04 | Missing severity, owner, summary, description, or runbook | `missing-context` |
| RULE-05 | Expression with no label matchers | `broad-selector` |
| RULE-06 | Expression scoped only by volatile labels like `pod` | `narrow-selector` |
| RULE-07 | Two alerts share the same normalized expression | `duplicate-expression` |
| RULE-08 | Warning and critical tiers share the same left-hand signal with different thresholds | `overlapping-thresholds` |
| RULE-09 | A threshold is written in reverse form such as `0.9 < metric` | `overlapping-thresholds` still works |
| RULE-10 | A multi-metric expression has one scoped selector and one unscoped metric | `broad-selector` still fires |
| RULE-11 | Severity label uses a non-standard value such as `sev1` | `invalid-severity` |
| RULE-12 | Two alerts in the same group share the same `alert` name | `duplicate-alert-name` |

## Manual QA Notes

- Verify text output remains readable with mixed severities and multiple files.
- Verify JSON output stays stable enough for CI parsing.
- Verify malformed input never silently passes as a healthy configuration.
