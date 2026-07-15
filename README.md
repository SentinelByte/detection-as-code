# detection-as-code

[![CI](https://github.com/SentinelByte/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/SentinelByte/detection-as-code/actions/workflows/ci.yml)

A small, schema-first pipeline for authoring detection rules as code: write
one YAML rule, run deterministic checks on it, export it to Kibana or Sigma,
and optionally get an advisory LLM review before a human ships it.

This isn't a SIEM or a rule-management platform - it's the layer that sits
between "an analyst has an idea for a detection" and "a well-formed,
documented, ATT&CK-mapped rule exists in version control."

## Why this exists

Most detection-as-code write-ups stop at "put your rules in git." The parts
that actually matter for rule *quality* - is this query too broad, does it
have documented false positives, is it mapped to ATT&CK, would an analyst
have enough context to triage an alert at 3am - are usually left to review
comments. This repo makes those checks executable, and adds one narrow,
explicitly-bounded LLM check on top for the judgment calls a linter can't
make. See [docs/architecture.md](docs/architecture.md) for the full flow and
[docs/threat_model.md](docs/threat_model.md) for how the AI reviewer is kept
advisory-only in the code, not just in the docs.

## Quickstart

```bash
git clone https://github.com/SentinelByte/detection-as-code.git
cd detection-as-code
pip install -e ".[dev]"

# Deterministic checks - this is what a CI merge gate should run
detection-as-code lint examples/rules/windows_suspicious_scheduled_task.yaml

# Export to a Kibana detection rule or a Sigma rule
detection-as-code export examples/rules/windows_suspicious_scheduled_task.yaml --format kibana
detection-as-code export examples/rules/windows_suspicious_scheduled_task.yaml --format sigma

# Advisory-only LLM review (requires `pip install -e ".[ai]"` and ANTHROPIC_API_KEY)
detection-as-code review examples/rules/windows_suspicious_scheduled_task.yaml

# Validate against Elasticsearch and create the rule in Kibana
# (requires DAC_ELASTIC_URL, DAC_ELASTIC_API_KEY, DAC_KIBANA_URL,
#  DAC_KIBANA_USER, DAC_KIBANA_PASSWORD in the environment)
detection-as-code deploy examples/rules/windows_suspicious_scheduled_task.yaml
```

## Authoring a rule

```yaml
name: windows_suspicious_scheduled_task_creation
platform: windows
description: >
  Detects creation of a scheduled task via schtasks.exe with cmd.exe as the
  parent process - a common persistence/privilege-escalation technique.
severity: high
risk_score: 62
index_patterns:
  - "winlogbeat-*"
query: 'process.name:"schtasks.exe" and process.parent.name:"cmd.exe"'
tactics:
  - persistence
  - privilege_escalation
techniques:
  - T1053.005
false_positives:
  - Legitimate software installers registering scheduled maintenance tasks
```

## What's checked, and by what

| Check | Where | Blocking? |
|---|---|---|
| Schema validity, risk score range, known severity/tactic values | `models.py` | Yes (raises on load) |
| Unsafe rule name, empty/wildcard query, missing index patterns | `validators.py` | Yes |
| Missing ATT&CK mapping, no false positives documented, thin description | `validators.py` | Warning only |
| Coverage gaps, false-positive risk, missing triage context | `ai_review.py` (LLM) | Never - advisory only |
| Query actually parses against real Elasticsearch indices | `elastic_client.py` | Yes, at deploy time |

## Non-goals / known limits

- **Sigma export is intentionally partial.** It only converts simple
  `field:value AND field:value` Kuery. Anything with `OR` or grouping
  raises `UnsupportedQueryError` rather than risk a silently wrong
  translation - see [docs/architecture.md](docs/architecture.md).
- **This is not a secrets manager.** `EnvSecretProvider` is the only
  provider shipped; production use should implement `SecretProvider`
  against your actual vault.
- **The AI reviewer doesn't replace a human reviewer** - it's scoped to
  produce findings, not decisions.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
mypy src
pytest --cov=detection_as_code
bandit -r src
pip-audit
```

## License

GPLv3 - see [LICENSE](LICENSE).
