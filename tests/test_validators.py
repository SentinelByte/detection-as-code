from detection_as_code.models import DetectionRule
from detection_as_code.validators import IssueLevel, has_blocking_issues, lint_rule

GOOD_RULE = DetectionRule.from_dict(
    {
        "name": "windows_suspicious_scheduled_task",
        "platform": "windows",
        "query": 'process.name:"schtasks.exe" and process.parent.name:"cmd.exe"',
        "index_patterns": ["winlogbeat-*"],
        "description": "Detects scheduled task creation from a suspicious parent process.",
        "severity": "high",
        "risk_score": 62,
        "tactics": ["persistence"],
        "techniques": ["T1053.005"],
        "false_positives": ["Legitimate installer scheduling maintenance tasks"],
    }
)


def test_clean_rule_has_no_blocking_issues():
    issues = lint_rule(GOOD_RULE)
    assert not has_blocking_issues(issues)


def test_wildcard_query_is_blocking():
    rule = DetectionRule.from_dict({**_as_dict(GOOD_RULE), "query": "*"})
    issues = lint_rule(rule)
    assert has_blocking_issues(issues)


def test_empty_index_patterns_is_blocking():
    rule = DetectionRule.from_dict({**_as_dict(GOOD_RULE), "index_patterns": []})
    issues = lint_rule(rule)
    assert has_blocking_issues(issues)


def test_unsafe_name_characters_is_blocking():
    rule = DetectionRule.from_dict({**_as_dict(GOOD_RULE), "name": "bad/name*here"})
    issues = lint_rule(rule)
    assert has_blocking_issues(issues)


def test_missing_tactics_is_a_warning_not_blocking():
    rule = DetectionRule.from_dict({**_as_dict(GOOD_RULE), "tactics": []})
    issues = lint_rule(rule)
    assert not has_blocking_issues(issues)
    assert any(i.level == IssueLevel.WARNING and "tactic" in i.message.lower() for i in issues)


def test_high_severity_without_technique_warns():
    rule = DetectionRule.from_dict({**_as_dict(GOOD_RULE), "techniques": []})
    issues = lint_rule(rule)
    assert any("technique" in i.message.lower() for i in issues)


def _as_dict(rule: DetectionRule) -> dict:
    return {
        "name": rule.name,
        "platform": rule.platform,
        "query": rule.query,
        "index_patterns": rule.index_patterns,
        "description": rule.description,
        "severity": rule.severity.value,
        "risk_score": rule.risk_score,
        "tactics": [t.name for t in rule.tactics],
        "techniques": rule.techniques,
        "false_positives": rule.false_positives,
    }
