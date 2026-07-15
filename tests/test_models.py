import pytest

from detection_as_code.models import DetectionRule, Severity, Tactic

VALID_RULE = {
    "name": "windows_suspicious_scheduled_task",
    "platform": "windows",
    "query": 'process.name:"schtasks.exe"',
    "index_patterns": ["winlogbeat-*"],
    "description": "Detects scheduled task creation from a suspicious path.",
    "severity": "high",
    "risk_score": 62,
    "tactics": ["persistence", "privilege_escalation"],
    "techniques": ["T1053.005"],
    "false_positives": ["Legitimate installer scheduling maintenance tasks"],
}


def test_from_dict_builds_a_valid_rule():
    rule = DetectionRule.from_dict(VALID_RULE)

    assert rule.severity == Severity.HIGH
    assert Tactic.PERSISTENCE in rule.tactics
    assert Tactic.PRIVILEGE_ESCALATION in rule.tactics
    assert rule.risk_score == 62


def test_risk_score_out_of_range_rejected():
    data = {**VALID_RULE, "risk_score": 150}
    with pytest.raises(ValueError, match="risk_score"):
        DetectionRule.from_dict(data)


def test_unknown_severity_rejected():
    data = {**VALID_RULE, "severity": "apocalyptic"}
    with pytest.raises(ValueError, match="severity"):
        DetectionRule.from_dict(data)


def test_unknown_tactic_rejected():
    data = {**VALID_RULE, "tactics": ["quantum_leap"]}
    with pytest.raises(ValueError, match="Unknown tactic"):
        DetectionRule.from_dict(data)


def test_empty_name_rejected():
    data = {**VALID_RULE, "name": "   "}
    with pytest.raises(ValueError, match="name"):
        DetectionRule.from_dict(data)
