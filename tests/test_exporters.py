import json

import pytest
import yaml

from detection_as_code.exporters import UnsupportedQueryError, to_kibana_json, to_sigma
from detection_as_code.models import DetectionRule

SIMPLE_RULE = DetectionRule.from_dict(
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


def test_to_kibana_json_round_trips():
    payload = json.loads(to_kibana_json(SIMPLE_RULE))

    assert payload["name"] == SIMPLE_RULE.name
    assert payload["risk_score"] == 62
    assert payload["index"] == ["winlogbeat-*"]
    assert "tactic:persistence" in payload["tags"]


def test_to_sigma_converts_simple_conjunction():
    sigma_yaml = to_sigma(SIMPLE_RULE)
    parsed = yaml.safe_load(sigma_yaml)

    assert parsed["detection"]["selection"] == {
        "process.name": "schtasks.exe",
        "process.parent.name": "cmd.exe",
    }
    assert parsed["logsource"]["category"] == "windows"
    assert "attack.persistence" in parsed["tags"]


def test_to_sigma_rejects_or_queries():
    rule = DetectionRule.from_dict(
        {
            "name": "or_query_rule",
            "platform": "windows",
            "query": 'process.name:"a.exe" or process.name:"b.exe"',
            "index_patterns": ["winlogbeat-*"],
            "description": "Has an OR clause that cannot be mechanically translated.",
            "severity": "low",
            "risk_score": 20,
        }
    )
    with pytest.raises(UnsupportedQueryError):
        to_sigma(rule)
