import json
from pathlib import Path

import pytest
import yaml

from detection_as_code.cli import main

VALID_RULE = {
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


@pytest.fixture
def rule_file(tmp_path: Path) -> Path:
    path = tmp_path / "rule.yaml"
    path.write_text(yaml.safe_dump(VALID_RULE))
    return path


def test_lint_passes_for_a_clean_rule(rule_file, capsys):
    exit_code = main(["lint", str(rule_file)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Lint passed" in out


def test_lint_fails_for_a_broad_rule(tmp_path, capsys):
    path = tmp_path / "broad.yaml"
    path.write_text(yaml.safe_dump({**VALID_RULE, "query": "*"}))

    exit_code = main(["lint", str(path)])
    out = capsys.readouterr().out

    assert exit_code == 1
    assert "too broad" in out.lower()


def test_export_kibana_produces_valid_json(rule_file, capsys):
    exit_code = main(["export", str(rule_file), "--format", "kibana"])
    out = capsys.readouterr().out

    assert exit_code == 0
    payload = json.loads(out)
    assert payload["name"] == VALID_RULE["name"]


def test_export_sigma_produces_valid_yaml(rule_file, capsys):
    exit_code = main(["export", str(rule_file), "--format", "sigma"])
    out = capsys.readouterr().out

    assert exit_code == 0
    parsed = yaml.safe_load(out)
    assert parsed["title"] == VALID_RULE["name"]


def test_deploy_refuses_when_lint_has_blocking_issues(tmp_path, capsys):
    path = tmp_path / "broad.yaml"
    path.write_text(yaml.safe_dump({**VALID_RULE, "query": "*"}))

    exit_code = main(["deploy", str(path)])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "Refusing to deploy" in err
