from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .models import DetectionRule, Severity

_UNSAFE_NAME_CHARS = re.compile(r'[\\/:*?"<>|]')
_MIN_DESCRIPTION_LEN = 20


class IssueLevel(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class LintIssue:
    level: IssueLevel
    message: str


def lint_rule(rule: DetectionRule) -> list[LintIssue]:
    """Deterministic checks. This - not the AI critic - is what gates a merge:
    every issue here is reproducible, explainable, and has no false-refusal
    risk from a model having a bad day.
    """
    issues: list[LintIssue] = []

    if _UNSAFE_NAME_CHARS.search(rule.name):
        issues.append(
            LintIssue(IssueLevel.ERROR, "Rule name contains characters unsafe for filenames")
        )

    if not rule.index_patterns:
        issues.append(LintIssue(IssueLevel.ERROR, "Rule has no index patterns"))

    if rule.query.strip() in {"", "*"}:
        issues.append(
            LintIssue(
                IssueLevel.ERROR,
                "Query is empty or matches everything ('*') - too broad to ship",
            )
        )

    if len(rule.description) < _MIN_DESCRIPTION_LEN:
        issues.append(
            LintIssue(IssueLevel.WARNING, "Description is too short to be useful during triage")
        )

    if not rule.tactics:
        issues.append(
            LintIssue(
                IssueLevel.WARNING,
                "No MITRE ATT&CK tactic mapped - triage context will be weak",
            )
        )

    if not rule.false_positives:
        issues.append(LintIssue(IssueLevel.WARNING, "No known false positives documented"))

    if rule.severity in (Severity.HIGH, Severity.CRITICAL) and not rule.techniques:
        issues.append(
            LintIssue(IssueLevel.WARNING, "High/critical severity rule has no ATT&CK technique ID")
        )

    return issues


def has_blocking_issues(issues: list[LintIssue]) -> bool:
    return any(issue.level == IssueLevel.ERROR for issue in issues)
