from __future__ import annotations

import json
import re
import uuid

import yaml

from .models import DetectionRule

_SIMPLE_CLAUSE = re.compile(r'^\s*([\w.]+)\s*:\s*"?([^"]+?)"?\s*$')


class UnsupportedQueryError(ValueError):
    """Raised when a query is too complex for the mechanical Sigma converter.

    Sigma's `detection` block expects structured field:value selections. Kuery
    supports arbitrary boolean grouping this converter does not attempt to
    reason about. Refusing loudly beats silently emitting a Sigma rule with
    different match semantics than the source query.
    """


def _parse_simple_conjunction(query: str) -> dict[str, str]:
    if " or " in query.lower() or "(" in query or ")" in query:
        raise UnsupportedQueryError(
            "Query uses OR/grouping - convert to Sigma by hand, "
            "a mechanical conversion would risk changing match semantics"
        )
    fields: dict[str, str] = {}
    for clause in re.split(r"\s+and\s+", query.strip(), flags=re.IGNORECASE):
        match = _SIMPLE_CLAUSE.match(clause)
        if not match:
            raise UnsupportedQueryError(f"Cannot mechanically translate clause: '{clause}'")
        fields[match.group(1)] = match.group(2)
    return fields


def to_sigma(rule: DetectionRule) -> str:
    """Export to Sigma YAML. Only supports simple `field:value AND field:value`
    Kuery - see UnsupportedQueryError for why anything richer is rejected
    rather than guessed at.
    """
    selection = _parse_simple_conjunction(rule.query)
    sigma_rule = {
        "title": rule.name,
        "id": rule.rule_id or str(uuid.uuid4()),
        "status": "stable" if rule.enabled else "experimental",
        "description": rule.description,
        "logsource": {"category": rule.platform.lower()},
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": rule.false_positives or ["Unknown"],
        "level": rule.severity.value,
        "tags": [f"attack.{tactic.name.lower()}" for tactic in rule.tactics] + rule.tags,
    }
    return yaml.safe_dump(sigma_rule, sort_keys=False)


def to_kibana_json(rule: DetectionRule) -> str:
    payload = {
        "rule_id": rule.rule_id or str(uuid.uuid4()),
        "name": rule.name,
        "description": rule.description,
        "risk_score": rule.risk_score,
        "severity": rule.severity.value,
        "type": "query",
        "query": rule.query,
        "language": "kuery",
        "index": rule.index_patterns,
        "interval": rule.interval,
        "from": f"now-{rule.lookback}",
        "tags": [f"tactic:{tactic.name.lower()}" for tactic in rule.tactics] + rule.tags,
        "false_positives": rule.false_positives,
        "author": [rule.author] if rule.author else [],
        "enabled": rule.enabled,
    }
    return json.dumps(payload, indent=2)
