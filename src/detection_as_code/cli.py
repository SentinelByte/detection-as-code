from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .exporters import to_kibana_json, to_sigma
from .models import DetectionRule
from .secrets import EnvSecretProvider
from .validators import has_blocking_issues, lint_rule


def _load_rule(path: Path) -> DetectionRule:
    data = yaml.safe_load(path.read_text())
    return DetectionRule.from_dict(data)


def cmd_lint(args: argparse.Namespace) -> int:
    rule = _load_rule(args.rule_file)
    issues = lint_rule(rule)
    for issue in issues:
        print(f"[{issue.level.value.upper()}] {issue.message}")
    if has_blocking_issues(issues):
        print("\nLint failed: blocking issues found")
        return 1
    print("\nLint passed")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    rule = _load_rule(args.rule_file)
    print(to_sigma(rule) if args.format == "sigma" else to_kibana_json(rule))
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    from .elastic_client import ElasticClient
    from .kibana_client import KibanaClient

    rule = _load_rule(args.rule_file)
    issues = lint_rule(rule)
    if has_blocking_issues(issues):
        print("Refusing to deploy: rule has blocking lint issues", file=sys.stderr)
        return 1

    secrets = EnvSecretProvider()
    elastic = ElasticClient.from_secrets(secrets)
    if not elastic.validate_query(rule.index_patterns, rule.query):
        print("Refusing to deploy: query failed Elasticsearch validation", file=sys.stderr)
        return 1

    kibana = KibanaClient.from_secrets(secrets)
    kibana.create_rule(json.loads(to_kibana_json(rule)))
    print("Deployed rule successfully")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    from .ai_review import review_rule

    rule = _load_rule(args.rule_file)
    review = review_rule(rule)

    print(f"Overall: {review.overall_comment}\n")
    for label, items in (
        ("Coverage gaps", review.coverage_gaps),
        ("False positive risks", review.false_positive_risks),
        ("Missing context", review.missing_context),
    ):
        print(f"{label}:")
        for item in items:
            print(f"  - {item}")
        if not items:
            print("  (none)")

    if not review.available:
        print(
            "\nNote: this is advisory only and does not affect lint/deploy gates.",
            file=sys.stderr,
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="detection-as-code")
    sub = parser.add_subparsers(dest="command", required=True)

    p_lint = sub.add_parser("lint", help="Run deterministic checks against a rule file")
    p_lint.add_argument("rule_file", type=Path)
    p_lint.set_defaults(func=cmd_lint)

    p_export = sub.add_parser("export", help="Export a rule to Sigma or Kibana JSON")
    p_export.add_argument("rule_file", type=Path)
    p_export.add_argument("--format", choices=["sigma", "kibana"], default="kibana")
    p_export.set_defaults(func=cmd_export)

    p_deploy = sub.add_parser("deploy", help="Validate and deploy a rule to Kibana")
    p_deploy.add_argument("rule_file", type=Path)
    p_deploy.set_defaults(func=cmd_deploy)

    p_review = sub.add_parser("review", help="Get an advisory AI review of a rule (non-blocking)")
    p_review.add_argument("rule_file", type=Path)
    p_review.set_defaults(func=cmd_review)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
