# Threat Model

Short version: this repo touches three things that deserve explicit trust
boundaries - secrets, an LLM, and a write path into production detection
tooling. Each is scoped down on purpose.

## Secrets

- No credential ever lives in this repo, including as an empty placeholder
  meant to be filled in - `secrets.py` defines a `SecretProvider` protocol
  and ships exactly one implementation, `EnvSecretProvider`, which reads
  from environment variables. Swap in a real vault-backed provider
  (AWS Secrets Manager, Akeyless, CyberArk, ...) for production use; nothing
  else in the pipeline needs to change.
- `KibanaClient` and `ElasticClient` take credentials as constructor
  arguments (or via `.from_secrets()`), never read them from globals, and
  never log them.

## The LLM reviewer is advisory only, by construction, not convention

- `review_rule()` is forced into structured tool output
  (`tool_choice={"type": "tool", "name": "submit_rule_review"}`) - there is
  no free-text path for the model to influence anything other than the
  three findings lists and a comment string. It has no tool that can edit a
  rule file, call `KibanaClient`, or affect `has_blocking_issues()`.
- The rule body (name, query, description, tags) is user-authored content
  that reaches the model. It's wrapped in explicit `<rule_under_review>`
  tags and the system prompt instructs the model to treat that block as
  data to critique, never as instructions - the classic prompt-injection
  boundary between control (system prompt) and untrusted data (rule
  content, which anyone opening a PR controls).
- Every failure mode (package not installed, no API key, network error,
  malformed/incomplete tool output) degrades to `RuleReview.unavailable()`
  rather than raising. A model having a bad day should never be able to
  break the deploy pipeline it's advising on, in either direction - it
  can't force a bad rule through, and it can't block a good one.

## The only path that writes to production is `deploy`

- `cmd_deploy` refuses to run if `lint_rule()` has any blocking issue.
- It then requires `ElasticClient.validate_query()` to confirm the query is
  syntactically valid against real index patterns before any Kibana write
  happens.
- Only after both checks pass does `KibanaClient.create_rule()` run - and
  Kibana's own 409 response is surfaced as a clear "already exists" error
  rather than silently overwriting an existing rule.

## Dependency hygiene

CI runs `bandit` (static analysis for common insecure patterns) and
`pip-audit` (known-vulnerability scan against the dependency set) on every
push and PR - see [ci.yml](../.github/workflows/ci.yml).
