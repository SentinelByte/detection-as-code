from __future__ import annotations

from typing import Any

from .secrets import SecretProvider


class ElasticQueryError(RuntimeError):
    """Raised when Elasticsearch rejects a query or the request itself fails."""


class ElasticClient:
    """Wraps the Elasticsearch client for the two things the pipeline needs
    before a rule ships: confirming the query is syntactically valid, and
    backtesting it against recent data so a rule doesn't go live silent.
    """

    def __init__(self, url: str, api_key: str, client: Any = None):
        if client is None:
            from elasticsearch import Elasticsearch

            client = Elasticsearch(url, api_key=api_key)
        self._client = client

    @classmethod
    def from_secrets(cls, secrets: SecretProvider) -> ElasticClient:
        return cls(url=secrets.get("elastic_url"), api_key=secrets.get("elastic_api_key"))

    def validate_query(self, index_patterns: list[str], query: str) -> bool:
        try:
            response = self._client.indices.validate_query(
                index=",".join(index_patterns), q=query, explain=True
            )
        except Exception as exc:  # noqa: BLE001 - surface as a domain error
            raise ElasticQueryError(f"Query validation request failed: {exc}") from exc
        return bool(response.get("valid", False))

    def count_matches(
        self, index_patterns: list[str], query: str, lookback: str = "now-7d/d"
    ) -> int:
        """Run the rule's query over the lookback window and return the hit
        count, so a rule with zero backtest hits gets flagged before it ships
        rather than discovered silent in production.
        """
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [{"range": {"@timestamp": {"gte": lookback, "lt": "now"}}}],
                }
            }
        }
        try:
            response = self._client.search(index=",".join(index_patterns), body=body, size=0)
        except Exception as exc:  # noqa: BLE001 - surface as a domain error
            raise ElasticQueryError(f"Backtest search failed: {exc}") from exc
        return int(response["hits"]["total"]["value"])
