from unittest.mock import MagicMock

import pytest

from detection_as_code.elastic_client import ElasticClient, ElasticQueryError


def test_validate_query_true():
    fake_es = MagicMock()
    fake_es.indices.validate_query.return_value = {"valid": True}
    client = ElasticClient(url="https://es.example.com", api_key="key", client=fake_es)

    assert client.validate_query(["winlogbeat-*"], 'process.name:"a.exe"') is True


def test_validate_query_false():
    fake_es = MagicMock()
    fake_es.indices.validate_query.return_value = {"valid": False}
    client = ElasticClient(url="https://es.example.com", api_key="key", client=fake_es)

    assert client.validate_query(["winlogbeat-*"], "bad::syntax") is False


def test_validate_query_wraps_exceptions():
    fake_es = MagicMock()
    fake_es.indices.validate_query.side_effect = RuntimeError("boom")
    client = ElasticClient(url="https://es.example.com", api_key="key", client=fake_es)

    with pytest.raises(ElasticQueryError, match="boom"):
        client.validate_query(["winlogbeat-*"], 'process.name:"a.exe"')


def test_count_matches_returns_hit_total():
    fake_es = MagicMock()
    fake_es.search.return_value = {"hits": {"total": {"value": 42}}}
    client = ElasticClient(url="https://es.example.com", api_key="key", client=fake_es)

    assert client.count_matches(["winlogbeat-*"], 'process.name:"a.exe"') == 42
