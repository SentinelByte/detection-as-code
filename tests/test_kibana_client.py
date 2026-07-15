from unittest.mock import MagicMock

import pytest

from detection_as_code.kibana_client import KibanaClient, KibanaClientError


def _client_with_session(session):
    return KibanaClient(
        base_url="https://kibana.example.com", username="user", password="pass", session=session
    )


def test_list_connectors_success():
    session = MagicMock()
    session.get.return_value = MagicMock(ok=True, json=lambda: [{"id": "1", "name": "torq"}])
    client = _client_with_session(session)

    connectors = client.list_connectors()

    assert connectors == [{"id": "1", "name": "torq"}]
    session.get.assert_called_once()


def test_list_connectors_failure_raises():
    session = MagicMock()
    session.get.return_value = MagicMock(ok=False, status_code=403, text="forbidden")
    client = _client_with_session(session)

    with pytest.raises(KibanaClientError, match="403"):
        client.list_connectors()


def test_create_rule_success():
    session = MagicMock()
    session.post.return_value = MagicMock(ok=True, json=lambda: {"id": "abc123"})
    client = _client_with_session(session)

    result = client.create_rule({"name": "my_rule"})

    assert result["id"] == "abc123"


def test_create_rule_conflict_raises_clear_error():
    session = MagicMock()
    session.post.return_value = MagicMock(ok=False, status_code=409, text="conflict")
    client = _client_with_session(session)

    with pytest.raises(KibanaClientError, match="already exists"):
        client.create_rule({"name": "duplicate_rule"})
