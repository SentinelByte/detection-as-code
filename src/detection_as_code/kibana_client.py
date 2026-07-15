from __future__ import annotations

from typing import Any

import requests
from requests.auth import HTTPBasicAuth

from .secrets import SecretProvider


class KibanaClientError(RuntimeError):
    """Raised when the Kibana Detection Engine API rejects a request."""


class KibanaClient:
    """Thin, dependency-injected wrapper around the Kibana Detection Engine
    API. The session is injectable so tests never touch the network.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        session: requests.Session | None = None,
        timeout: float = 15.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._auth = HTTPBasicAuth(username, password)
        self._session = session or requests.Session()
        self._timeout = timeout
        self._headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}

    @classmethod
    def from_secrets(cls, secrets: SecretProvider) -> KibanaClient:
        return cls(
            base_url=secrets.get("kibana_url"),
            username=secrets.get("kibana_user"),
            password=secrets.get("kibana_password"),
        )

    def list_connectors(self) -> list[dict[str, Any]]:
        resp = self._session.get(
            f"{self._base_url}/api/actions/connectors",
            headers=self._headers,
            auth=self._auth,
            timeout=self._timeout,
        )
        if not resp.ok:
            raise KibanaClientError(f"Failed to list connectors: {resp.status_code} {resp.text}")
        return resp.json()

    def create_rule(self, rule_payload: dict[str, Any]) -> dict[str, Any]:
        resp = self._session.post(
            f"{self._base_url}/api/detection_engine/rules",
            headers=self._headers,
            json=rule_payload,
            auth=self._auth,
            timeout=self._timeout,
        )
        if resp.status_code == 409:
            raise KibanaClientError(f"Rule '{rule_payload.get('name')}' already exists")
        if not resp.ok:
            raise KibanaClientError(f"Failed to create rule: {resp.status_code} {resp.text}")
        return resp.json()
