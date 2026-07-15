from __future__ import annotations

import os
from typing import Protocol


class SecretProvider(Protocol):
    """Anything that can resolve a named secret. Implement this against your
    org's actual vault (AWS Secrets Manager, Akeyless, CyberArk, ...) and the
    rest of the pipeline needs no changes - clients only depend on this shape.
    """

    def get(self, key: str) -> str: ...


class EnvSecretProvider:
    """Reads secrets from environment variables. This is the only provider
    shipped here; production deployments should swap in a real vault-backed
    provider rather than storing long-lived credentials in process env vars.
    """

    def __init__(self, prefix: str = "DAC_"):
        self.prefix = prefix

    def get(self, key: str) -> str:
        env_key = f"{self.prefix}{key.upper()}"
        value = os.environ.get(env_key)
        if not value:
            raise KeyError(f"Missing required secret: {env_key}")
        return value
