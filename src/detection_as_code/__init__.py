"""A schema-first detection engineering pipeline.

Rules are authored once as declarative YAML, checked deterministically,
exported to whichever backend needs them, and optionally reviewed by an
LLM before a human ships them. See docs/architecture.md for the full flow.
"""

from .models import DetectionRule, Severity, Tactic

__all__ = ["DetectionRule", "Severity", "Tactic"]
__version__ = "0.2.0"
