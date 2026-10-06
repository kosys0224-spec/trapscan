"""Detector modules. Importing this package registers every rule in trapscan.findings.RULES."""
from . import editors, gitrules, build, agents, content  # noqa: F401

__all__ = ["editors", "gitrules", "build", "agents", "content"]
