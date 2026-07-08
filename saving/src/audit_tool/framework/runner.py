"""Test runner — auto-discovers tests then dispatches by name."""

from audit_tool.framework.discovery import discover_tests
from audit_tool.framework.registry import list_tests, run

discover_tests()

__all__ = ["list_tests", "run"]
