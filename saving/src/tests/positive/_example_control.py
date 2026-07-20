"""TEMPLATE — copy to a new module (without leading underscore) to add a control.

cp _example_control.py control_4.py

Put control logic in this file (under tests/positive or tests/negative).
Shared helpers stay in audit_tool.framework.

Then implement run(). It will appear in: python main.py <name>
"""

# Optional: NAME = "custom_cli_name"


def evaluate():
    """Control logic — return findings/violations (empty = pass)."""
    raise NotImplementedError("Replace with control logic")


def run() -> int:
    """CLI entry — wire env/client, call evaluate, return 0 or 1."""
    findings = evaluate()
    return 1 if findings else 0
