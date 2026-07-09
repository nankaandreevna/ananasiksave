"""Control 3 — membership group must not have iam bindings (only activation_group may)."""

from dataclasses import dataclass
from typing import List

from audit_tool.config import get_group_pairs, load_config
from audit_tool.gcp_client import GcpPolicyClient


@dataclass
class Violation:
    membership_group: str
    activation_group: str
    message: str


def run(config_path: str, gcp: GcpPolicyClient) -> List[Violation]:
    pairs = get_group_pairs(load_config(config_path))
    violations: List[Violation] = []

    for membership, activation_group in pairs:
        if gcp.is_group_in_any_policy(membership):
            violations.append(
                Violation(
                    membership_group=membership,
                    activation_group=activation_group,
                    message=(
                        f"C3-001 - {membership} has iam bindings; "
                        f"bindings must be on {activation_group} only"
                    ),
                )
            )
    return violations
