"""Control 3 — membership group must not have crpa bindings (only tatata may)."""

from dataclasses import dataclass
from typing import List

from rabota_tool.config import get_group_pairs, load_config
from rabota_tool.gcp_client import GcpPolicyClient


@dataclass
class Violation:
    membership_group: str
    tatata: str
    message: str


def run(config_path: str, gcp: GcpPolicyClient) -> List[Violation]:
    pairs = get_group_pairs(load_config(config_path))
    violations: List[Violation] = []

    for membership, tatata in pairs:
        if gcp.is_group_in_any_policy(membership):
            violations.append(
                Violation(
                    membership_group=membership,
                    tatata=tatata,
                    message=(
                        f"EC009 - {membership} has crpa bindings; "
                        f"bindings must be on {tatata} only"
                    ),
                )
            )
    return violations
