"""Control 3 — membership group must not have IAM bindings (only activation_group may)."""

import logging
import os
from dataclasses import dataclass
from typing import List

from audit_tool.config import get_group_pairs, load_config
from audit_tool.gcp_client import GcpPolicyClient


@dataclass
class Violation:
    membership_group: str
    activation_group: str
    message: str


def _existence_check_enabled() -> bool:
    raw = os.environ.get("AUDIT_CHECK_GROUP_EXISTS", "true").strip().lower()
    return raw in ("1", "true", "yes", "y")


def run(config_path: str, gcp: GcpPolicyClient) -> List[Violation]:
    pairs = get_group_pairs(load_config(config_path))
    violations: List[Violation] = []
    # Env check lives here (not on GcpPolicyClient) so a partial gcp_client
    # sync cannot raise AttributeError for group_exists_check_enabled.
    check_exists = _existence_check_enabled()
    if check_exists and not hasattr(gcp, "group_exists"):
        logging.warning(
            "GcpPolicyClient has no group_exists(); skipping Cloud Identity "
            "existence checks. Sync gcp_client.py or set AUDIT_CHECK_GROUP_EXISTS=false."
        )
        check_exists = False
    elif not check_exists:
        logging.info(
            "Skipping Cloud Identity existence checks "
            "(AUDIT_CHECK_GROUP_EXISTS=false)"
        )

    for membership, activation_group in pairs:
        if check_exists:
            if not gcp.group_exists(membership):
                message = (
                    f"Group {membership} does not exist in Cloud Identity "
                    f"(looked up as {gcp.group_email(membership)})"
                )
                logging.info(message)
                violations.append(
                    Violation(
                        membership_group=membership,
                        activation_group=activation_group,
                        message=message,
                    )
                )
                continue

            if not gcp.group_exists(activation_group):
                message = (
                    f"Activation group {activation_group} does not exist in Cloud Identity "
                    f"(looked up as {gcp.group_email(activation_group)})"
                )
                logging.info(message)
                violations.append(
                    Violation(
                        membership_group=membership,
                        activation_group=activation_group,
                        message=message,
                    )
                )
                continue

        if gcp.is_group_in_any_policy(membership):
            message = (
                f"C3-001 - Group {membership} has iam bindings; "
                f"bindings must be on {activation_group} only"
            )
            logging.info(message)
            violations.append(
                Violation(
                    membership_group=membership,
                    activation_group=activation_group,
                    message=message,
                )
            )
        else:
            logging.info(
                "membership group %s doesn't have any bindings - SUCCESS",
                membership,
            )
    return violations
