"""Control 3 — membership group must not have IAM bindings (only activation_group may).

Positive CLI entry: python main.py control_3
"""

import logging
import os
from dataclasses import dataclass
from typing import List

from audit_tool.framework.config import get_group_pairs, load_config
from audit_tool.framework.gcp_client import GcpPolicyClient
from audit_tool.framework.paths import DEPLOY_CONTROL_3_GROUPS
from audit_tool.framework.runtime import resolve_config_path, validate_runtime


@dataclass
class Violation:
    membership_group: str
    activation_group: str
    message: str


def _existence_check_enabled() -> bool:
    raw = os.environ.get("AUDIT_CHECK_GROUP_EXISTS", "true").strip().lower()
    return raw in ("1", "true", "yes", "y")


def evaluate(config_path: str, gcp: GcpPolicyClient) -> List[Violation]:
    """Run Control 3 checks; return violations (empty = pass)."""
    pairs = get_group_pairs(load_config(config_path))
    violations: List[Violation] = []
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

        membership_email = gcp.group_email(membership)
        activation_email = gcp.group_email(activation_group)
        if gcp.is_group_in_any_policy(membership):
            message = (
                f"C3-001 - Group {membership_email} has iam bindings; "
                f"bindings must be on {activation_email} only"
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
                membership_email,
            )
    return violations


def run_with_config(config_path: str) -> int:
    """Execute Control 3 for a config file. 0 = pass, 1 = violations."""
    validate_runtime()
    logging.info("Control 3 starting, config=%s", config_path)
    violations = evaluate(config_path, GcpPolicyClient())
    if violations:
        for v in violations:
            logging.error(v.message)
        return 1
    logging.info("Control 3 passed")
    return 0


def run() -> int:
    """CLI entry for python main.py control_3."""
    return run_with_config(resolve_config_path(DEPLOY_CONTROL_3_GROUPS))
