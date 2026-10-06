"""Control 3 — membership group must not have IAM bindings (only activation_group may).

Positive CLI entry: python main.py control_3

Lists Directory groups at run time, writes:
  - directory_groups_listed.yaml (all groups, same dump as smoke)
  - control_3_groups_realtime.yaml (pairs plus member counts on both groups)
then evaluates C3-001 against that realtime pair file.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from audit_tool.framework.config import (
    get_group_pairs,
    load_config,
    pairs_from_directory_groups,
    write_directory_groups_list,
    write_privileged_group_pair_snapshots,
)
from audit_tool.framework.gcp_client import GcpPolicyClient
from audit_tool.framework.paths import (
    CONTROL_3_GROUPS_REALTIME,
    DIRECTORY_GROUPS_LISTED,
)
from audit_tool.framework.runtime import validate_runtime


@dataclass
class Violation:
    membership_group: str
    activation_group: str
    message: str


def _member_word(count: int) -> str:
    return "member" if count == 1 else "members"


def _pair_member_snapshot(
    membership: str,
    activation: str,
    membership_count: int,
    activation_count: int,
) -> dict:
    return {
        "membership_group": membership,
        "membership_members_found": membership_count,
        "activation_group": activation,
        "activation_members_found": activation_count,
    }


def evaluate(config_path: str, gcp: GcpPolicyClient) -> List[Violation]:
    """Run Control 3 checks; return violations (empty = pass)."""
    pairs = get_group_pairs(load_config(config_path))
    violations: List[Violation] = []

    for membership, activation_group in pairs:
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
                f"C3-001 - Group {membership_email} has IAM bindings; "
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


def run_with_config(
    config_path: str, gcp: Optional[GcpPolicyClient] = None
) -> int:
    """Execute Control 3 for a config file. 0 = pass, 1 = violations."""
    validate_runtime(config_path=config_path)
    logging.info("Control 3 starting, config=%s", config_path)
    violations = evaluate(config_path, gcp or GcpPolicyClient())
    if violations:
        for v in violations:
            logging.error(v.message)
        return 1
    logging.info("Control 3 passed")
    return 0


def build_realtime_config(gcp: GcpPolicyClient) -> str:
    """List Directory groups, count members on each pair, write realtime YAML."""
    logging.info("Control 3: listing Directory groups (realtime)")
    groups = gcp.list_all_directory_groups()
    listed_path = write_directory_groups_list(str(DIRECTORY_GROUPS_LISTED), groups)
    logging.info("Wrote %d group(s) to %s", len(groups), listed_path)

    generated_at = datetime.now(timezone.utc).isoformat()
    pairs = pairs_from_directory_groups(groups)
    snapshots: List[dict] = []
    note = ""

    if not pairs:
        note = (
            "No membership/activation pairs found in the Directory list. "
            "Need both <name> and <name>_ActivationGroup (or ACTIVATION_GROUP_SUFFIX)."
        )
        logging.warning("%s", note)
    else:
        logging.info(
            "Grouped %d membership/activation pair(s) (suffix from ACTIVATION_GROUP_SUFFIX)",
            len(pairs),
        )
        for membership, activation in pairs:
            membership_count = len(gcp.list_group_user_memberships(membership))
            activation_count = len(gcp.list_group_user_memberships(activation))
            snapshot = _pair_member_snapshot(
                membership,
                activation,
                membership_count,
                activation_count,
            )
            snapshots.append(snapshot)
            logging.info(
                "  %s: %d %s; %s: %d %s",
                membership,
                membership_count,
                _member_word(membership_count),
                activation,
                activation_count,
                _member_word(activation_count),
            )

    realtime_path = write_privileged_group_pair_snapshots(
        str(CONTROL_3_GROUPS_REALTIME),
        snapshots,
        generated_at,
        note=note,
    )
    logging.info("Wrote realtime Control 3 config to %s", realtime_path)
    if note:
        raise RuntimeError(note)
    return realtime_path


def run() -> int:
    """CLI entry for python main.py control_3 (positive)."""
    gcp = GcpPolicyClient(load_policies=False)
    config_path = build_realtime_config(gcp)
    gcp.load_allow_policies()
    return run_with_config(config_path, gcp)
