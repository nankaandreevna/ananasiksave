"""Control 2 — TEALAS access expiration on Activation Groups.

Temporary TEALAS access on an Activation Group must not remain after the
approved window (default 24 hours from createTime, or expireTime if set).

Positive CLI: python main.py control_2

Lists Directory groups at run time, writes:
  - directory_groups_listed.yaml (all groups, same dump as smoke)
  - control_2_groups_realtime.yaml (activation groups only, with member counts)
then evaluates C2-001 against those activation groups.

Uses GOOGLE_GROUP_DOMAIN_NAME (testenv.example in this env). Do not append
@example.com here; that domain is for a later org/SA via the same env var.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from audit_tool.framework.config import (
    get_activation_groups,
    load_config,
    pairs_from_directory_groups,
    write_activation_group_snapshots,
    write_directory_groups_list,
)
from audit_tool.framework.gcp_client import GcpPolicyClient
from audit_tool.framework.paths import (
    CONTROL_2_GROUPS_REALTIME,
    DIRECTORY_GROUPS_LISTED,
)
from audit_tool.framework.runtime import validate_runtime


@dataclass
class Violation:
    activation_group: str
    user_email: str
    expired_at: str
    overdue_hours: float
    message: str


def _max_age_hours() -> float:
    raw = os.environ.get("APP_TEALAS_MAX_AGE_HOURS", "24").strip()
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(
            f"APP_TEALAS_MAX_AGE_HOURS must be a number, got {raw!r}"
        ) from exc


def _parse_rfc3339(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _expiry_for_member(member: dict, max_age_hours: float) -> datetime:
    """Prefer TEALAS expireTime; else createTime + max age (docs: 24h)."""
    expire_raw = member.get("expire_time")
    if expire_raw:
        return _parse_rfc3339(expire_raw)
    create_raw = member.get("create_time")
    if not create_raw:
        raise ValueError(
            f"membership {member.get('email')!r} has no createTime or expireTime"
        )
    return _parse_rfc3339(create_raw) + timedelta(hours=max_age_hours)


def _member_word(count: int) -> str:
    return "member" if count == 1 else "members"


def _active_duration_hours(added_at: str, checked_at: str) -> Optional[float]:
    """Hours from membership createTime to this Control 2 run."""
    try:
        added = _parse_rfc3339(added_at)
        checked = _parse_rfc3339(checked_at)
    except (TypeError, ValueError):
        return None
    return round((checked - added).total_seconds() / 3600.0, 2)


def _membership_snapshot(activation: str, members: List[dict], checked_at: str) -> dict:
    """Snapshot for realtime YAML.

    ``checked_at`` = when this script ran (group-level).
    Per member: ``added_at`` = Cloud Identity createTime (joined activation group);
    ``active_duration_hours`` = hours since added_at as of checked_at.
    """
    count = len(members)
    rows: List[dict] = []
    for member in members:
        added_at = member.get("create_time")
        row: dict = {
            "email": member.get("email"),
            "added_at": added_at,  # when user joined the activation group
            "active_duration_hours": (
                _active_duration_hours(added_at, checked_at) if added_at else None
            ),
        }
        if member.get("expire_time"):
            row["expire_time"] = member["expire_time"]
        rows.append(row)
    return {
        "activation_group": activation,
        "members_found": count,
        "checked_at": checked_at,  # script run time (not membership add time)
        "summary": f"found {count} {_member_word(count)}; checked_at={checked_at}",
        "members": rows,
    }


def _violations_for_group(
    activation: str,
    members: List[dict],
    gcp: GcpPolicyClient,
    max_age: float,
    now: datetime,
) -> List[Violation]:
    activation_email = gcp.group_email(activation)
    violations: List[Violation] = []
    for member in members:
        user_email = member["email"]
        try:
            expired_at = _expiry_for_member(member, max_age)
        except ValueError as exc:
            logging.warning("%s", exc)
            continue
        if now <= expired_at:
            logging.info(
                "OK %s in %s until %s",
                user_email,
                activation_email,
                expired_at.isoformat(),
            )
            continue

        overdue = (now - expired_at).total_seconds() / 3600.0
        message = (
            f"C2-001 - TEALAS expiry: group={activation_email} user={user_email} "
            f"expired_at={expired_at.isoformat()} overdue_hours={overdue:.1f}"
        )
        logging.info(message)
        violations.append(
            Violation(
                activation_group=activation,
                user_email=user_email,
                expired_at=expired_at.isoformat(),
                overdue_hours=overdue,
                message=message,
            )
        )
    return violations


def evaluate(
    config_path: str,
    gcp: GcpPolicyClient,
    memberships_by_group: Optional[Dict[str, List[dict]]] = None,
) -> List[Violation]:
    """Return violations for users still in Activation Groups past expiry."""
    groups = get_activation_groups(load_config(config_path))
    max_age = _max_age_hours()
    now = datetime.now(timezone.utc)
    violations: List[Violation] = []

    logging.info(
        "Control 2 starting TEALAS expiry check: %d activation groups, max_age=%sh",
        len(groups),
        max_age,
    )

    for activation in groups:
        if memberships_by_group is not None and activation in memberships_by_group:
            members = memberships_by_group[activation]
        else:
            members = gcp.list_group_user_memberships(activation)
        violations.extend(
            _violations_for_group(activation, members, gcp, max_age, now)
        )
    return violations


def run_with_config(
    config_path: str,
    gcp: Optional[GcpPolicyClient] = None,
    memberships_by_group: Optional[Dict[str, List[dict]]] = None,
) -> int:
    """0 = pass (no expired members), 1 = violations."""
    validate_runtime(config_path=config_path)
    # No Asset IAM load — Control 2 only needs Cloud Identity memberships.
    client = gcp or GcpPolicyClient(load_policies=False)
    violations = evaluate(config_path, client, memberships_by_group)
    if violations:
        for v in violations:
            logging.error(v.message)
        return 1
    logging.info("Control 2 passed — no expired TEALAS activation memberships")
    return 0


def build_realtime_config(
    gcp: GcpPolicyClient,
) -> Tuple[str, Dict[str, List[dict]]]:
    """List Directory groups, snapshot activation memberships, write realtime YAML."""
    logging.info("Control 2: listing Directory groups (realtime)")
    groups = gcp.list_all_directory_groups()
    listed_path = write_directory_groups_list(str(DIRECTORY_GROUPS_LISTED), groups)
    logging.info("Wrote %d group(s) to %s", len(groups), listed_path)

    generated_at = datetime.now(timezone.utc).isoformat()
    pairs = pairs_from_directory_groups(groups)
    snapshots: List[dict] = []
    memberships_by_group: Dict[str, List[dict]] = {}
    note = ""

    if not pairs:
        note = (
            "No membership/activation pairs found in the Directory list. "
            "Need both <name> and <name>_ActivationGroup (or ACTIVATION_GROUP_SUFFIX)."
        )
        logging.warning("%s", note)
    else:
        logging.info(
            "Checking %d activation group(s) (suffix from ACTIVATION_GROUP_SUFFIX)",
            len(pairs),
        )
        for _, activation in pairs:
            checked_at = datetime.now(timezone.utc).isoformat()
            members = gcp.list_group_user_memberships(activation)
            memberships_by_group[activation] = members
            snapshot = _membership_snapshot(activation, members, checked_at)
            snapshots.append(snapshot)
            logging.info("%s: %s", activation, snapshot["summary"])

    realtime_path = write_activation_group_snapshots(
        str(CONTROL_2_GROUPS_REALTIME),
        snapshots,
        generated_at,
        note=note,
    )
    logging.info("Wrote realtime Control 2 config to %s", realtime_path)
    return realtime_path, memberships_by_group


def run() -> int:
    """CLI entry for python main.py control_2 (positive)."""
    gcp = GcpPolicyClient(load_policies=False)
    config_path, memberships_by_group = build_realtime_config(gcp)
    return run_with_config(config_path, gcp, memberships_by_group)
