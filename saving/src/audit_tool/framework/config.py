"""Load YAML config and read manual group pairs / activation groups."""

import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

GroupPair = Tuple[str, str]

# Same default: membership + suffix = activation group
ACTIVATION_GROUP_SUFFIX = os.environ.get("ACTIVATION_GROUP_SUFFIX", "_ActivationGroup")


def expected_activation_group(membership_group: str) -> str:
    """Derive activation group name from membership + ACTIVATION_GROUP_SUFFIX."""
    return f"{membership_group}{ACTIVATION_GROUP_SUFFIX}"


def local_group_name(value: str) -> str:
    """Local part of a group email, lowercased, no domain."""
    return str(value).split("@")[0].strip().lower()


def pairs_from_directory_groups(groups: List[dict]) -> List[GroupPair]:
    """Pair membership + activation groups from a live Directory list.

    A pair exists only when both local names are present:
    membership and membership + ACTIVATION_GROUP_SUFFIX.
    """
    names = set()
    for item in groups:
        email = (item.get("email") or item.get("name") or "").strip()
        name = local_group_name(email)
        if name:
            names.add(name)

    suffix = ACTIVATION_GROUP_SUFFIX.lower()
    pairs: List[GroupPair] = []
    for membership in sorted(names):
        if membership.endswith(suffix):
            continue
        activation = expected_activation_group(membership)
        if activation.lower() in names:
            pairs.append((membership, activation))
    return pairs


def write_directory_groups_list(path: str, groups: List[dict]) -> str:
    """Write Directory emails as returned. Does not rewrite the domain."""
    payload = {
        "domain": os.environ.get("GOOGLE_GROUP_DOMAIN_NAME", "").lower(),
        "count": len(groups),
        "groups": groups,
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        handle.write(
            "# Generated from Directory groups.list. Do not edit.\n"
            "# Emails are as returned by Directory — domain is not rewritten.\n"
        )
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
    return str(out)


def write_activation_group_snapshots(
    path: str,
    snapshots: List[Dict[str, Any]],
    generated_at: str,
    note: str = "",
) -> str:
    """Write Control 2 realtime YAML: activation groups only, plus membership counts."""
    payload: Dict[str, Any] = {
        "generated_at": generated_at,
        "count": len(snapshots),
        "activation_groups": snapshots,
    }
    if note:
        payload["note"] = note
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        handle.write(
            "# Generated at Control 2 run. Activation groups only. Do not edit.\n"
            "# members_found is 0 when Cloud Identity returned no user memberships.\n"
        )
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
    return str(out)


def write_privileged_group_pair_snapshots(
    path: str,
    snapshots: List[Dict[str, Any]],
    generated_at: str,
    note: str = "",
) -> str:
    """Write Control 3 realtime YAML: pairs plus member counts on both groups."""
    payload: Dict[str, Any] = {
        "generated_at": generated_at,
        "count": len(snapshots),
        "privileged_group_pairs": snapshots,
    }
    if note:
        payload["note"] = note
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        handle.write(
            "# Generated at Control 3 run. Do not edit.\n"
            "# Each pair lists membership_group and activation_group member counts.\n"
        )
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
    return str(out)


def write_control_5_findings_realtime(
    path: str,
    findings: List[Dict[str, Any]],
    generated_at: str,
    scope: str,
    marker_key: str,
    marker_value: str,
    note: str = "",
) -> str:
    """Write Control 5 realtime YAML: violation findings only (not all tagged SAs)."""
    payload: Dict[str, Any] = {
        "generated_at": generated_at,
        "scope": scope,
        "marker_key": marker_key,
        "marker_value": marker_value,
        "finding_count": len(findings),
        "findings": findings,
    }
    if note:
        payload["note"] = note
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        handle.write(
            "# Generated at Control 5 run. Overwritten each run. Do not edit.\n"
            "# findings only: SAs that violated Control 5 (SA + tag + role + permissions).\n"
            "# Tagged SAs with no privileged permissions are omitted.\n"
        )
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
    return str(out)


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Config must be a YAML mapping")
    return data


def get_group_pairs(config: Dict[str, Any]) -> List[GroupPair]:
    """Read privileged_group_pairs from config (manual list, no LDAP).

    Validates that activation_group matches membership_group + ACTIVATION_GROUP_SUFFIX.
    """
    pairs = config.get("privileged_group_pairs", [])
    if not pairs:
        raise ValueError("privileged_group_pairs must be a non-empty list")

    result: List[GroupPair] = []
    for item in pairs:
        membership = str(item["membership_group"]).split("@")[0].strip()
        activation_group = str(item["activation_group"]).split("@")[0].strip()
        if not membership or not activation_group:
            raise ValueError("each pair needs membership_group and activation_group")
        expected = expected_activation_group(membership)
        if activation_group.casefold() != expected.casefold():
            raise ValueError(
                f"activation group naming mismatch: membership_group={membership!r} "
                f"expects activation_group={expected!r} "
                f"(suffix {ACTIVATION_GROUP_SUFFIX!r}), got {activation_group!r}"
            )
        result.append((membership, activation_group))
    return result


def get_activation_groups(config: Dict[str, Any]) -> List[str]:
    """Activation groups for Control 2 (TEALAS expiry).

    Accepts:
      activation_groups: [name, ...]
      activation_groups: [{activation_group: name, ...}, ...]  (realtime snapshot)
      or privileged_group_pairs (uses each activation_group).
    An explicit empty activation_groups list is allowed (nothing to check).
    """
    if "activation_groups" in config:
        raw = config.get("activation_groups")
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            raise ValueError("activation_groups must be a list")
        result: List[str] = []
        for item in raw:
            if isinstance(item, dict):
                name = str(
                    item.get("activation_group") or item.get("name") or ""
                ).split("@")[0].strip()
            else:
                name = str(item).split("@")[0].strip()
            if not name:
                raise ValueError("activation_groups entries must be non-empty")
            result.append(name)
        return result

    pairs = get_group_pairs(config)
    return [activation for _, activation in pairs]
