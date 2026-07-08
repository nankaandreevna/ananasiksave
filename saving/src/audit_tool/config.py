"""Load YAML config and read manual group pairs."""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

GroupPair = Tuple[str, str]


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Config must be a YAML mapping")
    return data


def get_group_pairs(config: Dict[str, Any]) -> List[GroupPair]:
    """Read privileged_group_pairs from config (manual list, no LDAP)."""
    pairs = config.get("privileged_group_pairs", [])
    if not pairs:
        raise ValueError("privileged_group_pairs must be a non-empty list")

    result: List[GroupPair] = []
    for item in pairs:
        membership = str(item["membership_group"]).split("@")[0].strip()
        activation_group = str(item["activation_group"]).split("@")[0].strip()
        if not membership or not activation_group:
            raise ValueError("each pair needs membership_group and activation_group")
        result.append((membership, activation_group))
    return result
