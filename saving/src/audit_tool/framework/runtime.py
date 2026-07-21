"""Shared runtime — env validation and config path helpers (no control logic)."""

import os
from pathlib import Path
from typing import Tuple

from audit_tool.framework.paths import (
    CONTROL_3_GROUPS,
    CONTROL_3_GROUPS_NEGATIVE,
    CONTROL_3_GROUPS_SMOKE,
    CONTROL_3_GROUPS_SMOKE_NEGATIVE,
    DEPLOY_CONTROL_3_GROUPS,
    DEPLOY_CONTROL_3_GROUPS_NEGATIVE,
    DEPLOY_CONTROL_3_GROUPS_SMOKE,
    DEPLOY_CONTROL_3_GROUPS_SMOKE_NEGATIVE,
)

VAULT_ENV_VARS: Tuple[str, ...] = (
    "CERT_FILE",
    "VAULT_ENV",
    "VAULT_ROLE",
    "GCP_VAULT_MOUNT_POINT",
    "VAULT_KUBERNETES_LOGIN_MOUNT_POINT",
    "VAULT_NAMESPACE",
    "VAULTED_GCP_SERVICE_ACCOUNT",
)

LOCAL_GCP_ENV_VARS: Tuple[str, ...] = ("GCP_SERVICE_ACCOUNT_FILE",)

AUTH_REQUIRED_ENV: Tuple[str, ...] = (
    "RUNNING_ENVIRONMENT",
    "SOURCE_CREDENTIALS_GCP",
    "GOOGLE_DOMAIN_NAME",
    "GOOGLE_ORG_ID",
)

# Auth + group domain. Suite-specific YAML paths are separate env vars (below).
BASE_REQUIRED_ENV: Tuple[str, ...] = AUTH_REQUIRED_ENV + (
    "GOOGLE_GROUP_DOMAIN_NAME",
)

CREDENTIALS_SOURCES = ("LOCAL", "VAULT", "ADC")

REQUIRED_ENV = BASE_REQUIRED_ENV + VAULT_ENV_VARS

# Control 3 config env vars (one per CLI suite)
ENV_CONTROL_3 = "APP_CHECK_CONFIG"
ENV_CONTROL_3_NEGATIVE = "APP_CHECK_NEGATIVE_CONFIG"
ENV_SMOKE = "APP_CHECK_SMOKE_CONFIG"
ENV_SMOKE_NEGATIVE = "APP_CHECK_SMOKE_NEGATIVE_CONFIG"


def get_auth_required_env() -> Tuple[str, ...]:
    source = os.environ.get("SOURCE_CREDENTIALS_GCP", "").upper()
    if source == "LOCAL":
        return AUTH_REQUIRED_ENV + LOCAL_GCP_ENV_VARS
    if source == "ADC":
        return AUTH_REQUIRED_ENV
    return AUTH_REQUIRED_ENV + VAULT_ENV_VARS


def get_required_env() -> Tuple[str, ...]:
    """Auth + GOOGLE_GROUP_DOMAIN_NAME (no suite-specific config env)."""
    source = os.environ.get("SOURCE_CREDENTIALS_GCP", "").upper()
    if source == "LOCAL":
        return BASE_REQUIRED_ENV + LOCAL_GCP_ENV_VARS
    if source == "ADC":
        return BASE_REQUIRED_ENV
    return BASE_REQUIRED_ENV + VAULT_ENV_VARS


def resolve_config_path(default_path: str) -> str:
    """Legacy helper — positive Control 3 override only."""
    return os.environ.get(ENV_CONTROL_3, default_path)


def resolve_control_3_config_path() -> str:
    """Positive Control 3 — APP_CHECK_CONFIG."""
    override = os.environ.get(ENV_CONTROL_3, "").strip()
    if override:
        return override
    if os.path.isfile(DEPLOY_CONTROL_3_GROUPS):
        return DEPLOY_CONTROL_3_GROUPS
    return str(CONTROL_3_GROUPS)


def resolve_control_3_negative_config_path() -> str:
    """Negative Control 3 — APP_CHECK_NEGATIVE_CONFIG."""
    override = os.environ.get(ENV_CONTROL_3_NEGATIVE, "").strip()
    if override:
        return override
    if os.path.isfile(DEPLOY_CONTROL_3_GROUPS_NEGATIVE):
        return DEPLOY_CONTROL_3_GROUPS_NEGATIVE
    return str(CONTROL_3_GROUPS_NEGATIVE)


def resolve_smoke_config_path() -> str:
    """Positive smoke — APP_CHECK_SMOKE_CONFIG."""
    override = os.environ.get(ENV_SMOKE, "").strip()
    if override:
        return override
    if os.path.isfile(DEPLOY_CONTROL_3_GROUPS_SMOKE):
        return DEPLOY_CONTROL_3_GROUPS_SMOKE
    return str(CONTROL_3_GROUPS_SMOKE)


def resolve_smoke_negative_config_path() -> str:
    """Negative smoke — APP_CHECK_SMOKE_NEGATIVE_CONFIG."""
    override = os.environ.get(ENV_SMOKE_NEGATIVE, "").strip()
    if override:
        return override
    if os.path.isfile(DEPLOY_CONTROL_3_GROUPS_SMOKE_NEGATIVE):
        return DEPLOY_CONTROL_3_GROUPS_SMOKE_NEGATIVE
    return str(CONTROL_3_GROUPS_SMOKE_NEGATIVE)


def validate_auth_runtime() -> None:
    missing = [n for n in get_auth_required_env() if not os.environ.get(n)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")

    env = os.environ.get("RUNNING_ENVIRONMENT")
    if env not in ("LOCAL", "K8S_DEPLOY"):
        raise ValueError("RUNNING_ENVIRONMENT must be LOCAL or K8S_DEPLOY")

    source = os.environ.get("SOURCE_CREDENTIALS_GCP")
    if source not in CREDENTIALS_SOURCES:
        raise ValueError("SOURCE_CREDENTIALS_GCP must be LOCAL, ADC, or VAULT")
    if env == "K8S_DEPLOY" and source != "VAULT":
        raise ValueError("container platform deploy must use SOURCE_CREDENTIALS_GCP=VAULT")
    if source == "LOCAL":
        key = Path(os.environ["GCP_SERVICE_ACCOUNT_FILE"])
        if not key.is_file():
            raise FileNotFoundError(f"GCP service account key not found: {key}")


def validate_runtime(config_path: str = "") -> None:
    """Validate auth + group domain. Prefer passing the resolved suite config_path."""
    validate_auth_runtime()
    if not os.environ.get("GOOGLE_GROUP_DOMAIN_NAME"):
        raise ValueError("Missing env: GOOGLE_GROUP_DOMAIN_NAME")
    if config_path:
        if not os.path.isfile(config_path):
            raise FileNotFoundError(f"Config not found: {config_path}")
        return
    raise ValueError(
        "Control 3 config path required. Set the suite env var "
        f"({ENV_CONTROL_3} / {ENV_CONTROL_3_NEGATIVE} / "
        f"{ENV_SMOKE} / {ENV_SMOKE_NEGATIVE}) or use bundled defaults."
    )
