"""Shared runtime — env validation and config path helpers (no control logic)."""

import os
from pathlib import Path
from typing import Tuple

from audit_tool.framework.paths import (
    CONTROL_3_GROUPS_SMOKE,
    CONTROL_3_GROUPS_SMOKE_NEGATIVE,
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

BASE_REQUIRED_ENV: Tuple[str, ...] = AUTH_REQUIRED_ENV + (
    "GOOGLE_GROUP_DOMAIN_NAME",
    "APP_CHECK_CONFIG",
)

CREDENTIALS_SOURCES = ("LOCAL", "VAULT", "ADC")

REQUIRED_ENV = BASE_REQUIRED_ENV + VAULT_ENV_VARS


def get_auth_required_env() -> Tuple[str, ...]:
    source = os.environ.get("SOURCE_CREDENTIALS_GCP", "").upper()
    if source == "LOCAL":
        return AUTH_REQUIRED_ENV + LOCAL_GCP_ENV_VARS
    if source == "ADC":
        return AUTH_REQUIRED_ENV
    return AUTH_REQUIRED_ENV + VAULT_ENV_VARS


def get_required_env() -> Tuple[str, ...]:
    source = os.environ.get("SOURCE_CREDENTIALS_GCP", "").upper()
    if source == "LOCAL":
        return BASE_REQUIRED_ENV + LOCAL_GCP_ENV_VARS
    if source == "ADC":
        return BASE_REQUIRED_ENV
    return BASE_REQUIRED_ENV + VAULT_ENV_VARS


def resolve_config_path(default_path: str) -> str:
    return os.environ.get("APP_CHECK_CONFIG", default_path)


def resolve_smoke_config_path() -> str:
    if os.environ.get("APP_CHECK_CONFIG"):
        return os.environ["APP_CHECK_CONFIG"]
    if os.path.isfile(DEPLOY_CONTROL_3_GROUPS_SMOKE):
        return DEPLOY_CONTROL_3_GROUPS_SMOKE
    return str(CONTROL_3_GROUPS_SMOKE)


def resolve_smoke_negative_config_path() -> str:
    """Negative smoke config — ignores APP_CHECK_CONFIG (positive leftover)."""
    override = os.environ.get("APP_CHECK_NEGATIVE_CONFIG", "").strip()
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


def validate_runtime() -> None:
    validate_auth_runtime()
    if not os.environ.get("APP_CHECK_CONFIG"):
        raise ValueError("Missing env: APP_CHECK_CONFIG")
