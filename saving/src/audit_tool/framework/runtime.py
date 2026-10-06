"""Shared runtime — env validation and config path helpers (no control logic)."""

import os
from typing import Tuple

VAULT_ENV_VARS: Tuple[str, ...] = (
    "CERT_FILE",
    "VAULT_ENV",
    "VAULT_ROLE",
    "GCP_VAULT_MOUNT_POINT",
    "VAULT_KUBERNETES_LOGIN_MOUNT_POINT",
    "VAULT_NAMESPACE",
    "VAULTED_GCP_SERVICE_ACCOUNT",
)

# Local laptop Vault (AppRole + GCP static account token).
# Use when SOURCE_CREDENTIALS_GCP=VAULT and VAULT_AUTH_METHOD=approle.
VAULT_APPROLE_ENV_VARS: Tuple[str, ...] = (
    "CERT_FILE",
    "VAULT_ADDR",
    "VAULT_NAMESPACE",
    "VAULT_ROLE_ID",
    "VAULT_SECRET_ID",
    "GCP_VAULT_MOUNT_POINT",
    "VAULTED_GCP_SERVICE_ACCOUNT",
)

AUTH_REQUIRED_ENV: Tuple[str, ...] = (
    "RUNNING_ENVIRONMENT",
    "SOURCE_CREDENTIALS_GCP",
    "GOOGLE_DOMAIN_NAME",
    "GOOGLE_ORG_ID",
)

# Auth + group domain. Control 1 still has its own policy/permissions env vars.
BASE_REQUIRED_ENV: Tuple[str, ...] = AUTH_REQUIRED_ENV + (
    "GOOGLE_GROUP_DOMAIN_NAME",
)


def vault_auth_method() -> str:
    """kubernetes (cluster VaultCreds) or approle (local)."""
    explicit = os.environ.get("VAULT_AUTH_METHOD", "").strip().lower()
    if explicit:
        return explicit
    if os.environ.get("VAULT_ROLE_ID") and os.environ.get("VAULT_SECRET_ID"):
        return "approle"
    return "kubernetes"


def vault_required_env() -> Tuple[str, ...]:
    if os.environ.get("RUNNING_ENVIRONMENT") == "LOCAL":
        return VAULT_APPROLE_ENV_VARS
    if vault_auth_method() == "approle":
        return VAULT_APPROLE_ENV_VARS
    return VAULT_ENV_VARS


def get_auth_required_env() -> Tuple[str, ...]:
    return AUTH_REQUIRED_ENV + vault_required_env()


def get_required_env() -> Tuple[str, ...]:
    """Auth + GOOGLE_GROUP_DOMAIN_NAME (Vault AppRole locally, VaultCreds in cluster)."""
    return BASE_REQUIRED_ENV + vault_required_env()


def validate_auth_runtime() -> None:
    missing = [n for n in get_auth_required_env() if not os.environ.get(n)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")

    env = os.environ.get("RUNNING_ENVIRONMENT")
    if env not in ("LOCAL", "K8S_DEPLOY"):
        raise ValueError("RUNNING_ENVIRONMENT must be LOCAL or K8S_DEPLOY")

    source = os.environ.get("SOURCE_CREDENTIALS_GCP")
    if source != "VAULT":
        raise ValueError("SOURCE_CREDENTIALS_GCP must be VAULT")
    if env == "LOCAL" and vault_auth_method() != "approle":
        raise ValueError("Local runs must use Vault AppRole (VAULT_ROLE_ID / VAULT_SECRET_ID)")
    if env == "K8S_DEPLOY" and vault_auth_method() != "kubernetes":
        raise ValueError("container platform deploy must use Vault Kubernetes auth (vaultcreds)")


def validate_runtime(config_path: str = "") -> None:
    """Validate auth + group domain. Prefer passing the resolved suite config_path."""
    validate_auth_runtime()
    if not os.environ.get("GOOGLE_GROUP_DOMAIN_NAME"):
        raise ValueError("Missing env: GOOGLE_GROUP_DOMAIN_NAME")
    if config_path:
        if not os.path.isfile(config_path):
            raise FileNotFoundError(f"Config not found: {config_path}")
        return
    raise ValueError("Control config path required.")
