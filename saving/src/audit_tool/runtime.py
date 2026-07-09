"""Shared runtime checks and Control 3 execution."""

import logging
import os
from pathlib import Path
from typing import Tuple

CONFIG_PATH = "/apps/config/app_config.yaml"
SMOKE_CONFIG_PATH = "/apps/config/app_config_smoke.yaml"
LOCAL_SMOKE_CONFIG = (
    Path(__file__).resolve().parents[1] / "config" / "app_config_smoke.yaml"
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

BASE_REQUIRED_ENV: Tuple[str, ...] = (
    "RUNNING_ENVIRONMENT",
    "SOURCE_CREDENTIALS_GCP",
    "GOOGLE_DOMAIN_NAME",
    "GOOGLE_ORG_ID",
    "APP_CHECK_CONFIG",
)

CREDENTIALS_SOURCES = ("LOCAL", "VAULT", "ADC")


def get_required_env() -> Tuple[str, ...]:
    creds_source = os.environ.get("SOURCE_CREDENTIALS_GCP", "").upper()
    if creds_source == "LOCAL":
        return BASE_REQUIRED_ENV + LOCAL_GCP_ENV_VARS
    if creds_source == "ADC":
        return BASE_REQUIRED_ENV
    return BASE_REQUIRED_ENV + VAULT_ENV_VARS


# Backward-compatible name for imports.
REQUIRED_ENV = BASE_REQUIRED_ENV + VAULT_ENV_VARS


def resolve_config_path(default_path: str) -> str:
    return os.environ.get("APP_CHECK_CONFIG", default_path)


def resolve_smoke_config_path() -> str:
    if os.environ.get("APP_CHECK_CONFIG"):
        return os.environ["APP_CHECK_CONFIG"]
    if os.path.isfile(SMOKE_CONFIG_PATH):
        return SMOKE_CONFIG_PATH
    return str(LOCAL_SMOKE_CONFIG)


def validate_required_env() -> None:
    missing = [name for name in get_required_env() if not os.environ.get(name)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")


def validate_runtime() -> None:
    validate_required_env()

    running_env = os.environ.get("RUNNING_ENVIRONMENT")
    if running_env not in ("LOCAL", "K8S_DEPLOY"):
        raise ValueError("RUNNING_ENVIRONMENT must be LOCAL or K8S_DEPLOY")

    creds_source = os.environ.get("SOURCE_CREDENTIALS_GCP")
    if creds_source not in CREDENTIALS_SOURCES:
        raise ValueError("SOURCE_CREDENTIALS_GCP must be LOCAL, ADC, or VAULT")

    if running_env == "K8S_DEPLOY" and creds_source != "VAULT":
        raise ValueError("container platform deploy must use SOURCE_CREDENTIALS_GCP=VAULT")

    if creds_source == "LOCAL":
        key_path = Path(os.environ["GCP_SERVICE_ACCOUNT_FILE"])
        if not key_path.is_file():
            raise FileNotFoundError(f"GCP service account key not found: {key_path}")


def run_control_3(config_path: str) -> int:
    validate_runtime()

    from audit_tool.control_3 import run
    from audit_tool.gcp_client import GcpPolicyClient

    logging.info("Control 3 starting, config=%s", config_path)
    gcp = GcpPolicyClient()
    violations = run(config_path, gcp)

    if violations:
        for violation in violations:
            logging.error(violation.message)
        return 1

    logging.info("Control 3 passed")
    return 0
