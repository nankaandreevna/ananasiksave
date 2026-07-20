"""Shared runtime — env validation and control runners."""

import logging
import os
from pathlib import Path
from typing import Tuple

from audit_tool.paths import (
    CONTROL_3_GROUPS,
    CONTROL_3_GROUPS_SMOKE,
    DEPLOY_CONTROL_3_GROUPS,
    DEPLOY_CONTROL_3_GROUPS_SMOKE,
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


def run_control_3(config_path: str) -> int:
    validate_runtime()
    from audit_tool.control_3 import run
    from audit_tool.gcp_client import GcpPolicyClient

    logging.info("Control 3 starting, config=%s", config_path)
    violations = run(config_path, GcpPolicyClient())
    if violations:
        for v in violations:
            logging.error(v.message)
        return 1
    logging.info("Control 3 passed")
    return 0


def run_control_1() -> int:
    validate_auth_runtime()
    from audit_tool.control_1 import run

    logging.info("Control 1 starting")
    findings = run()
    if findings:
        for msg in findings:
            logging.error(msg)
        return 1
    logging.info("Control 1 passed")
    return 0
