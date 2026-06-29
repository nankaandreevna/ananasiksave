"""Shared runtime checks and Control 3 execution for prod and smoke entry points."""

import logging
import os
from typing import Tuple

PROD_CONFIG_PATH = "/apps/config/rabota_control_3.yaml"
SMOKE_CONFIG_PATH = "/apps/config/rabota_control_3_smoke.yaml"

VAULT_ENV_VARS: Tuple[str, ...] = (
    "CERT_FILE",
    "VAULT_ENV",
    "VAULT_ROLE",
    "GCP_VAULT_MOUNT_POINT",
    "VAULT_KUBERNETES_LOGIN_MOUNT_POINT",
    "VAULT_NAMESPACE",
    "VAULTED_GCP_SERVICE_ACCOUNT",
)

REQUIRED_ENV: Tuple[str, ...] = (
    "RUNNING_ENVIRONMENT",
    "SOURCE_CREDENTIALS_GCP",
    "GOOGLE_DOMAIN_NAME",
    "GOOGLE_ORG_ID",
    "RABOTA_CONTROL_3_CONFIG",
    *VAULT_ENV_VARS,
)


def resolve_config_path(default_path: str) -> str:
    return os.environ.get("RABOTA_CONTROL_3_CONFIG", default_path)


def validate_required_env() -> None:
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")


def validate_runtime() -> None:
    validate_required_env()
    if os.environ.get("RUNNING_ENVIRONMENT") != "LIGHTSPEED":
        raise ValueError("Must run in OpenShift (RUNNING_ENVIRONMENT=LIGHTSPEED)")
    if os.environ.get("SOURCE_CREDENTIALS_GCP") != "VAULT":
        raise ValueError("Must use Vault credentials (SOURCE_CREDENTIALS_GCP=VAULT)")


def run_control_3(config_path: str) -> int:
    validate_runtime()

    from rabota_tool.control_3 import run
    from rabota_tool.gcp_client import GcpPolicyClient

    logging.info("Control 3 starting, config=%s", config_path)
    gcp = GcpPolicyClient()
    violations = run(config_path, gcp)

    if violations:
        for violation in violations:
            logging.error(violation.message)
        return 1

    logging.info("Control 3 passed")
    return 0
