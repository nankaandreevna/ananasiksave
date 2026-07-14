"""Control 3 smoke run with step logging."""

import logging
import os

from audit_tool.config import get_group_pairs, load_config
from audit_tool.gcp_client import load_gcp_credentials, resolve_credentials_identity
from audit_tool.runtime import (
    get_required_env,
    resolve_smoke_config_path,
    run_control_3,
    validate_runtime,
)

_SENSITIVE_ENV = frozenset(
    {"VAULTED_GCP_SERVICE_ACCOUNT", "GCP_SERVICE_ACCOUNT_FILE"}
)


def run() -> int:
    if not os.environ.get("APP_CHECK_CONFIG"):
        os.environ["APP_CHECK_CONFIG"] = resolve_smoke_config_path()

    config_path = resolve_smoke_config_path()
    if not os.path.isfile(config_path):
        raise FileNotFoundError(
            f"Smoke config not found: {config_path}. "
            "Create controls_data/control_3_groups_smoke.yaml or set APP_CHECK_CONFIG."
        )

    logging.info("=== Smoke test start ===")

    logging.info("Smoke step 1/3: runtime environment")
    required = get_required_env()
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")
    for name in required:
        if name in _SENSITIVE_ENV:
            logging.info("  %s: set", name)
        else:
            logging.info("  %s: %s", name, os.environ.get(name))
    if os.environ.get("GCP_IMPERSONATE_SERVICE_ACCOUNT"):
        logging.info(
            "  GCP_IMPERSONATE_SERVICE_ACCOUNT: %s",
            os.environ["GCP_IMPERSONATE_SERVICE_ACCOUNT"],
        )
    if os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT"):
        logging.info(
            "  GOOGLE_CLOUD_QUOTA_PROJECT: %s",
            os.environ["GOOGLE_CLOUD_QUOTA_PROJECT"],
        )
    validate_runtime()
    logging.info("Smoke step 1/3 ok")

    logging.info("Smoke step 2/3: config %s", config_path)
    pairs = get_group_pairs(load_config(config_path))
    for membership, activation_group in pairs:
        logging.info("  pair: %s -> %s", membership, activation_group)
    logging.info("Smoke step 2/3 ok: %d group pairs", len(pairs))

    creds_mode = os.environ.get("SOURCE_CREDENTIALS_GCP", "VAULT")
    logging.info(
        "Smoke step 3/3: %s GCP credentials, Asset API, Control 3", creds_mode
    )
    credentials = load_gcp_credentials()
    identity = resolve_credentials_identity(credentials)
    logging.info("  running as: %s", identity)
    result = run_control_3(config_path)
    logging.info("=== Smoke test finished exit=%s (ran as %s) ===", result, identity)
    return result
