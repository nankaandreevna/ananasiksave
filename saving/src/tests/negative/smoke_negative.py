"""Negative Control 3 smoke — expect C3-001 violations (membership has iam bindings).

Uses APP_CHECK_SMOKE_NEGATIVE_CONFIG or control_3_groups_smoke_negative.yaml.
Does not read or overwrite APP_CHECK_CONFIG (positive).
Test passes when Control 3 finds violations; fails if the groups are clean.
"""

import logging
import os

from audit_tool.framework.config import get_group_pairs, load_config
from audit_tool.framework.gcp_client import load_gcp_credentials, resolve_credentials_identity
from audit_tool.framework.runtime import (
    get_auth_required_env,
    resolve_smoke_negative_config_path,
    validate_runtime,
)
from tests.positive.control_3 import run_with_config

NAME = "smoke_negative"

_SENSITIVE_ENV = frozenset(
    {"VAULTED_GCP_SERVICE_ACCOUNT", "GCP_SERVICE_ACCOUNT_FILE"}
)


def run() -> int:
    config_path = resolve_smoke_negative_config_path()
    if not os.path.isfile(config_path):
        raise FileNotFoundError(
            f"Negative smoke config not found: {config_path}. "
            "Create controls_data/control_3_groups_smoke_negative.yaml "
            "or set APP_CHECK_SMOKE_NEGATIVE_CONFIG."
        )

    logging.info("=== Smoke negative test start ===")

    logging.info("Smoke negative step 1/3: runtime environment")
    required = get_auth_required_env() + ("GOOGLE_GROUP_DOMAIN_NAME",)
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")
    for name in required:
        if name in _SENSITIVE_ENV:
            logging.info("  %s: set", name)
        else:
            logging.info("  %s: %s", name, os.environ.get(name))
    logging.info("  config: %s", config_path)
    validate_runtime(config_path=config_path)
    logging.info("Smoke negative step 1/3 ok")

    logging.info("Smoke negative step 2/3: config %s", config_path)
    pairs = get_group_pairs(load_config(config_path))
    for membership, activation_group in pairs:
        logging.info("  pair: %s -> %s", membership, activation_group)
    logging.info("Smoke negative step 2/3 ok: %d group pairs", len(pairs))

    creds_mode = os.environ.get("SOURCE_CREDENTIALS_GCP", "VAULT")
    logging.info(
        "Smoke negative step 3/3: %s GCP credentials, Asset API, Control 3 "
        "(expect violations)",
        creds_mode,
    )
    credentials = load_gcp_credentials()
    identity = resolve_credentials_identity(credentials)
    logging.info("  running as: %s", identity)

    control_exit = run_with_config(config_path)
    if control_exit == 0:
        logging.error(
            "Smoke negative FAILED: expected C3-001 violations but Control 3 passed "
            "(membership groups have no IAM bindings). Update "
            "control_3_groups_smoke_negative.yaml to a group that holds org IAM roles."
        )
        logging.info("=== Smoke negative finished exit=1 (ran as %s) ===", identity)
        return 1

    logging.info(
        "Smoke negative ok: Control 3 correctly reported violations (exit=%s)",
        control_exit,
    )
    logging.info("=== Smoke negative finished exit=0 (ran as %s) ===", identity)
    return 0
