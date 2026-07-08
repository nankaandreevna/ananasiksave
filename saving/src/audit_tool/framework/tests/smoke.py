"""Control 3 smoke run with step logging."""

import logging
import os

from audit_tool.config import get_group_pairs, load_config
from audit_tool.runtime import (
    REQUIRED_ENV,
    SMOKE_CONFIG_PATH,
    run_control_3,
    validate_runtime,
)


def run() -> int:
    config_path = SMOKE_CONFIG_PATH

    logging.info("=== Smoke test start ===")

    logging.info("Smoke step 1/3: runtime environment")
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise ValueError(f"Missing env: {', '.join(missing)}")
    for name in REQUIRED_ENV:
        if name == "VAULTED_GCP_SERVICE_ACCOUNT":
            logging.info("  %s: set", name)
        else:
            logging.info("  %s: %s", name, os.environ.get(name))
    validate_runtime()
    logging.info("Smoke step 1/3 ok")

    logging.info("Smoke step 2/3: config %s", config_path)
    pairs = get_group_pairs(load_config(config_path))
    for membership, activation_group in pairs:
        logging.info("  pair: %s -> %s", membership, activation_group)
    logging.info("Smoke step 2/3 ok: %d group pairs", len(pairs))

    logging.info("Smoke step 3/3: Vault credentials, GCP Asset API, Control 3")
    result = run_control_3(config_path)
    logging.info("=== Smoke test finished exit=%s ===", result)
    return result
