"""Smoke entry point — same runtime path as rabota_tool_run.py with step logging."""

import logging
import os
import sys

from rabota_tool.config import get_group_pairs, load_config
from rabota_tool.runtime import (
    REQUIRED_ENV,
    SMOKE_CONFIG_PATH,
    resolve_config_path,
    run_control_3,
    validate_runtime,
)

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


def main() -> int:
    config_path = resolve_config_path(SMOKE_CONFIG_PATH)

    logging.info("=== Smoke test start (production code path) ===")

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
    for membership, tatata in pairs:
        logging.info("  pair: %s -> %s", membership, tatata)
    logging.info("Smoke step 2/3 ok: %d group pairs", len(pairs))

    logging.info("Smoke step 3/3: Vault credentials, GCP Asset API, Control 3")
    result = run_control_3(config_path)
    logging.info("=== Smoke test finished exit=%s ===", result)
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logging.error("Smoke test failed: %s", exc)
        sys.exit(1)
