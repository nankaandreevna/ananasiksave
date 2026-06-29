"""Production entry point — runs in OpenShift only (LIGHTSPEED + Vault)."""

import logging
import os
import sys

from rabota_tool.runtime import PROD_CONFIG_PATH, resolve_config_path, run_control_3

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


def main() -> int:
    return run_control_3(resolve_config_path(PROD_CONFIG_PATH))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logging.error("Failed: %s", exc)
        sys.exit(1)
