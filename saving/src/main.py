"""Entry point — run registered audit tests: smoke, control_3, ..."""

import logging
import os
import sys

from audit_tool.framework.runner import list_tests, run

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


def main() -> int:
    if len(sys.argv) < 2:
        names = ", ".join(list_tests())
        logging.error("Usage: python main.py <%s>", names)
        return 2
    return run(sys.argv[1])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logging.error("Failed: %s", exc)
        sys.exit(1)
