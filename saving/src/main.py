"""Entry point — run registered audit tests: smoke, control_1, control_3, all, ..."""

import logging
import os
import sys

from audit_tool.framework.registry import run_all
from audit_tool.framework.runner import list_tests, run

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


def main() -> int:
    if len(sys.argv) < 2:
        names = ", ".join(list_tests())
        logging.error("Usage: python main.py <%s, all>", names)
        return 2
    name = sys.argv[1]
    if name == "all":
        return run_all()
    return run(name)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logging.error("Failed: %s", exc)
        sys.exit(1)
