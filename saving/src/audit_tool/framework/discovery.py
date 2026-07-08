"""Auto-discover and register audit tests from framework/tests/*.py."""

import importlib
import pkgutil
from typing import Callable

from audit_tool.framework.registry import register_test

_PACKAGE = "audit_tool.framework.tests"


def discover_tests() -> None:
    """Import every module in framework/tests/ and register its run() function."""
    package = importlib.import_module(_PACKAGE)
    package_path = package.__path__

    for module_info in pkgutil.iter_modules(package_path):
        name = module_info.name
        if name.startswith("_"):
            continue

        module = importlib.import_module(f"{_PACKAGE}.{name}")
        run_fn: Callable[[], int] = getattr(module, "run", None)
        if not callable(run_fn):
            continue

        test_name = getattr(module, "NAME", name)
        register_test(test_name, run_fn)
