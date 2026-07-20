"""Auto-discover and register audit tests from tests/positive and tests/negative."""

import importlib
import pkgutil
from typing import Callable

from audit_tool.framework.registry import register_test

_TEST_PACKAGES = (
    "tests.positive",
    "tests.negative",
)


def discover_tests() -> None:
    """Import every module under tests/{positive,negative}/ and register run()."""
    for package_name in _TEST_PACKAGES:
        package = importlib.import_module(package_name)
        for module_info in pkgutil.iter_modules(package.__path__):
            name = module_info.name
            if name.startswith("_"):
                continue

            module = importlib.import_module(f"{package_name}.{name}")
            run_fn: Callable[[], int] = getattr(module, "run", None)
            if not callable(run_fn):
                continue

            test_name = getattr(module, "NAME", name)
            register_test(test_name, run_fn)
