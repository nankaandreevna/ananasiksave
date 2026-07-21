"""Register and run audit tests by name."""

from typing import Callable, Dict, List

_TESTS: Dict[str, Callable[[], int]] = {}


def register(name: str) -> Callable[[Callable[[], int]], Callable[[], int]]:
    """Optional decorator — overrides auto-discovered name from filename."""

    def decorator(fn: Callable[[], int]) -> Callable[[], int]:
        register_test(name, fn)
        return fn

    return decorator


def register_test(name: str, fn: Callable[[], int]) -> None:
    if name in _TESTS:
        raise ValueError(f"Duplicate test name: {name}")
    _TESTS[name] = fn


def list_tests() -> List[str]:
    return sorted(_TESTS)


def run(name: str) -> int:
    if name not in _TESTS:
        available = ", ".join(list_tests()) or "(none)"
        raise ValueError(f"Unknown test '{name}'. Available: {available}")
    return _TESTS[name]()


def run_all(exclude: tuple = ("smoke", "smoke_negative")) -> int:
    """Run production controls: control_1, control_3, control_3_negative, …

    Smoke suites are skipped (same Control 3 checks with extra step logs).
    Each suite reads its own config env var from helm / the environment.
    """
    import logging

    names = [n for n in list_tests() if n not in exclude]
    if not names:
        raise ValueError("No tests to run (only smoke suites registered?)")

    logging.info("Running all tests: %s", ", ".join(names))
    failed = []
    for name in names:
        logging.info("=== Start %s ===", name)
        code = _TESTS[name]()
        if code != 0:
            logging.error("=== %s failed exit=%s ===", name, code)
            failed.append(name)
        else:
            logging.info("=== %s passed ===", name)

    if failed:
        logging.error("Failed tests: %s", ", ".join(failed))
        return 1
    logging.info("All tests passed: %s", ", ".join(names))
    return 0
