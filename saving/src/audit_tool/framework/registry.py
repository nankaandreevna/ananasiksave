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
