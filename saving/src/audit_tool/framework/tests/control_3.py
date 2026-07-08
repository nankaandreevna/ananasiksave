"""Control 3 main run."""

from audit_tool.runtime import CONFIG_PATH, resolve_config_path, run_control_3


def run() -> int:
    return run_control_3(resolve_config_path(CONFIG_PATH))
