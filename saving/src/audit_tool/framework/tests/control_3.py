"""Control 3 main run."""

from audit_tool.paths import DEPLOY_CONTROL_3_GROUPS
from audit_tool.runtime import resolve_config_path, run_control_3


def run() -> int:
    return run_control_3(resolve_config_path(DEPLOY_CONTROL_3_GROUPS))
