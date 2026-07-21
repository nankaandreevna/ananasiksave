"""Negative Control 3 — expect C3-001 violations on configured pairs.

Uses APP_CHECK_NEGATIVE_CONFIG or controls_data/control_3_groups_negative.yaml.
Does not read or overwrite APP_CHECK_CONFIG (positive).
Test passes when Control 3 finds violations; fails if the groups are clean.
"""

import logging
import os

from audit_tool.framework.runtime import resolve_control_3_negative_config_path
from tests.positive.control_3 import run_with_config

NAME = "control_3_negative"


def run() -> int:
    config_path = resolve_control_3_negative_config_path()
    if not os.path.isfile(config_path):
        raise FileNotFoundError(
            f"Negative Control 3 config not found: {config_path}. "
            "Create controls_data/control_3_groups_negative.yaml "
            "or set APP_CHECK_NEGATIVE_CONFIG."
        )

    logging.info("Control 3 negative starting, config=%s (expect violations)", config_path)
    control_exit = run_with_config(config_path)
    if control_exit == 0:
        logging.error(
            "Control 3 negative FAILED: expected C3-001 violations but Control 3 passed. "
            "Update control_3_groups_negative.yaml to a membership group that holds "
            "org IAM roles."
        )
        return 1

    logging.info(
        "Control 3 negative ok: correctly reported violations (control exit=%s)",
        control_exit,
    )
    return 0
