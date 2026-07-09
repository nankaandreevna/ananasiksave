"""Paths to static control data files under src/controls_data/."""

from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "controls_data"

CONTROL_1_PERMISSIONS = DATA_DIR / "control_1_permissions.json"
CONTROL_3_GROUPS = DATA_DIR / "control_3_groups.yaml"
CONTROL_3_GROUPS_SMOKE = DATA_DIR / "control_3_groups_smoke.yaml"
CONTROL_3_GROUPS_EXAMPLE = DATA_DIR / "control_3_groups.yaml.example"

# container platform: WORKDIR /apps, COPY src/ .
DEPLOY_CONTROL_3_GROUPS = "/apps/controls_data/control_3_groups.yaml"
DEPLOY_CONTROL_3_GROUPS_SMOKE = "/apps/controls_data/control_3_groups_smoke.yaml"
