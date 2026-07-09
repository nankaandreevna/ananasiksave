"""Control 1 — privileged roles and external principals on IAM bindings."""

import json
import logging
import os
import re
from typing import List, Set

from google.cloud import asset_v1
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from audit_tool.gcp_client import load_gcp_credentials

logger = logging.getLogger(__name__)

from audit_tool.paths import CONTROL_1_PERMISSIONS

DEFAULT_PRIVILEGED_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
    "roles/resourcemanager.projectCreator",
    "roles/iam.admin",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/billing.admin",
    "roles/compute.admin",
    "roles/container.admin",
    "roles/cloudkms.admin",
}

DEFAULT_PRIVILEGED_PERMISSION_RE = {
    r"\.actAs.*$",
    r"\.add.*$",
    r"\.attach*$",
    r"\.bypass.*$",
    r"\.cancel.*$",
    r"\.create.*$",
    r"\.delete*$",
    r"\.detach*$",
    r"\.export*$",
    r"\.generate*$",
    r"\.import*$",
    r"\.move*$",
    r"\.override*$",
    r"\.purge.*$",
    r"\.restore.*$",
    r"\.route.*$",
    r"\.setIamPolicy*$",
    r"\.setOrgPolicy*$",
    r"\.undelete.*$",
    r"\.update*$",
    r"\.use.*$",
    r"\.unwrap.*$",
    r"\.wrap.*$",
}


def resolve_audit_scope() -> str:
    scope = os.environ.get("AUDIT_SCOPE", "").strip()
    if scope:
        return scope
    org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
    if org_id and org_id.upper() != "N/A":
        return f"organizations/{org_id}"
    raise ValueError("Set AUDIT_SCOPE or GOOGLE_ORG_ID")


def run() -> List[str]:
    scope = resolve_audit_scope()
    org_domain = os.environ["GOOGLE_DOMAIN_NAME"].lower()
    privileged_roles = get_privileged_roles()

    logger.info("Control 1 scope=%s privileged_roles=%d", scope, len(privileged_roles))

    credentials = load_gcp_credentials()
    client = asset_v1.AssetServiceClient(credentials=credentials)
    request = asset_v1.SearchAllIamPoliciesRequest(scope=scope)
    results = client.search_all_iam_policies(request=request)

    findings: List[str] = []
    total_bindings = 0

    for search_result in results:
        resource = search_result.resource
        project = search_result.project
        if not search_result.policy or not search_result.policy.bindings:
            continue

        for binding in search_result.policy.bindings:
            role = binding.role
            for member in binding.members:
                total_bindings += 1
                if ":" in member:
                    member_type, identifier = member.split(":", 1)
                else:
                    member_type, identifier = "unknown", member

                is_external = False
                if member_type in ("user", "serviceAccount", "group") and "@" in identifier:
                    domain = identifier.split("@")[-1].lower()
                    if domain != org_domain:
                        is_external = True

                if role in privileged_roles:
                    findings.append(
                        f"CRITICAL: {member} has privileged role {role} on {resource} (project={project})"
                    )
                elif is_external:
                    findings.append(
                        f"WARNING: external principal {member} has role {role} on {resource} (project={project})"
                    )

    logger.info(
        "Control 1 checked %d bindings, found %d issues",
        total_bindings,
        len(findings),
    )
    return findings


def get_privileged_roles() -> Set[str]:
    privileged_roles = set(DEFAULT_PRIVILEGED_ROLES)
    privileged_roles_env = os.environ.get("PRIVILEGED_ROLES")
    if privileged_roles_env:
        privileged_roles.update(r.strip() for r in privileged_roles_env.split(",") if r.strip())

    try:
        with open(CONTROL_1_PERMISSIONS, encoding="utf-8") as handle:
            permission_db = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not load audit metadata (%s), using regex fallback", exc)
        return get_privileged_roles_from_regex()

    admin_write_permissions = {
        entry["permission"]
        for entry in permission_db
        if entry.get("permissionType") == "ADMIN_WRITE"
    }

    for role in get_roles():
        if role.get("stage") != "GA":
            continue
        for permission in role.get("includedPermissions", []):
            if permission in admin_write_permissions:
                privileged_roles.add(role["name"])
                break

    return privileged_roles


def get_privileged_roles_from_regex() -> Set[str]:
    all_privileged_roles: Set[str] = set()
    patterns = set(DEFAULT_PRIVILEGED_PERMISSION_RE)
    extra = os.environ.get("PRIVILEGED_PERMISSION_RE")
    if extra:
        patterns.update(p.strip() for p in extra.split(",") if p.strip())

    for role in get_roles():
        if role.get("stage") != "GA":
            continue
        for permission in role.get("includedPermissions", []):
            if any(re.search(pattern, permission) for pattern in patterns):
                all_privileged_roles.add(role["name"])
                break
    return all_privileged_roles


def get_roles() -> List[dict]:
    credentials = load_gcp_credentials()
    iam_service = discovery.build("iam", "v1", credentials=credentials, cache_discovery=False)
    roles: List[dict] = []
    request = iam_service.roles().list()
    while request is not None:
        try:
            response = request.execute()
            roles.extend(response.get("roles", []))
            request = iam_service.roles().list_next(
                previous_request=request, previous_response=response
            )
        except HttpError as exc:
            logger.error("Error listing roles: %s", exc)
            break

    for role in roles:
        role["includedPermissions"] = []
        name = role["name"]
        if name.startswith("roles/"):
            request = iam_service.roles().get(name=name)
        elif name.startswith("organizations/"):
            request = iam_service.organizations().roles().get(name=name)
        elif name.startswith("projects/"):
            request = iam_service.projects().roles().get(name=name)
        else:
            continue
        try:
            response = request.execute()
            role["includedPermissions"] = response.get("includedPermissions", [])
        except HttpError as exc:
            logger.error("Error getting permissions for role %s: %s", name, exc)

    return roles
