"""Control 1 — Read-Only Group Permission Validation (audit-grade).

RO groups (local name ends with suffix, default `_RO`) must not receive write,
admin, secrets-access, crypto-use, impersonation, or IAM-policy-change
capabilities.

Checks (in order) for each IAM binding on an RO group:
  1) Role name patterns (owner / editor / *admin* / …)
  2) Exact always_restricted_permissions (policy YAML)
  3) GCP permission metadata (ADMIN_WRITE, DATA_WRITE, SENSITIVE_DATA_READ)
  4) Restricted permission substrings
  5) Restricted verbs on permission last-segment (safe verbs exempt)

Positive CLI: python main.py control_1
Finding code: C1-001
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml
from google.cloud import asset_v1
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from audit_tool.framework.gcp_client import (
    authorized_http,
    load_gcp_credentials,
    resolve_credentials_identity,
)
from audit_tool.framework.paths import (
    CONTROL_1_ALLOWLIST,
    CONTROL_1_PERMISSIONS,
    CONTROL_1_RO_POLICY,
)
from audit_tool.framework.runtime import validate_auth_runtime

logger = logging.getLogger(__name__)

_FALLBACK_VERBS = frozenset(
    {
        "create",
        "update",
        "delete",
        "modify",
        "add",
        "remove",
        "set",
        "patch",
        "insert",
        "write",
        "actas",
        "access",
        "decrypt",
        "encrypt",
        "setiampolicy",
    }
)

_FALLBACK_SAFE = frozenset(
    {
        "get",
        "list",
        "read",
        "view",
        "watch",
        "search",
        "check",
        "exists",
        "getiampolicy",
        "testiampermissions",
    }
)


@dataclass
class RoPolicy:
    readonly_suffix: str = "_RO"
    metadata_types: Set[str] = field(
        default_factory=lambda: {"ADMIN_WRITE", "DATA_WRITE", "SENSITIVE_DATA_READ"}
    )
    verbs: Set[str] = field(default_factory=lambda: set(_FALLBACK_VERBS))
    safe_verbs: Set[str] = field(default_factory=lambda: set(_FALLBACK_SAFE))
    permission_substrings: List[str] = field(default_factory=list)
    role_name_substrings: List[str] = field(default_factory=list)
    always_restricted: Set[str] = field(default_factory=set)


@dataclass
class AllowEntry:
    project: str
    permissions: Set[str] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)


@dataclass
class Violation:
    group_email: str
    role: str
    resource: str
    permission: str
    reason: str
    message: str


def resolve_audit_scope() -> str:
    scope = os.environ.get("APP_SCOPE", "").strip()
    if scope:
        return scope
    org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
    if org_id and org_id.upper() != "N/A":
        return f"organizations/{org_id}"
    raise ValueError("Set APP_SCOPE or GOOGLE_ORG_ID")


def _policy_path() -> Path:
    override = os.environ.get("APP_CHECK_1_POLICY", "").strip()
    if override:
        return Path(override)
    return CONTROL_1_RO_POLICY


def _permissions_db_path() -> Path:
    override = os.environ.get("APP_CHECK_1_PERMISSIONS", "").strip()
    if override:
        return Path(override)
    return CONTROL_1_PERMISSIONS


def _allowlist_path() -> Path:
    override = os.environ.get("APP_CHECK_1_ALLOWLIST", "").strip()
    if override:
        return Path(override)
    return CONTROL_1_ALLOWLIST


def load_allowlist() -> List[AllowEntry]:
    """Expected project + permission (and role-name) exceptions. Missing file = none."""
    path = _allowlist_path()
    if not path.is_file():
        logger.info("Control 1 allowlist not found (%s); no exceptions", path)
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries: List[AllowEntry] = []
    for row in data.get("whitelisted_entries") or []:
        project = str(row.get("project") or "").strip()
        if not project:
            continue
        entries.append(
            AllowEntry(
                project=project.lower(),
                permissions={
                    str(p).strip().lower()
                    for p in (row.get("permissions") or [])
                    if str(p).strip()
                },
                roles={
                    str(r).strip().lower()
                    for r in (row.get("roles") or [])
                    if str(r).strip()
                },
            )
        )
    logger.info("Loaded %d Control 1 allowlist entr(ies) from %s", len(entries), path.name)
    return entries


def _project_id(resource: str) -> str:
    text = (resource or "").strip()
    marker = "/projects/"
    if marker in text:
        return text.split(marker, 1)[1].split("/", 1)[0]
    if text.lower().startswith("projects/"):
        return text.split("/", 1)[1].split("/", 1)[0]
    return text


def _allow_entry(resource: str, allowlist: List[AllowEntry]) -> Optional[AllowEntry]:
    project = _project_id(resource).lower()
    for entry in allowlist:
        if entry.project == project:
            return entry
    return None


def permission_is_allowlisted(
    resource: str, permission: str, allowlist: List[AllowEntry]
) -> bool:
    entry = _allow_entry(resource, allowlist)
    if not entry:
        return False
    return permission.strip().lower() in entry.permissions


def role_is_allowlisted(resource: str, role: str, allowlist: List[AllowEntry]) -> bool:
    entry = _allow_entry(resource, allowlist)
    if not entry or not entry.roles:
        return False
    role_l = role.strip().lower()
    leaf = role_l.rsplit("/", 1)[-1]
    return role_l in entry.roles or leaf in entry.roles


def load_ro_policy() -> RoPolicy:
    path = _policy_path()
    if not path.is_file():
        logger.warning("RO policy file missing (%s); using built-in fallbacks", path)
        return RoPolicy()

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    suffix = os.environ.get("READONLY_SUFFIX", "").strip() or str(
        data.get("readonly_suffix") or "_RO"
    )
    verbs_env = os.environ.get("RESTRICTED_VERBS", "").strip()
    if verbs_env:
        verbs = {v.strip().lower() for v in verbs_env.split(",") if v.strip()}
    else:
        verbs = {
            str(v).strip().lower()
            for v in (data.get("restricted_verbs") or [])
            if str(v).strip()
        } or set(_FALLBACK_VERBS)

    types = {
        str(t).strip()
        for t in (data.get("metadata_restricted_types") or [])
        if str(t).strip()
    } or {"ADMIN_WRITE", "DATA_WRITE", "SENSITIVE_DATA_READ"}

    safe = {
        str(v).strip().lower()
        for v in (data.get("safe_permission_verbs") or [])
        if str(v).strip()
    } or set(_FALLBACK_SAFE)

    always = {
        str(p).strip().lower()
        for p in (data.get("always_restricted_permissions") or [])
        if str(p).strip()
    }

    return RoPolicy(
        readonly_suffix=suffix,
        metadata_types=types,
        verbs=verbs,
        safe_verbs=safe,
        permission_substrings=[
            str(s).lower()
            for s in (data.get("restricted_permission_substrings") or [])
            if str(s).strip()
        ],
        role_name_substrings=[
            str(s).lower()
            for s in (data.get("restricted_role_name_substrings") or [])
            if str(s).strip()
        ],
        always_restricted=always,
    )


def load_restricted_permission_map(policy: RoPolicy) -> Dict[str, str]:
    """permission -> reason from metadata JSON (ADMIN_WRITE / DATA_WRITE / …)."""
    path = _permissions_db_path()
    mapping: Dict[str, str] = {}
    if not path.is_file():
        logger.warning("Restricted permissions DB missing (%s)", path)
        return mapping

    rows = json.loads(path.read_text(encoding="utf-8"))
    for row in rows:
        perm = (row.get("permission") or "").strip()
        if not perm:
            continue
        ptype = (row.get("permissionType") or "").strip()
        reason = (row.get("reason") or ptype or "METADATA").strip()
        if (
            ptype in policy.metadata_types
            or reason in policy.metadata_types
            or row.get("ro_restricted")
        ):
            mapping[perm.lower()] = f"metadata:{reason}"
    logger.info(
        "Loaded %d restricted permissions from %s (types=%s)",
        len(mapping),
        path.name,
        sorted(policy.metadata_types),
    )
    return mapping


def _group_local_name(member: str) -> Optional[str]:
    if not member.lower().startswith("group:"):
        return None
    identity = member.split(":", 1)[1].strip().lower()
    return identity.split("@", 1)[0]


def is_readonly_group_member(member: str, suffix: str) -> bool:
    local = _group_local_name(member)
    if not local:
        return False
    return local.endswith(suffix.lower())


def role_name_is_restricted(role: str, policy: RoPolicy) -> Optional[str]:
    r = role.lower()
    for needle in policy.role_name_substrings:
        if needle and needle in r:
            return f"role name matches restricted pattern '{needle}'"
    leaf = r.rsplit("/", 1)[-1]
    if leaf in ("owner", "editor"):
        return f"role name {role} is privileged"
    return None


def re_access_sensitive(perm_l: str) -> bool:
    """True for secret/log/KMS-style *.access permissions, not every 'access' substring."""
    if perm_l.endswith(".access") or "versions.access" in perm_l or "views.access" in perm_l:
        return any(
            x in perm_l
            for x in (
                "secretmanager",
                "logging",
                "privatelog",
                "versions.access",
                "views.access",
            )
        )
    return "secretmanager" in perm_l and "access" in perm_l


def permission_is_restricted(
    permission: str,
    policy: RoPolicy,
    metadata_map: Dict[str, str],
) -> Optional[str]:
    perm = permission.strip()
    perm_l = perm.lower()

    # 1) Exact bank denylist
    if perm_l in policy.always_restricted:
        return f"always_restricted ({permission})"

    # 2) Explicit metadata classification
    meta = metadata_map.get(perm_l)
    if meta:
        return f"{meta} ({permission})"

    # 3) Substring denylist
    for needle in policy.permission_substrings:
        if not needle:
            continue
        if needle == ".access":
            if re_access_sensitive(perm_l):
                return f"permission substring sensitive access ({permission})"
            continue
        if needle in perm_l:
            return f"permission substring '{needle}' ({permission})"

    # 4) Verb on last segment (compound verbs like useToDecrypt)
    parts = perm_l.split(".")
    if len(parts) < 2:
        return None
    action = parts[-1]
    if action in policy.safe_verbs:
        return None
    for verb in policy.verbs:
        v = verb.lower()
        if action == v or action.startswith(v):
            return f"mutating/sensitive verb '{verb}' on {permission}"
        # compound: useToDecrypt, signBlob, generateAccessToken, …
        if len(v) >= 4 and v in action:
            return f"mutating/sensitive verb '{verb}' on {permission}"

    return None


def _iam_service(credentials):
    return discovery.build(
        "iam",
        "v1",
        http=authorized_http(credentials),
        cache_discovery=False,
    )


def get_role_permissions(iam, role_name: str) -> List[str]:
    """Fully expand predefined or custom role to includedPermissions."""
    try:
        if role_name.startswith("roles/"):
            resp = iam.roles().get(name=role_name).execute()
        elif role_name.startswith("organizations/"):
            resp = iam.organizations().roles().get(name=role_name).execute()
        elif role_name.startswith("projects/"):
            resp = iam.projects().roles().get(name=role_name).execute()
        else:
            logger.warning("Unknown role name format: %s", role_name)
            return []
        perms = list(resp.get("includedPermissions") or [])
        stage = resp.get("stage")
        title = resp.get("title")
        logger.info(
            "Role expand %s title=%r stage=%s permissions=%d",
            role_name,
            title,
            stage,
            len(perms),
        )
        return perms
    except HttpError as exc:
        logger.error("Failed to expand role %s: %s", role_name, exc)
        return []


def collect_ro_group_bindings(
    scope: str, credentials, suffix: str
) -> List[Tuple[str, str, str]]:
    """(group_member, role, resource) for every IAM binding on *_RO groups."""
    client = asset_v1.AssetServiceClient(credentials=credentials)
    request = asset_v1.SearchAllIamPoliciesRequest(
        scope=scope, query="memberTypes:group", page_size=500
    )
    found: List[Tuple[str, str, str]] = []
    for search_result in client.search_all_iam_policies(request=request):
        resource = search_result.resource
        if not search_result.policy or not search_result.policy.bindings:
            continue
        for binding in search_result.policy.bindings:
            role = binding.role
            for member in binding.members:
                if is_readonly_group_member(member, suffix):
                    found.append((member, role, resource))
    logger.info("Asset IAM scan complete: %d RO group binding(s)", len(found))
    return found


def evaluate(credentials=None) -> List[Violation]:
    policy = load_ro_policy()
    metadata_map = load_restricted_permission_map(policy)
    allowlist = load_allowlist()
    scope = resolve_audit_scope()
    credentials = credentials or load_gcp_credentials()
    iam = _iam_service(credentials)

    logger.info(
        "Control 1 RO audit: scope=%s suffix=%r always=%d verbs=%d substrings=%d "
        "role_patterns=%d metadata_perms=%d",
        scope,
        policy.readonly_suffix,
        len(policy.always_restricted),
        len(policy.verbs),
        len(policy.permission_substrings),
        len(policy.role_name_substrings),
        len(metadata_map),
    )

    bindings = collect_ro_group_bindings(scope, credentials, policy.readonly_suffix)
    ro_groups = sorted({m for m, _, _ in bindings})
    logger.info(
        "RO groups with bindings: %d (%s)",
        len(ro_groups),
        ", ".join(ro_groups[:20]) + ("…" if len(ro_groups) > 20 else ""),
    )

    role_cache: Dict[str, List[str]] = {}
    violations: List[Violation] = []
    seen: Set[Tuple[str, str, str, str]] = set()
    allowlisted_projects: Set[str] = set()
    allowlisted_permissions: Set[str] = set()

    for member, role, resource in bindings:
        name_reason = role_name_is_restricted(role, policy)
        if name_reason:
            if role_is_allowlisted(resource, role, allowlist):
                allowlisted_projects.add(_project_id(resource))
                logger.info(
                    "Allowlisted role %s on %s for %s (%s)",
                    role,
                    resource,
                    member,
                    name_reason,
                )
            else:
                key = (member, role, resource, f"role:{name_reason}")
                if key not in seen:
                    seen.add(key)
                    message = (
                        f"C1-001 - RO group {member} has restricted role {role} "
                        f"on {resource} ({name_reason})"
                    )
                    logger.info(message)
                    violations.append(
                        Violation(
                            group_email=member,
                            role=role,
                            resource=resource,
                            permission="",
                            reason=name_reason,
                            message=message,
                        )
                    )
            # Still expand to list every bad permission (detailed audit evidence)

        if role not in role_cache:
            role_cache[role] = get_role_permissions(iam, role)

        for permission in role_cache[role]:
            perm_reason = permission_is_restricted(permission, policy, metadata_map)
            if not perm_reason:
                continue
            if permission_is_allowlisted(resource, permission, allowlist):
                allowlisted_projects.add(_project_id(resource))
                allowlisted_permissions.add(permission)
                logger.info(
                    "Allowlisted permission %s via role %s on %s for %s [%s]",
                    permission,
                    role,
                    resource,
                    member,
                    perm_reason,
                )
                continue
            key = (member, role, resource, permission)
            if key in seen:
                continue
            seen.add(key)
            message = (
                f"C1-001 - RO group {member} has restricted permission "
                f"{permission} via role {role} on {resource} [{perm_reason}]"
            )
            logger.info(message)
            violations.append(
                Violation(
                    group_email=member,
                    role=role,
                    resource=resource,
                    permission=permission,
                    reason=perm_reason,
                    message=message,
                )
            )

    if violations and allowlisted_projects:
        logger.error(
            "Control 1 failed with %d finding(s). Allowlisted project %s was excluded. "
            "Review the whitelist at %s.",
            len(violations),
            ", ".join(sorted(allowlisted_projects)),
            _allowlist_path(),
        )
    elif violations:
        logger.error("Control 1 failed with %d finding(s).", len(violations))
    elif allowlisted_projects:
        project_word = "Project" if len(allowlisted_projects) == 1 else "Projects"
        project_verb = "was" if len(allowlisted_projects) == 1 else "were"
        permission_word = (
            "permission" if len(allowlisted_permissions) == 1 else "permissions"
        )
        logger.info(
            "Control 1 passed. %s %s %s allowlisted along with %s %s. "
            "Review the whitelist at %s.",
            project_word,
            ", ".join(sorted(allowlisted_projects)),
            project_verb,
            permission_word,
            ", ".join(sorted(allowlisted_permissions)),
            _allowlist_path(),
        )
    else:
        logger.info("Control 1 passed. No restricted permissions were found on RO groups.")
    return violations


def run() -> int:
    validate_auth_runtime()
    credentials = load_gcp_credentials()
    logger.info(
        "Control 1 starting (Read-Only Group Permission Validation — detailed); running as %s",
        resolve_credentials_identity(credentials),
    )
    violations = evaluate(credentials)
    if violations:
        for v in violations:
            logger.error(v.message)
        return 1
    return 0
