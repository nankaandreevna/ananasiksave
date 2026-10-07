"""Control 1 — Read-Only Group Permission Validation (audit-grade).

RO groups (local name ends with `_RO` or `ro` before @domain — with or without
underscore) must not receive write, admin, secrets-access, crypto-use,
impersonation, or IAM-policy-change capabilities.

Checks (in order) for each IAM binding on an RO group:
  1) Role name patterns (owner / editor / *admin* / …)
  2) Exact always_restricted_permissions (policy YAML)
  3) GCP permission metadata (ADMIN_WRITE, DATA_WRITE, SENSITIVE_DATA_READ)
  4) Restricted permission substrings
  5) Restricted verbs on permission last-segment (safe verbs exempt)

Positive CLI: python main.py control_1
Finding code: C1-001

Realtime inventory (gitignored, overwritten each run):
  controls_data/testenv_control_1_all_RO_groups_bindings_realtime.yaml
  controls_data/testenv_control_1_findings_realtime.yaml
Override paths: APP_CHECK_1_BINDINGS, APP_CHECK_1_FINDINGS
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from google.cloud import asset_v1
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from audit_tool.framework.config import (
    local_group_name,
    write_control_1_findings_realtime,
    write_control_1_ro_bindings_realtime,
)
from audit_tool.framework.gcp_client import (
    GcpPolicyClient,
    authorized_http,
    load_gcp_credentials,
    resolve_credentials_identity,
)
from audit_tool.framework.paths import (
    CONTROL_1_ALLOWLIST,
    CONTROL_1_FINDINGS_REALTIME,
    CONTROL_1_PERMISSIONS,
    CONTROL_1_RO_BINDINGS_REALTIME,
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


_FALLBACK_SAFE_PREDEFINED_ROLE_PATTERNS = (
    ".viewer",
    "/viewer",
    ".browser",
    "/browser",
    ".reader",
    "/reader",
)


_FALLBACK_RO_SUFFIXES = ("_RO", "ro")


@dataclass
class RoPolicy:
    readonly_suffix: str = "_RO"  # primary label for logs
    # Local-part endings before @domain (case-insensitive). Includes bare "ro"
    # for names like gcp_staging_cloudadminro@… (no underscore).
    readonly_suffixes: List[str] = field(
        default_factory=lambda: list(_FALLBACK_RO_SUFFIXES)
    )
    metadata_types: Set[str] = field(
        default_factory=lambda: {"ADMIN_WRITE", "DATA_WRITE", "SENSITIVE_DATA_READ"}
    )
    verbs: Set[str] = field(default_factory=lambda: set(_FALLBACK_VERBS))
    safe_verbs: Set[str] = field(default_factory=lambda: set(_FALLBACK_SAFE))
    permission_substrings: List[str] = field(default_factory=list)
    role_name_substrings: List[str] = field(default_factory=list)
    always_restricted: Set[str] = field(default_factory=set)
    # Predefined roles/* that are RO by GCP design (e.g. roles/cloudkms.viewer).
    safe_predefined_role_patterns: List[str] = field(
        default_factory=lambda: list(_FALLBACK_SAFE_PREDEFINED_ROLE_PATTERNS)
    )


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


def _bindings_realtime_path() -> Path:
    override = os.environ.get("APP_CHECK_1_BINDINGS", "").strip()
    if override:
        return Path(override)
    return CONTROL_1_RO_BINDINGS_REALTIME


def _findings_realtime_path() -> Path:
    override = os.environ.get("APP_CHECK_1_FINDINGS", "").strip()
    if override:
        return Path(override)
    return CONTROL_1_FINDINGS_REALTIME


def _group_email_only(member: str) -> str:
    """Strip leading group: so YAML shows email only."""
    text = (member or "").strip()
    if text.lower().startswith("group:"):
        return text.split(":", 1)[1].strip()
    return text


def _directory_ro_group_emails(suffixes: List[str]) -> List[str]:
    """All Directory group emails whose local name ends with an RO suffix."""
    try:
        gcp = GcpPolicyClient(load_policies=False)
        listed = gcp.list_all_directory_groups()
    except Exception as exc:
        logger.warning(
            "Could not list Directory groups for RO inventory (%s); "
            "logging Asset-only counts",
            exc,
        )
        return []

    emails: List[str] = []
    for item in listed:
        email = (item.get("email") or item.get("name") or "").strip().lower()
        if not email or "@" not in email:
            continue
        if is_readonly_local_name(local_group_name(email), suffixes):
            emails.append(email)
    return sorted(set(emails))


def _write_ro_bindings_realtime(
    scope: str,
    readonly_suffix: str,
    readonly_suffixes: List[str],
    bindings: List[Tuple[str, str, str]],
    directory_ro_groups: Optional[List[str]] = None,
) -> str:
    """Overwrite realtime YAML listing every *_RO group binding from Asset."""
    by_group: Dict[str, List[Dict[str, str]]] = {}
    for member, role, resource in bindings:
        by_group.setdefault(member, []).append({"role": role, "resource": resource})

    groups: List[Dict[str, Any]] = []
    for group_email in sorted(by_group.keys()):
        rows = sorted(
            by_group[group_email],
            key=lambda r: (r["role"], r["resource"]),
        )
        # De-dupe identical role+resource pairs
        seen: Set[Tuple[str, str]] = set()
        unique: List[Dict[str, str]] = []
        for row in rows:
            key = (row["role"], row["resource"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(row)
        groups.append(
            {
                "group": group_email,
                "bindings_found": len(unique),
                "bindings": unique,
            }
        )

    directory_list = directory_ro_groups or []
    binding_count = sum(g["bindings_found"] for g in groups)
    note = ""
    if not groups:
        note = (
            f"No group: members ending with {readonly_suffixes!r} appeared in any "
            "IAM binding in scope."
        )

    path = write_control_1_ro_bindings_realtime(
        path=str(_bindings_realtime_path()),
        groups=groups,
        generated_at=datetime.now(timezone.utc).isoformat(),
        scope=scope,
        readonly_suffix=readonly_suffix,
        readonly_suffixes=readonly_suffixes,
        binding_count=binding_count,
        directory_ro_groups_count=len(directory_list),
        directory_ro_groups=directory_list,
        note=note,
    )
    logger.info(
        "Wrote realtime Control 1 RO bindings inventory to %s "
        "(directory_ro=%d with_bindings=%d binding_rows=%d)",
        path,
        len(directory_list),
        len(groups),
        binding_count,
    )
    return path


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
    suffixes_env = os.environ.get("READONLY_SUFFIXES", "").strip()
    if suffixes_env:
        suffixes = [s.strip() for s in suffixes_env.split(",") if s.strip()]
    else:
        suffixes = [
            str(s).strip()
            for s in (data.get("readonly_suffixes") or [])
            if str(s).strip()
        ]
    if not suffixes:
        suffixes = [suffix] if suffix else list(_FALLBACK_RO_SUFFIXES)
    # Longest first so "_RO" wins over "ro" when both match.
    suffixes = sorted(set(suffixes), key=lambda s: (-len(s), s.lower()))
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

    safe_roles = [
        str(s).strip().lower()
        for s in (data.get("safe_predefined_role_patterns") or [])
        if str(s).strip()
    ] or list(_FALLBACK_SAFE_PREDEFINED_ROLE_PATTERNS)

    return RoPolicy(
        readonly_suffix=suffix,
        readonly_suffixes=suffixes,
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
        safe_predefined_role_patterns=safe_roles,
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


def is_readonly_local_name(local_name: str, suffixes: List[str]) -> bool:
    """True if group local-part ends with any configured RO suffix (_RO, ro, …)."""
    local_l = (local_name or "").strip().lower()
    if not local_l:
        return False
    for suffix in suffixes:
        s = (suffix or "").strip().lower()
        if s and local_l.endswith(s):
            return True
    return False


def is_readonly_group_member(member: str, suffixes) -> bool:
    """True if IAM member is group:… ending with an RO suffix before @domain."""
    local = _group_local_name(member)
    if not local:
        return False
    if isinstance(suffixes, str):
        suffixes = [suffixes]
    return is_readonly_local_name(local, list(suffixes))


def role_is_safe_readonly_predefined(role: str, policy: RoPolicy) -> bool:
    """True for predefined roles/* that are clearly read-only (viewer/browser/reader).

    Custom roles (projects/…/roles/…) are never skipped here. Skipped roles do
    not produce Control 1 / Control 5 findings even if a bundled permission
    would otherwise match a verb (e.g. generateRandomBytes on cloudkms.viewer).
    """
    r = (role or "").strip().lower()
    if not r.startswith("roles/"):
        return False
    for needle in policy.safe_predefined_role_patterns:
        if needle and needle in r:
            return True
    dotted = r.rsplit(".", 1)[-1]
    if dotted in ("viewer", "browser", "reader"):
        return True
    leaf = r.rsplit("/", 1)[-1]
    return leaf in ("viewer", "browser", "reader")


def role_name_is_restricted(role: str, policy: RoPolicy) -> Optional[str]:
    if role_is_safe_readonly_predefined(role, policy):
        return None
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
    # Exact safe verbs, or read-style compounds (listTagBindings, getIamPolicy, …).
    # always_restricted / substrings already caught getAccessToken etc. above.
    for safe in policy.safe_verbs:
        s = safe.lower()
        if action == s or action.startswith(s):
            return None
    for verb in policy.verbs:
        v = verb.lower()
        if action == v or action.startswith(v):
            return f"mutating/sensitive verb '{verb}' on {permission}"
        # compound: useToDecrypt, signBlob, generateAccessToken, …
        # Require the verb at a camelCase boundary so "bind" does not match
        # inside listTagBindings (…Tag + Bindings).
        if len(v) >= 4 and _verb_at_camel_boundary(action, v):
            return f"mutating/sensitive verb '{verb}' on {permission}"

    return None


def _verb_at_camel_boundary(action_l: str, verb_l: str) -> bool:
    """Match restricted verb as whole action or trailing compound (useToDecrypt).

    Avoids false positives like ``bind`` inside ``listTagBindings``.
    """
    if verb_l == action_l:
        return True
    if action_l.endswith(verb_l) and len(action_l) > len(verb_l):
        return True
    return False


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
    scope: str, credentials, suffixes: List[str]
) -> List[Tuple[str, str, str]]:
    """(group_member, role, resource) for every IAM binding on RO-suffixed groups."""
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
                if is_readonly_group_member(member, suffixes):
                    found.append((member, role, resource))
    logger.info("Asset IAM scan complete: %d RO group binding(s)", len(found))
    return found


def _write_findings_realtime(
    scope: str,
    binding_findings: Dict[Tuple[str, str, str], Dict[str, Any]],
) -> str:
    """Overwrite Control 1 findings YAML (failures + allowlisted with note)."""
    by_group: Dict[str, List[Dict[str, Any]]] = {}

    # item = ((member, role, resource), row_dict) — sort by the tuple key only
    for (member, _role, _resource), row in sorted(
        binding_findings.items(),
        key=lambda item: item[0],
    ):
        group = _group_email_only(member)
        violated = sorted(row.get("violated_permissions") or [])
        allowlisted_perms = sorted(row.get("allowlisted_permissions") or [])
        entry: Dict[str, Any] = {
            "role": row["role"],
            "resource": row["resource"],
            "violated_permissions": violated,
        }
        if allowlisted_perms:
            entry["allowlisted_permissions"] = allowlisted_perms
        if row.get("role_name_hit"):
            entry["role_name_hit"] = row["role_name_hit"]
        if row.get("note") == "whitelisted":
            entry["note"] = "whitelisted"
        by_group.setdefault(group, []).append(entry)

    finding_bindings = 0
    allowlisted_bindings = 0
    for entries in by_group.values():
        for entry in entries:
            is_wl = entry.get("note") == "whitelisted"
            has_fail = bool(entry.get("violated_permissions")) or (
                bool(entry.get("role_name_hit")) and not is_wl
            )
            if has_fail:
                finding_bindings += 1
            if is_wl:
                allowlisted_bindings += 1

    findings: List[Dict[str, Any]] = [
        {
            "group": group,
            "bindings_found": len(bindings_list),
            "bindings": bindings_list,
        }
        for group, bindings_list in sorted(by_group.items())
    ]

    note = ""
    if not findings:
        note = "No Control 1 findings or allowlisted restricted hits."

    path = write_control_1_findings_realtime(
        path=str(_findings_realtime_path()),
        findings=findings,
        generated_at=datetime.now(timezone.utc).isoformat(),
        scope=scope,
        finding_count=finding_bindings,
        allowlisted_count=allowlisted_bindings,
        note=note,
    )
    logger.info(
        "Wrote realtime Control 1 findings to %s "
        "(groups=%d finding_bindings=%d allowlisted_bindings=%d)",
        path,
        len(findings),
        finding_bindings,
        allowlisted_bindings,
    )
    return path


def evaluate(credentials=None) -> List[Violation]:
    policy = load_ro_policy()
    metadata_map = load_restricted_permission_map(policy)
    allowlist = load_allowlist()
    scope = resolve_audit_scope()
    credentials = credentials or load_gcp_credentials()
    iam = _iam_service(credentials)

    logger.info(
        "Control 1 RO audit: scope=%s suffixes=%s always=%d verbs=%d substrings=%d "
        "role_patterns=%d metadata_perms=%d",
        scope,
        policy.readonly_suffixes,
        len(policy.always_restricted),
        len(policy.verbs),
        len(policy.permission_substrings),
        len(policy.role_name_substrings),
        len(metadata_map),
    )

    directory_ro = _directory_ro_group_emails(policy.readonly_suffixes)
    bindings = collect_ro_group_bindings(
        scope, credentials, policy.readonly_suffixes
    )
    ro_groups = sorted({m for m, _, _ in bindings})
    binding_rows = len(bindings)

    logger.info(
        "Control 1 RO coverage: directory_ro_groups=%d "
        "ro_groups_with_bindings=%d bindings_checked=%d suffixes=%s",
        len(directory_ro),
        len(ro_groups),
        binding_rows,
        policy.readonly_suffixes,
    )
    if directory_ro:
        sample_dir = ", ".join(directory_ro[:20]) + (
            "…" if len(directory_ro) > 20 else ""
        )
        logger.info("Directory *_RO groups (%d): %s", len(directory_ro), sample_dir)
    if ro_groups:
        sample_bound = ", ".join(ro_groups[:20]) + (
            "…" if len(ro_groups) > 20 else ""
        )
        logger.info(
            "RO groups with IAM bindings checked (%d): %s",
            len(ro_groups),
            sample_bound,
        )
    else:
        logger.info("RO groups with IAM bindings checked: 0")

    without_bindings = []
    if directory_ro:
        bound_emails = {
            m.split(":", 1)[-1].strip().lower() for m in ro_groups
        }
        without_bindings = [e for e in directory_ro if e not in bound_emails]
        logger.info(
            "Directory *_RO groups with no IAM bindings (not checked as bindings): %d",
            len(without_bindings),
        )

    _write_ro_bindings_realtime(
        scope,
        policy.readonly_suffix,
        policy.readonly_suffixes,
        bindings,
        directory_ro_groups=directory_ro,
    )

    role_cache: Dict[str, List[str]] = {}
    violations: List[Violation] = []
    seen: Set[Tuple[str, str, str, str]] = set()
    allowlisted_projects: Set[str] = set()
    allowlisted_permissions: Set[str] = set()
    # (member, role, resource) -> finding row accumulator for realtime YAML
    binding_findings: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def _binding_row(member: str, role: str, resource: str) -> Dict[str, Any]:
        key = (member, role, resource)
        row = binding_findings.get(key)
        if row is None:
            row = {
                "role": role,
                "resource": resource,
                "violated_permissions": [],
                "allowlisted_permissions": [],
            }
            binding_findings[key] = row
        return row

    for member, role, resource in bindings:
        if role_is_safe_readonly_predefined(role, policy):
            continue
        name_reason = role_name_is_restricted(role, policy)
        if name_reason:
            if role_is_allowlisted(resource, role, allowlist):
                allowlisted_projects.add(_project_id(resource))
                row = _binding_row(member, role, resource)
                row["note"] = "whitelisted"
                row["role_name_hit"] = name_reason
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
                    row = _binding_row(member, role, resource)
                    row["role_name_hit"] = name_reason
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
                row = _binding_row(member, role, resource)
                if permission not in row["allowlisted_permissions"]:
                    row["allowlisted_permissions"].append(permission)
                row["note"] = "whitelisted"
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
            row = _binding_row(member, role, resource)
            if permission not in row["violated_permissions"]:
                row["violated_permissions"].append(permission)

    _write_findings_realtime(scope, binding_findings)

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
