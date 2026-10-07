"""Control 5 — Non-privileged service accounts must not hold privileged IAM.

Service accounts with Resource Manager tag privileged=false must not receive
write, admin, secrets, impersonation, or IAM-policy-change capability. Same
"not read-only" definition as Control 1 (policy YAML + permissions JSON).
GCP resource labels are not used.

Positive CLI: python main.py control_5
Finding code: C5-001
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml
from google.cloud import asset_v1

from audit_controls.control_1 import (
    AllowEntry,
    get_role_permissions,
    load_restricted_permission_map,
    load_ro_policy,
    permission_is_allowlisted,
    permission_is_restricted,
    resolve_audit_scope,
    _iam_service,
    _project_id,
)
from audit_tool.framework.gcp_client import (
    load_gcp_credentials,
    resolve_credentials_identity,
)
from audit_tool.framework.paths import CONTROL_5_ALLOWLIST, CONTROL_5_SA_POLICY
from audit_tool.framework.runtime import validate_auth_runtime

logger = logging.getLogger(__name__)

SA_ASSET_TYPE = "iam.googleapis.com/ServiceAccount"


@dataclass
class SaTagPolicy:
    tag_key: str = "privileged"
    tag_value: str = "false"


@dataclass
class Violation:
    service_account: str
    role: str
    resource: str
    permission: str
    reason: str
    message: str


def _sa_policy_path() -> Path:
    override = os.environ.get("APP_CHECK_5_POLICY", "").strip()
    if override:
        return Path(override)
    return CONTROL_5_SA_POLICY


def _allowlist_path() -> Path:
    override = os.environ.get("APP_CHECK_5_ALLOWLIST", "").strip()
    if override:
        return Path(override)
    return CONTROL_5_ALLOWLIST


def load_sa_tag_policy() -> SaTagPolicy:
    path = _sa_policy_path()
    data: dict = {}
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    else:
        logger.warning("Control 5 SA policy missing (%s); using defaults", path)

    key = (
        os.environ.get("APP_CHECK_5_TAG_KEY", "").strip()
        or str(data.get("tag_key") or "privileged")
    )
    value = (
        os.environ.get("APP_CHECK_5_TAG_VALUE", "").strip()
        or str(data.get("tag_value") if data.get("tag_value") is not None else "false")
    )
    return SaTagPolicy(tag_key=key, tag_value=str(value))


def load_allowlist() -> List[AllowEntry]:
    path = _allowlist_path()
    if not path.is_file():
        logger.info("Control 5 allowlist not found (%s); no exceptions", path)
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
    logger.info(
        "Loaded %d Control 5 allowlist entr(ies) from %s", len(entries), path.name
    )
    return entries


def _sa_email_from_resource_name(name: str) -> Optional[str]:
    """Extract SA email from Asset name //iam.googleapis.com/projects/.../serviceAccounts/EMAIL."""
    text = (name or "").strip()
    marker = "/serviceAccounts/"
    if marker not in text:
        return None
    email = text.split(marker, 1)[1].strip().lower()
    if "@" not in email:
        return None
    return email


def _tag_map_match(tags: dict, key: str, value: str) -> bool:
    """Match Asset `tags` map (namespaced keys/values or short names)."""
    if not tags:
        return False
    key_l = key.lower()
    value_l = value.lower()
    for tag_key, tag_value in tags.items():
        key_text = str(tag_key).lower()
        value_text = str(tag_value).lower()
        key_ok = key_text == key_l or key_text.endswith("/" + key_l) or key_text.endswith(
            "/tagkeys/" + key_l
        )
        value_ok = (
            value_text == value_l
            or value_text.endswith("/" + value_l)
            or value_text.endswith("/tagvalues/" + value_l)
            or value_text.rsplit("/", 1)[-1] == value_l
        )
        if key_ok and value_ok:
            return True
    return False


def _effective_tags_match(effective_tags, key: str, value: str) -> bool:
    if not effective_tags:
        return False
    key_l = key.lower()
    value_l = value.lower()
    for item in effective_tags:
        # proto message or dict after conversion
        if isinstance(item, dict):
            ns_key = str(item.get("namespaced_tag_key") or item.get("namespacedTagKey") or "")
            ns_val = str(
                item.get("namespaced_tag_value") or item.get("namespacedTagValue") or ""
            )
            attached = str(
                item.get("attached_tag_value") or item.get("attachedTagValue") or ""
            )
        else:
            ns_key = str(getattr(item, "namespaced_tag_key", "") or "")
            ns_val = str(getattr(item, "namespaced_tag_value", "") or "")
            attached = str(getattr(item, "attached_tag_value", "") or "")
        key_text = ns_key.lower()
        value_text = (ns_val or attached).lower()
        key_ok = (
            key_text == key_l
            or key_text.endswith("/" + key_l)
            or key_text.rsplit("/", 1)[-1] == key_l
        )
        value_ok = (
            value_text == value_l
            or value_text.endswith("/" + value_l)
            or value_text.rsplit("/", 1)[-1] == value_l
        )
        if key_ok and value_ok:
            return True
    return False


def sa_matches_non_privileged_tag(result, policy: SaTagPolicy) -> bool:
    """True if this Asset SA result has Resource Manager tag privileged=false."""
    key = policy.tag_key
    value = policy.tag_value
    tags = dict(getattr(result, "tags", None) or {})
    effective = list(getattr(result, "effective_tags", None) or [])
    return _tag_map_match(tags, key, value) or _effective_tags_match(
        effective, key, value
    )


def collect_non_privileged_service_accounts(
    scope: str, credentials, policy: SaTagPolicy
) -> Set[str]:
    """Return SA emails that carry Resource Manager tag privileged=false."""
    client = asset_v1.AssetServiceClient(credentials=credentials)
    request = asset_v1.SearchAllResourcesRequest(
        scope=scope,
        asset_types=[SA_ASSET_TYPE],
        page_size=500,
    )
    found: Set[str] = set()
    for result in client.search_all_resources(request=request):
        if not sa_matches_non_privileged_tag(result, policy):
            continue
        email = _sa_email_from_resource_name(getattr(result, "name", "") or "")
        if not email:
            # Fallback: display_name is sometimes the email for SAs
            display = (getattr(result, "display_name", "") or "").strip().lower()
            if "@" in display:
                email = display
        if email:
            found.add(email)
    logger.info(
        "Asset SA scan complete: %d service account(s) with %s=%s",
        len(found),
        policy.tag_key,
        policy.tag_value,
    )
    return found


def collect_sa_bindings(
    scope: str, credentials, sa_emails: Set[str]
) -> List[Tuple[str, str, str]]:
    """(serviceAccount:email, role, resource) for IAM bindings on tagged SAs."""
    if not sa_emails:
        return []
    wanted = {f"serviceaccount:{email.lower()}" for email in sa_emails}
    client = asset_v1.AssetServiceClient(credentials=credentials)
    request = asset_v1.SearchAllIamPoliciesRequest(
        scope=scope, query="memberTypes:serviceAccount", page_size=500
    )
    found: List[Tuple[str, str, str]] = []
    for search_result in client.search_all_iam_policies(request=request):
        resource = search_result.resource
        if not search_result.policy or not search_result.policy.bindings:
            continue
        for binding in search_result.policy.bindings:
            role = binding.role
            for member in binding.members:
                if member.strip().lower() in wanted:
                    found.append((member, role, resource))
    logger.info(
        "Asset IAM scan complete: %d binding(s) on privileged=false service accounts",
        len(found),
    )
    return found


def evaluate(credentials=None) -> List[Violation]:
    # Permission rules — same "not RO" logic as Control 1
    ro_policy = load_ro_policy()
    metadata_map = load_restricted_permission_map(ro_policy)
    allowlist = load_allowlist()
    tag_policy = load_sa_tag_policy()
    scope = resolve_audit_scope()
    credentials = credentials or load_gcp_credentials()
    iam = _iam_service(credentials)

    logger.info(
        "Control 5 SA audit: scope=%s tag=%s=%s always=%d verbs=%d metadata_perms=%d",
        scope,
        tag_policy.tag_key,
        tag_policy.tag_value,
        len(ro_policy.always_restricted),
        len(ro_policy.verbs),
        len(metadata_map),
    )

    sa_emails = collect_non_privileged_service_accounts(scope, credentials, tag_policy)
    if sa_emails:
        sample = ", ".join(sorted(sa_emails)[:20])
        if len(sa_emails) > 20:
            sample += "…"
        logger.info("Non-privileged SAs in scope: %d (%s)", len(sa_emails), sample)
    else:
        logger.info("No service accounts matched %s=%s", tag_policy.tag_key, tag_policy.tag_value)

    bindings = collect_sa_bindings(scope, credentials, sa_emails)
    role_cache: Dict[str, List[str]] = {}
    violations: List[Violation] = []
    seen: Set[Tuple[str, str, str, str]] = set()
    allowlisted_projects: Set[str] = set()
    allowlisted_permissions: Set[str] = set()

    for member, role, resource in bindings:
        # Scope is tag-only (privileged=false). Do not fail on role name
        # patterns — only expanded permissions decide privileged vs not.
        if role not in role_cache:
            role_cache[role] = get_role_permissions(iam, role)

        for permission in role_cache[role]:
            perm_reason = permission_is_restricted(permission, ro_policy, metadata_map)
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
                f"C5-001 - Non-privileged SA {member} has restricted permission "
                f"{permission} via role {role} on {resource} [{perm_reason}]"
            )
            logger.info(message)
            violations.append(
                Violation(
                    service_account=member,
                    role=role,
                    resource=resource,
                    permission=permission,
                    reason=perm_reason,
                    message=message,
                )
            )

    if violations and allowlisted_projects:
        logger.error(
            "Control 5 failed with %d finding(s). Allowlisted project %s was excluded. "
            "Review the whitelist at %s.",
            len(violations),
            ", ".join(sorted(allowlisted_projects)),
            _allowlist_path(),
        )
    elif violations:
        logger.error("Control 5 failed with %d finding(s).", len(violations))
    elif allowlisted_projects:
        project_word = "Project" if len(allowlisted_projects) == 1 else "Projects"
        project_verb = "was" if len(allowlisted_projects) == 1 else "were"
        permission_word = (
            "permission" if len(allowlisted_permissions) == 1 else "permissions"
        )
        logger.info(
            "Control 5 passed. %s %s %s allowlisted along with %s %s. "
            "Review the whitelist at %s.",
            project_word,
            ", ".join(sorted(allowlisted_projects)),
            project_verb,
            permission_word,
            ", ".join(sorted(allowlisted_permissions)),
            _allowlist_path(),
        )
    else:
        logger.info(
            "Control 5 passed. No privileged permissions on service accounts "
            "tagged %s=%s.",
            tag_policy.tag_key,
            tag_policy.tag_value,
        )
    return violations


def run() -> int:
    validate_auth_runtime()
    credentials = load_gcp_credentials()
    logger.info(
        "Control 5 starting (non-privileged SA permission validation); running as %s",
        resolve_credentials_identity(credentials),
    )
    violations = evaluate(credentials)
    if violations:
        for v in violations:
            logger.error(v.message)
        return 1
    return 0
