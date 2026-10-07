"""Control 5 — Non-privileged service accounts must not hold privileged IAM.

Service accounts marked privileged=false (GCP label and/or Resource Manager
tag) must not receive write, admin, secrets, impersonation, or IAM-policy-
change capability. Same "not read-only" definition as Control 1 (policy YAML
+ permissions JSON).

Foundation IaC often stores ``privileged: "false"`` as a **label** on the SA
resource; Asset Inventory ``tags`` is a list of Tag messages (not a map).

Positive CLI: python main.py control_5
Finding code: C5-001

Realtime findings (gitignored, overwritten each run) — violators only:
  controls_data/testenv_control_5_findings_realtime.yaml
Override path: APP_CHECK_5_FINDINGS
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from google.cloud import asset_v1
from google.protobuf import field_mask_pb2

from audit_controls.control_1 import (
    AllowEntry,
    get_role_permissions,
    load_restricted_permission_map,
    load_ro_policy,
    permission_is_allowlisted,
    permission_is_restricted,
    resolve_audit_scope,
    role_is_safe_readonly_predefined,
    _iam_service,
    _project_id,
)
from audit_tool.framework.config import write_control_5_findings_realtime
from audit_tool.framework.gcp_client import (
    load_gcp_credentials,
    resolve_credentials_identity,
)
from audit_tool.framework.paths import (
    CONTROL_5_ALLOWLIST,
    CONTROL_5_FINDINGS_REALTIME,
    CONTROL_5_SA_POLICY,
)
from audit_tool.framework.runtime import validate_auth_runtime

logger = logging.getLogger(__name__)

SA_ASSET_TYPE = "iam.googleapis.com/ServiceAccount"


@dataclass
class SaTagPolicy:
    tag_key: str = "privileged"
    tag_value: str = "false"
    # Foundation SA YAML ``privileged:`` usually lands as a GCP label.
    match_labels: bool = True
    match_tags: bool = True


@dataclass
class Violation:
    service_account: str
    role: str
    resource: str
    permission: str
    reason: str
    message: str
    tag: str = ""
    tag_source: str = ""


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


def _findings_path() -> Path:
    """Realtime findings YAML path (overwritten each run; env override)."""
    override = os.environ.get("APP_CHECK_5_FINDINGS", "").strip()
    if override:
        return Path(override)
    return CONTROL_5_FINDINGS_REALTIME


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

    def _bool_opt(env_name: str, yaml_key: str, default: bool) -> bool:
        raw = os.environ.get(env_name, "").strip().lower()
        if raw in ("1", "true", "yes", "on"):
            return True
        if raw in ("0", "false", "no", "off"):
            return False
        if yaml_key in data and data.get(yaml_key) is not None:
            return bool(data.get(yaml_key))
        return default

    return SaTagPolicy(
        tag_key=key,
        tag_value=str(value),
        match_labels=_bool_opt("APP_CHECK_5_MATCH_LABELS", "match_labels", True),
        match_tags=_bool_opt("APP_CHECK_5_MATCH_TAGS", "match_tags", True),
    )


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


def _key_value_match(key_text: str, value_text: str, key: str, value: str) -> bool:
    """Match short or namespaced tag/label key and value."""
    key_l = key.lower()
    value_l = value.lower()
    kt = (key_text or "").lower()
    vt = (value_text or "").lower()
    key_ok = (
        kt == key_l
        or kt.endswith("/" + key_l)
        or kt.endswith("/tagkeys/" + key_l)
        or kt.rsplit("/", 1)[-1] == key_l
    )
    value_ok = (
        vt == value_l
        or vt.endswith("/" + value_l)
        or vt.endswith("/tagvalues/" + value_l)
        or vt.rsplit("/", 1)[-1] == value_l
    )
    return key_ok and value_ok


def _tag_map_match(pairs: dict, key: str, value: str) -> bool:
    if not pairs:
        return False
    for tag_key, tag_value in pairs.items():
        if _key_value_match(str(tag_key), str(tag_value), key, value):
            return True
    return False


def _map_field_as_dict(raw) -> dict:
    """Normalize a protobuf map / dict field to {str: str}."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if hasattr(raw, "items"):
        try:
            return {str(k): str(v) for k, v in raw.items()}
        except (TypeError, ValueError):
            return {}
    return {}


def _attached_tags_as_dict(result) -> dict:
    """Build key→value from Asset ``tags`` (list of Tag) or legacy tag_keys/values.

    Modern Asset Inventory returns ``tags`` as repeated Tag messages
    (``tag_key`` / ``tag_value``). Calling ``dict(tags)`` raises TypeError;
    treating it as a map via ``.items()`` yields an empty dict and silent
    zero matches.
    """
    out: dict = {}
    raw_tags = getattr(result, "tags", None)
    if raw_tags:
        # Legacy map shape (older clients)
        if isinstance(raw_tags, dict) or (
            hasattr(raw_tags, "items")
            and not hasattr(raw_tags, "append")
            and not isinstance(raw_tags, (list, tuple))
        ):
            try:
                maybe = {str(k): str(v) for k, v in raw_tags.items()}
                # Map values should be strings, not Tag messages
                if maybe and all(
                    not hasattr(v, "tag_key") and not hasattr(v, "tag_value")
                    for v in maybe.values()
                ):
                    out.update(maybe)
            except (TypeError, ValueError):
                pass
        for item in list(raw_tags):
            if isinstance(item, dict):
                k = item.get("tag_key") or item.get("tagKey") or ""
                v = item.get("tag_value") or item.get("tagValue") or ""
            else:
                k = getattr(item, "tag_key", None) or getattr(item, "tagKey", None) or ""
                v = (
                    getattr(item, "tag_value", None)
                    or getattr(item, "tagValue", None)
                    or ""
                )
            if k:
                out[str(k)] = str(v)

    keys = list(getattr(result, "tag_keys", None) or [])
    vals = list(getattr(result, "tag_values", None) or [])
    if keys and vals and len(keys) == len(vals):
        for k, v in zip(keys, vals):
            out[str(k)] = str(v)
    elif keys:
        for k in keys:
            out.setdefault(str(k), "")
    return out


def _effective_tags_match(effective_tags, key: str, value: str) -> bool:
    if not effective_tags:
        return False
    for item in effective_tags:
        if isinstance(item, dict):
            ns_key = str(
                item.get("namespaced_tag_key") or item.get("namespacedTagKey") or ""
            )
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
        if _key_value_match(ns_key, ns_val or attached, key, value):
            return True
    return False


def _first_matching_pair(pairs: dict, key: str, value: str) -> Optional[Tuple[str, str]]:
    for tag_key, tag_value in pairs.items():
        if _key_value_match(str(tag_key), str(tag_value), key, value):
            return str(tag_key), str(tag_value)
    return None


def resolve_sa_marker(result, policy: SaTagPolicy) -> Optional[Dict[str, str]]:
    """Return marker metadata if SA is privileged=false (label and/or RM tag)."""
    key = policy.tag_key
    value = policy.tag_value
    if policy.match_labels:
        labels = _map_field_as_dict(getattr(result, "labels", None))
        hit = _first_matching_pair(labels, key, value)
        if hit:
            raw_key, raw_value = hit
            return {
                "tag": f"{key}={value}",
                "tag_source": "label",
                "raw_key": raw_key,
                "raw_value": raw_value,
            }
    if policy.match_tags:
        tags = _attached_tags_as_dict(result)
        hit = _first_matching_pair(tags, key, value)
        if hit:
            raw_key, raw_value = hit
            return {
                "tag": f"{key}={value}",
                "tag_source": "tag",
                "raw_key": raw_key,
                "raw_value": raw_value,
            }
        effective = list(getattr(result, "effective_tags", None) or [])
        if _effective_tags_match(effective, key, value):
            return {
                "tag": f"{key}={value}",
                "tag_source": "effective_tag",
                "raw_key": key,
                "raw_value": value,
            }
    return None


def sa_matches_non_privileged_marker(result, policy: SaTagPolicy) -> bool:
    """True if SA has privileged=false as a label and/or Resource Manager tag."""
    return resolve_sa_marker(result, policy) is not None


def _sa_email_from_result(result) -> Optional[str]:
    email = _sa_email_from_resource_name(getattr(result, "name", "") or "")
    if email:
        return email
    display = (getattr(result, "display_name", "") or "").strip().lower()
    if "@" in display:
        return display
    # additional_attributes.email on some Asset SA results
    attrs = getattr(result, "additional_attributes", None)
    if attrs:
        if isinstance(attrs, dict):
            extra = str(attrs.get("email") or "").strip().lower()
        else:
            # Struct / MapComposite
            try:
                extra = str(attrs.get("email") or "").strip().lower()
            except Exception:
                extra = ""
        if "@" in extra:
            return extra
    return None


def collect_non_privileged_service_accounts(
    scope: str, credentials, policy: SaTagPolicy
) -> Dict[str, Dict[str, str]]:
    """Return email → marker info for SAs marked privileged=false."""
    client = asset_v1.AssetServiceClient(credentials=credentials)
    # Include effective_tags explicitly (not always in the default mask).
    read_mask = field_mask_pb2.FieldMask(
        paths=[
            "name",
            "display_name",
            "labels",
            "tags",
            "tag_keys",
            "tag_values",
            "effective_tags",
            "additional_attributes",
        ]
    )

    # Prefer server-side filter (labels from foundation YAML; tags if bound).
    queries: List[str] = []
    if policy.match_labels:
        queries.append(f"labels.{policy.tag_key}:{policy.tag_value}")
    if policy.match_tags:
        queries.append(f"tagKeys:{policy.tag_key}")
        queries.append(f"effectiveTagKeys:{policy.tag_key}")

    found: Dict[str, Dict[str, str]] = {}
    scanned = 0
    with_labels = 0
    with_tags = 0
    seen_names: Set[str] = set()

    def _consume(result) -> None:
        nonlocal scanned, with_labels, with_tags
        name = getattr(result, "name", "") or ""
        if name in seen_names:
            return
        seen_names.add(name)
        scanned += 1
        labels = _map_field_as_dict(getattr(result, "labels", None))
        tags = _attached_tags_as_dict(result)
        effective = list(getattr(result, "effective_tags", None) or [])
        if labels:
            with_labels += 1
        if tags or effective:
            with_tags += 1
        marker = resolve_sa_marker(result, policy)
        if not marker:
            return
        email = _sa_email_from_result(result)
        if email and email not in found:
            found[email] = marker

    # Query-scoped searches first (fast path when markers exist in Asset).
    for query in queries:
        request = asset_v1.SearchAllResourcesRequest(
            scope=scope,
            asset_types=[SA_ASSET_TYPE],
            query=query,
            page_size=500,
            read_mask=read_mask,
        )
        try:
            for result in client.search_all_resources(request=request):
                _consume(result)
        except Exception as exc:
            logger.warning(
                "Asset SA query %r failed (%s); continuing", query, exc
            )

    # Full SA scan fallback when queries returned nothing (query syntax /
    # indexing gaps) so we still evaluate labels/tags client-side.
    if not found:
        request = asset_v1.SearchAllResourcesRequest(
            scope=scope,
            asset_types=[SA_ASSET_TYPE],
            page_size=500,
            read_mask=read_mask,
        )
        for result in client.search_all_resources(request=request):
            _consume(result)

    logger.info(
        "Asset SA scan complete: %d service account(s) with %s=%s "
        "(scanned=%d with_labels=%d with_tags=%d match_labels=%s match_tags=%s)",
        len(found),
        policy.tag_key,
        policy.tag_value,
        scanned,
        with_labels,
        with_tags,
        policy.match_labels,
        policy.match_tags,
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
        "Control 5 SA audit: scope=%s marker=%s=%s labels=%s tags=%s "
        "always=%d verbs=%d metadata_perms=%d",
        scope,
        tag_policy.tag_key,
        tag_policy.tag_value,
        tag_policy.match_labels,
        tag_policy.match_tags,
        len(ro_policy.always_restricted),
        len(ro_policy.verbs),
        len(metadata_map),
    )

    sa_markers = collect_non_privileged_service_accounts(
        scope, credentials, tag_policy
    )
    sa_emails = set(sa_markers.keys())
    if sa_emails:
        sample = ", ".join(sorted(sa_emails)[:20])
        if len(sa_emails) > 20:
            sample += "…"
        logger.info("Non-privileged SAs in scope: %d (%s)", len(sa_emails), sample)
    else:
        logger.info(
            "No service accounts matched %s=%s",
            tag_policy.tag_key,
            tag_policy.tag_value,
        )

    bindings = collect_sa_bindings(scope, credentials, sa_emails)
    role_cache: Dict[str, List[str]] = {}
    violations: List[Violation] = []
    seen: Set[Tuple[str, str, str, str]] = set()
    allowlisted_projects: Set[str] = set()
    allowlisted_permissions: Set[str] = set()

    def _marker_for_member(member: str) -> Dict[str, str]:
        email = member.split(":", 1)[-1].strip().lower()
        return sa_markers.get(email) or {
            "tag": f"{tag_policy.tag_key}={tag_policy.tag_value}",
            "tag_source": "unknown",
            "raw_key": tag_policy.tag_key,
            "raw_value": tag_policy.tag_value,
        }

    for member, role, resource in bindings:
        # Predefined RO roles (roles/*.viewer etc.) — same skip as Control 1.
        if role_is_safe_readonly_predefined(role, ro_policy):
            continue
        # Scope is marker-only (privileged=false). Do not fail on role name
        # patterns — only expanded permissions decide privileged vs not.
        if role not in role_cache:
            role_cache[role] = get_role_permissions(iam, role)
        marker = _marker_for_member(member)

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
                    tag=marker.get("tag", ""),
                    tag_source=marker.get("tag_source", ""),
                )
            )

    findings_path = _write_findings_realtime(
        scope=scope,
        tag_policy=tag_policy,
        violations=violations,
    )
    logger.info("Wrote realtime Control 5 findings to %s", findings_path)

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


def _write_findings_realtime(
    scope: str,
    tag_policy: SaTagPolicy,
    violations: List[Violation],
) -> str:
    """Overwrite Control 5 realtime YAML with violation findings only."""
    generated_at = datetime.now(timezone.utc).isoformat()

    # Group violated permissions under (SA, tag, role, resource)
    grouped: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for v in violations:
        gkey = (v.service_account, v.tag, v.role, v.resource)
        row = grouped.get(gkey)
        if row is None:
            row = {
                "service_account": v.service_account,
                "tag": v.tag,
                "role": v.role,
                "resource": v.resource,
                "permissions": [],
            }
            grouped[gkey] = row
        if v.permission not in row["permissions"]:
            row["permissions"].append(v.permission)

    findings = list(grouped.values())
    for row in findings:
        row["permissions"] = sorted(row["permissions"])

    note = ""
    if not findings:
        note = (
            f"No Control 5 violations for SAs marked "
            f"{tag_policy.tag_key}={tag_policy.tag_value}."
        )

    return write_control_5_findings_realtime(
        path=str(_findings_path()),
        findings=findings,
        generated_at=generated_at,
        scope=scope,
        marker_key=tag_policy.tag_key,
        marker_value=tag_policy.tag_value,
        note=note,
    )


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
