#!/usr/bin/env python3
"""Find principals + roles that grant permissions for selected Google APIs.

Default target APIs:
  - sourcerepo.googleapis.com
  - servicedirectory.googleapis.com
  - oslogin.googleapis.com

Approach:
  1) Cloud Asset: search_all_iam_policies across an org (or folder/project scope)
  2) For each unique role on those policies, expand includedPermissions (IAM API)
  3) If the role includes sourcerepo.* / servicedirectory.* / oslogin.* → report
     every principal on that binding

Usage:
  python find_api_permission_principals.py --org YOUR_ORG_ID
  python find_api_permission_principals.py --scope organizations/YOUR_ORG_ID -o out.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Dict, List, Set, Tuple

from google.auth import default as google_auth_default
from google.cloud import asset_v1
from googleapiclient import discovery
from googleapiclient.errors import HttpError

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger("api-permission-lookup")

# API host → permission prefix(es) that mean "can use this API"
API_PERMISSION_PREFIXES: Dict[str, Tuple[str, ...]] = {
    "sourcerepo.googleapis.com": ("sourcerepo.",),
    "servicedirectory.googleapis.com": ("servicedirectory.",),
    "oslogin.googleapis.com": ("oslogin.",),
}


@dataclass
class Finding:
    api: str
    principal: str
    role: str
    resource: str
    matching_permissions: str  # semicolon-separated sample


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "List principals and roles that include permissions for "
            "sourcerepo / servicedirectory / oslogin APIs."
        )
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--org",
        help="Numeric organization ID",
    )
    g.add_argument(
        "--scope",
        help="Full Asset scope, e.g. organizations/ID or folders/ID or projects/ID",
    )
    p.add_argument(
        "--apis",
        nargs="+",
        default=list(API_PERMISSION_PREFIXES.keys()),
        help="API hosts to check (default: sourcerepo, servicedirectory, oslogin)",
    )
    p.add_argument(
        "-o",
        "--output",
        default="api_permission_principals.csv",
        help="CSV output path (default: api_permission_principals.csv)",
    )
    p.add_argument(
        "--json",
        dest="json_output",
        default="",
        help="Optional JSON output path",
    )
    p.add_argument(
        "--max-perms-shown",
        type=int,
        default=8,
        help="How many matching permission names to list per finding (default 8)",
    )
    return p.parse_args()


def resolve_scope(args: argparse.Namespace) -> str:
    if args.scope:
        return args.scope.strip()
    return f"organizations/{args.org.strip()}"


def load_credentials():
    credentials, project = google_auth_default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    quota = os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT", "").strip() or project
    if quota:
        logger.info("ADC quota/project hint: %s", quota)
    else:
        logger.warning(
            "No quota project detected. If Asset/IAM calls fail, run: "
            "gcloud auth application-default set-quota-project YOUR_PROJECT"
        )
    return credentials


def prefixes_for_apis(apis: List[str]) -> Dict[str, Tuple[str, ...]]:
    out: Dict[str, Tuple[str, ...]] = {}
    for api in apis:
        api = api.strip().lower()
        if api not in API_PERMISSION_PREFIXES:
            key = api if api.endswith(".googleapis.com") else f"{api}.googleapis.com"
            if key in API_PERMISSION_PREFIXES:
                out[key] = API_PERMISSION_PREFIXES[key]
            else:
                service = api.split(".", 1)[0]
                out[key if key.endswith(".googleapis.com") else f"{service}.googleapis.com"] = (
                    f"{service}.",
                )
                logger.warning(
                    "Unknown API %s — using permission prefix %s.*", api, service
                )
        else:
            out[api] = API_PERMISSION_PREFIXES[api]
    return out


def search_all_iam_policies(credentials, scope: str):
    """Return IAM policy search results from Cloud Asset."""
    client = asset_v1.AssetServiceClient(credentials=credentials)
    request = asset_v1.SearchAllIamPoliciesRequest(scope=scope, page_size=500)
    results = []
    logger.info("Searching IAM policies in %s …", scope)
    for item in client.search_all_iam_policies(request=request):
        results.append(item)
    logger.info("Fetched %d IAM policy resource(s)", len(results))
    return results


def iam_service(credentials):
    return discovery.build("iam", "v1", credentials=credentials, cache_discovery=False)


def get_role_permissions(iam, role_name: str, cache: Dict[str, List[str]]) -> List[str]:
    if role_name in cache:
        return cache[role_name]
    try:
        if role_name.startswith("roles/"):
            resp = iam.roles().get(name=role_name).execute()
        elif role_name.startswith("organizations/"):
            resp = iam.organizations().roles().get(name=role_name).execute()
        elif role_name.startswith("projects/"):
            resp = iam.projects().roles().get(name=role_name).execute()
        else:
            logger.warning("Skip unknown role format: %s", role_name)
            cache[role_name] = []
            return []
        perms = list(resp.get("includedPermissions") or [])
        cache[role_name] = perms
        logger.info("Expanded %s → %d permission(s)", role_name, len(perms))
        return perms
    except HttpError as exc:
        logger.error("Failed to expand role %s: %s", role_name, exc)
        cache[role_name] = []
        return []


def apis_matched_by_permissions(
    permissions: List[str],
    api_prefixes: Dict[str, Tuple[str, ...]],
) -> Dict[str, List[str]]:
    """api -> list of matching permission names."""
    matched: Dict[str, List[str]] = {}
    for api, prefixes in api_prefixes.items():
        hits = [
            p
            for p in permissions
            if any(p.startswith(pref) for pref in prefixes)
        ]
        if hits:
            matched[api] = sorted(hits)
    return matched


def collect_findings(
    policies,
    iam,
    api_prefixes: Dict[str, Tuple[str, ...]],
    max_perms_shown: int,
) -> List[Finding]:
    role_cache: Dict[str, List[str]] = {}
    role_api_map: Dict[str, Dict[str, List[str]]] = {}
    findings: List[Finding] = []
    seen: Set[Tuple[str, str, str, str]] = set()

    roles_seen: Set[str] = set()
    for item in policies:
        if not item.policy or not item.policy.bindings:
            continue
        for binding in item.policy.bindings:
            roles_seen.add(binding.role)

    logger.info("Unique roles to expand: %d", len(roles_seen))
    for role in sorted(roles_seen):
        perms = get_role_permissions(iam, role, role_cache)
        matched = apis_matched_by_permissions(perms, api_prefixes)
        if matched:
            role_api_map[role] = matched

    logger.info(
        "Roles that grant target API permissions: %d", len(role_api_map)
    )

    for item in policies:
        resource = item.resource or ""
        if not item.policy or not item.policy.bindings:
            continue
        for binding in item.policy.bindings:
            role = binding.role
            if role not in role_api_map:
                continue
            for api, perms in role_api_map[role].items():
                sample = ";".join(perms[:max_perms_shown])
                if len(perms) > max_perms_shown:
                    sample += f";…(+{len(perms) - max_perms_shown} more)"
                for member in binding.members:
                    key = (api, member, role, resource)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            api=api,
                            principal=member,
                            role=role,
                            resource=resource,
                            matching_permissions=sample,
                        )
                    )
    return findings


def write_csv(path: str, findings: List[Finding]) -> None:
    fields = ["api", "principal", "role", "resource", "matching_permissions"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in findings:
            w.writerow(asdict(row))
    logger.info("Wrote %d row(s) → %s", len(findings), path)


def write_json(path: str, findings: List[Finding], scope: str) -> None:
    payload = {
        "scope": scope,
        "apis": sorted({f.api for f in findings}),
        "count": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    logger.info("Wrote JSON → %s", path)


def summarize(findings: List[Finding]) -> None:
    by_api: Dict[str, Set[str]] = defaultdict(set)
    for f in findings:
        by_api[f.api].add(f.principal)
    print("\n=== Summary (unique principals per API) ===")
    for api in sorted(by_api):
        print(f"  {api}: {len(by_api[api])} principal(s)")
    print(f"  TOTAL rows: {len(findings)}")


def main() -> int:
    args = parse_args()
    scope = resolve_scope(args)
    api_prefixes = prefixes_for_apis(args.apis)

    logger.info("Scope: %s", scope)
    logger.info("APIs: %s", ", ".join(sorted(api_prefixes)))

    credentials = load_credentials()
    policies = search_all_iam_policies(credentials, scope)
    iam = iam_service(credentials)
    findings = collect_findings(
        policies, iam, api_prefixes, args.max_perms_shown
    )
    findings.sort(key=lambda f: (f.api, f.principal, f.role, f.resource))

    write_csv(args.output, findings)
    if args.json_output:
        write_json(args.json_output, findings, scope)
    summarize(findings)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logger.error("Failed: %s", exc)
        sys.exit(1)
