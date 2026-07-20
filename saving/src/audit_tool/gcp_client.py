"""GCP IAM policy lookup — local or Vault credentials + Asset API."""

import logging
import os
from typing import List

import proto
from google.api_core import exceptions
from google.auth import default as google_auth_default
from google.auth import exceptions as auth_exceptions
from google.auth import impersonated_credentials
from google.cloud import asset_v1
from google.oauth2 import service_account

logger = logging.getLogger(__name__)

GCP_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
]


def _maybe_impersonate(source_credentials):
    """Optionally wrap credentials to act as a target SA (deny-test style)."""
    target = os.environ.get("GCP_IMPERSONATE_SERVICE_ACCOUNT", "").strip()
    if not target:
        return source_credentials
    logger.info("Impersonating service account %s", target)
    return impersonated_credentials.Credentials(
        source_credentials=source_credentials,
        target_principal=target,
        target_scopes=GCP_SCOPES,
        lifetime=3600,
    )


def resolve_credentials_identity(credentials) -> str:
    """Best-effort caller identity for smoke/local logging."""
    email = getattr(credentials, "service_account_email", None)
    if email:
        return email

    if isinstance(credentials, impersonated_credentials.Credentials):
        target = getattr(credentials, "_service_account_email", None) or getattr(
            credentials, "service_account_email", None
        )
        if target:
            return target

    configured = os.environ.get("GCP_IMPERSONATE_SERVICE_ACCOUNT", "").strip()
    if configured:
        return f"{configured} (GCP_IMPERSONATE_SERVICE_ACCOUNT)"

    # User ADC / unknown — ask Google who the access token belongs to
    try:
        from google.auth.transport.requests import Request
        import urllib.request

        credentials.refresh(Request())
        token = credentials.token
        if not token:
            return "unknown (no access token)"
        req = urllib.request.Request(
            f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            import json

            info = json.loads(resp.read().decode())
        return (
            info.get("email")
            or info.get("azp")
            or info.get("sub")
            or "unknown (tokeninfo had no email)"
        )
    except Exception as exc:
        logger.warning("Could not resolve credentials identity: %s", exc)
        return f"unknown ({type(credentials).__name__})"


def load_gcp_credentials():
    creds_source = os.environ.get("SOURCE_CREDENTIALS_GCP", "").upper()
    if creds_source == "LOCAL":
        key_path = os.environ["GCP_SERVICE_ACCOUNT_FILE"]
        logger.info("Loading GCP credentials from local key file")
        credentials = service_account.Credentials.from_service_account_file(
            key_path, scopes=GCP_SCOPES
        )
        return _maybe_impersonate(credentials)
    if creds_source == "ADC":
        logger.info("Loading GCP credentials from application default credentials")
        credentials, _ = google_auth_default(scopes=GCP_SCOPES)
        return _maybe_impersonate(credentials)
    if creds_source == "VAULT":
        from audit_tool.runtime import VAULT_ENV_VARS
        from vaultcreds import VaultCreds

        missing = [key for key in VAULT_ENV_VARS if not os.environ.get(key)]
        if missing:
            raise ValueError(f"Missing Vault env: {', '.join(missing)}")
        try:
            return VaultCreds(
                secret_engine_type="GCP",
                vault_env=os.environ["VAULT_ENV"],
                vault_cert_path=os.environ["CERT_FILE"],
                vault_role=os.environ["VAULT_ROLE"],
                vault_mount_point=os.environ["GCP_VAULT_MOUNT_POINT"],
                vault_login_mount_point=os.environ["VAULT_KUBERNETES_LOGIN_MOUNT_POINT"],
                namespace=os.environ["VAULT_NAMESPACE"],
                vault_brokered_role=os.environ["VAULTED_GCP_SERVICE_ACCOUNT"],
            ).get_credentials()
        except Exception as exc:
            logger.error("Failed to load GCP credentials from Vault: %s", exc)
            raise
    raise ValueError("SOURCE_CREDENTIALS_GCP must be LOCAL, ADC, or VAULT")


class GcpPolicyClient:
    """Load group IAM allow policies and check membership group bindings."""

    def __init__(self, load_policies: bool = True) -> None:
        # Group emails may use a different domain than GOOGLE_DOMAIN_NAME.
        # Set GOOGLE_GROUP_DOMAIN_NAME for Cloud Identity / IAM group lookups.
        self.group_domain = os.environ["GOOGLE_GROUP_DOMAIN_NAME"].lower()
        self.credentials = load_gcp_credentials()
        self._asset = asset_v1.AssetServiceClient(credentials=self.credentials)
        self._directory = None
        self._policies: List[dict] = []
        if not load_policies:
            return
        org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
        if not org_id or org_id.upper() == "N/A":
            raise ValueError("GOOGLE_ORG_ID env var is required")
        scope = f"organizations/{org_id}"
        logger.info("Loading IAM allow policies from %s", scope)
        self._policies = self._search_group_policies(scope)
        logger.info("Loaded %d group IAM policies", len(self._policies))

    def _group_email(self, group_name: str) -> str:
        name = group_name.strip().lower()
        if "@" in name:
            return name
        return f"{name}@{self.group_domain}"

    def group_email(self, group_name: str) -> str:
        """Resolve group name using GOOGLE_GROUP_DOMAIN_NAME when needed."""
        return self._group_email(group_name)

    def _directory_service(self):
        if self._directory is None:
            import google_auth_httplib2
            import httplib2
            from googleapiclient.discovery import build

            # Asset API often works while Directory hangs without an explicit
            # HTTP timeout (corp proxy / VPN). Default socket timeout is too vague.
            timeout_s = int(os.environ.get("GCP_DIRECTORY_TIMEOUT_SECONDS", "60"))
            http = google_auth_httplib2.AuthorizedHttp(
                self.credentials, http=httplib2.Http(timeout=timeout_s)
            )
            self._directory = build(
                "admin",
                "directory_v1",
                http=http,
                cache_discovery=False,
            )
        return self._directory

    def group_exists(self, group_name: str) -> bool:
        """True if group exists in Cloud Identity / Workspace Directory."""
        from googleapiclient.errors import HttpError

        email = self._group_email(group_name)
        logger.info("Checking Cloud Identity for group %s", email)
        try:
            self._directory_service().groups().get(groupKey=email).execute()
            logger.info("Group %s exists in Cloud Identity", email)
            return True
        except HttpError as exc:
            if exc.resp is not None and exc.resp.status == 404:
                logger.info("Group %s does not exist in Cloud Identity", email)
                return False
            logger.warning("Cloud Identity lookup failed for %s: %s", email, exc)
            raise
        except (TimeoutError, OSError) as exc:
            raise TimeoutError(
                f"Cloud Identity lookup timed out for {email}. "
                "Confirm VPN/proxy (https_proxy) is set, then retry. "
                f"Optional: export GCP_DIRECTORY_TIMEOUT_SECONDS=120. Original: {exc}"
            ) from exc

    def _search_group_policies(self, scope: str) -> List[dict]:
        results: List[dict] = []
        request = asset_v1.SearchAllIamPoliciesRequest(
            scope=scope, query="memberTypes:group", page_size=500
        )
        try:
            response = self._asset.search_all_iam_policies(request=request)
            for page in response.pages:
                for item in page.results:
                    results.append(proto.Message.to_dict(item))
        except exceptions.ServiceUnavailable as exc:
            logger.warning("GCP Asset API unavailable: %s", exc)
        except exceptions.DeadlineExceeded as exc:
            logger.warning("GCP Asset API timeout: %s", exc)
        except auth_exceptions.TransportError as exc:
            logger.warning("GCP auth/network error: %s", exc)
        except exceptions.GoogleAPICallError as exc:
            logger.warning("GCP API error: %s", exc)
        return results

    def is_group_in_any_policy(self, group_name: str) -> bool:
        group_email = self._group_email(group_name)
        member = f"group:{group_email}"
        logger.info("Checking IAM bindings for %s", member)
        for policy in self._policies:
            bindings = policy.get("policy", {}).get("bindings", [])
            for binding in bindings:
                for m in binding.get("members", []):
                    if m.casefold() == member.casefold():
                        return True
        return False
