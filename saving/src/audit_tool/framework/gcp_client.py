"""GCP IAM policy lookup — Vault credentials + Asset API."""

import logging
import os
from typing import List

import proto
from google.api_core import exceptions
from google.auth import exceptions as auth_exceptions
from google.cloud import asset_v1

logger = logging.getLogger(__name__)

GCP_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
]

# Admin Directory — group read (smoke list-all + Control 3 group exists).
# Vault SA with domain-wide delegation / Directory role must allow this scope.
DIRECTORY_GROUP_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.group.readonly"
)

ALL_SCOPES = GCP_SCOPES + [DIRECTORY_GROUP_SCOPE]


def _with_directory_scopes(credentials):
    """Attach Directory group scope when the credential type supports it."""
    if not hasattr(credentials, "with_scopes"):
        return credentials
    try:
        return credentials.with_scopes(ALL_SCOPES)
    except Exception as exc:
        logger.warning(
            "Could not attach Directory scopes to credentials (%s); "
            "Directory calls may fail unless Vault token already includes them",
            exc,
        )
        return credentials


def authorized_http(credentials):
    """httplib2 client for googleapiclient (IAM, Directory, Cloud Identity).

    Uses the Vault access token. Corp proxy only works if PySocks is installed.
    """
    import google_auth_httplib2
    import httplib2

    if httplib2.socks is None and (
        os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    ):
        logger.warning(
            "https_proxy is set but PySocks is missing, so Google API calls "
            "will ignore the proxy. Install it: pip install PySocks"
        )

    timeout_s = int(os.environ.get("GCP_DIRECTORY_TIMEOUT_SECONDS", "60"))
    return google_auth_httplib2.AuthorizedHttp(
        credentials, http=httplib2.Http(timeout=timeout_s)
    )


def resolve_credentials_identity(credentials) -> str:
    """Best-effort caller identity for smoke/local logging."""
    email = getattr(credentials, "service_account_email", None)
    if email:
        return email

    # Vault brokered token — ask Google who the token belongs to
    try:
        import json
        import urllib.request

        # A Vault brokered token is a bare access token with no refresh
        # material, so only refresh when there is nothing to introspect.
        token = getattr(credentials, "token", None)
        if not token:
            from google.auth.transport.requests import Request

            credentials.refresh(Request())
            token = credentials.token
        if not token:
            return "unknown (no access token)"

        req = urllib.request.Request(
            f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            info = json.loads(resp.read().decode())

        # Scopes decide Directory access, so surface them next to the identity:
        # 403 insufficient scopes vs 403 forbidden are different root causes.
        logger.info("Access token scopes: %s", info.get("scope") or "(none reported)")
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
    if creds_source != "VAULT":
        raise ValueError("SOURCE_CREDENTIALS_GCP must be VAULT")
    from audit_tool.framework.runtime import vault_auth_method, vault_required_env

    missing = [key for key in vault_required_env() if not os.environ.get(key)]
    if missing:
        raise ValueError(f"Missing Vault env: {', '.join(missing)}")
    if vault_auth_method() == "approle":
        return _load_vault_approle_gcp_credentials()
    return _load_vaultcreds_gcp_credentials()


def _load_vaultcreds_gcp_credentials():
    """Cluster deploy: VaultCreds + Kubernetes auth."""
    from audit_tool.framework.paths import resolve_cert_file
    from vaultcreds import VaultCreds

    cert_file = resolve_cert_file()
    try:
        logger.info(
            "Loading GCP credentials via VaultCreds (CERT_FILE=%s, brokered_role=%s)",
            cert_file,
            os.environ.get("VAULTED_GCP_SERVICE_ACCOUNT"),
        )
        credentials = VaultCreds(
            secret_engine_type="GCP",
            vault_env=os.environ["VAULT_ENV"],
            vault_cert_path=cert_file,
            vault_role=os.environ["VAULT_ROLE"],
            vault_mount_point=os.environ["GCP_VAULT_MOUNT_POINT"],
            vault_login_mount_point=os.environ["VAULT_KUBERNETES_LOGIN_MOUNT_POINT"],
            namespace=os.environ["VAULT_NAMESPACE"],
            vault_brokered_role=os.environ["VAULTED_GCP_SERVICE_ACCOUNT"],
        ).get_credentials()
        return _with_directory_scopes(credentials)
    except Exception as exc:
        logger.error("Failed to load GCP credentials from VaultCreds: %s", exc)
        raise


def _load_vault_approle_gcp_credentials():
    """Local Vault: AppRole login + GCP static-account OAuth2 token.

    Requires hvac. CERT_FILE is the Internal CA chain PEM under src/.
    """
    import hvac
    from google.oauth2.credentials import Credentials

    from audit_tool.framework.paths import resolve_cert_file

    vault_addr = os.environ["VAULT_ADDR"].rstrip("/")
    cert_file = resolve_cert_file()
    if not os.path.isfile(cert_file):
        raise FileNotFoundError(
            f"CERT_FILE not found: {cert_file}. "
            "Paste the chain into src/InternalCAChain_UAT.pem."
        )
    if os.path.getsize(cert_file) == 0:
        raise ValueError(
            f"CERT_FILE is empty: {cert_file}. "
            "Paste the Internal CA chain PEM into that file before running."
        )

    # requests lets http(s)_proxy env vars override a session's proxies dict,
    # so trust_env=False is required to keep internal Vault TLS off the corp
    # proxy. Scoped to Vault only; Google API calls still use the proxy.
    import requests

    vault_session = requests.Session()
    vault_session.trust_env = False
    vault_session.verify = cert_file

    namespace = os.environ["VAULT_NAMESPACE"]
    mount = os.environ["GCP_VAULT_MOUNT_POINT"]
    roleset = os.environ["VAULTED_GCP_SERVICE_ACCOUNT"]

    logger.info(
        "Loading GCP credentials via Vault AppRole "
        "(addr=%s, cert=%s, namespace=%s, mount=%s, roleset=%s)",
        vault_addr,
        cert_file,
        namespace,
        mount,
        roleset,
    )
    try:
        client = hvac.Client(
            url=vault_addr,
            session=vault_session,
            namespace=namespace,
        )
        client.auth.approle.login(
            role_id=os.environ["VAULT_ROLE_ID"],
            secret_id=os.environ["VAULT_SECRET_ID"],
        )
        if not client.is_authenticated():
            raise RuntimeError("Vault AppRole login failed (not authenticated)")

        response = client.secrets.gcp.generate_static_account_oauth2_access_token(
            name=roleset,
            mount_point=mount,
        )
        token = response["data"]["token"]
        credentials = Credentials(token=token)
        return _with_directory_scopes(credentials)
    except Exception as exc:
        logger.error("Failed to load GCP credentials via Vault AppRole: %s", exc)
        raise


class GcpPolicyClient:
    """Load group IAM allow policies and check membership group bindings."""

    def __init__(self, load_policies: bool = True) -> None:
        # Group emails come from GOOGLE_GROUP_DOMAIN_NAME, not GOOGLE_DOMAIN_NAME.
        # Control 1 reads full group: members from Asset and does not rewrite domain.
        # Current env (testenv) is @testenv.example. A later org/SA will use
        # @example.com by changing only this env var — do not hardcode it here.
        self.group_domain = os.environ["GOOGLE_GROUP_DOMAIN_NAME"].lower()
        self.credentials = load_gcp_credentials()
        self._asset = asset_v1.AssetServiceClient(credentials=self.credentials)
        self._directory = None
        self._cloudidentity = None
        self._policies: List[dict] = []
        if load_policies:
            self.load_allow_policies()

    def load_allow_policies(self) -> None:
        """Load org IAM allow policies (group members) via Cloud Asset."""
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

    def _authorized_http(self):
        return authorized_http(self.credentials)

    def _directory_service(self):
        if self._directory is None:
            from googleapiclient.discovery import build

            self._directory = build(
                "admin",
                "directory_v1",
                http=self._authorized_http(),
                cache_discovery=False,
            )
        return self._directory

    def _cloudidentity_service(self):
        if self._cloudidentity is None:
            from googleapiclient.discovery import build

            self._cloudidentity = build(
                "cloudidentity",
                "v1",
                http=self._authorized_http(),
                cache_discovery=False,
            )
        return self._cloudidentity

    def list_group_user_memberships(self, group_name: str) -> List[dict]:
        """List USER memberships with createTime / optional expireTime (Control 2).

        Uses Cloud Identity groups.memberships (Admin Directory members.list has
        no createTime — insufficient for TEALAS 24h expiry).
        Returns dicts: email, create_time, expire_time (optional).
        """
        from googleapiclient.errors import HttpError

        email = self._group_email(group_name)
        logger.info("Listing Cloud Identity memberships for %s", email)
        try:
            lookup = (
                self._cloudidentity_service()
                .groups()
                .lookup(groupKey_id=email)
                .execute()
            )
            parent = lookup.get("name")
            if not parent:
                raise RuntimeError(f"Cloud Identity lookup returned no name for {email}")

            members: List[dict] = []
            request = (
                self._cloudidentity_service()
                .groups()
                .memberships()
                .list(parent=parent)
            )
            while request is not None:
                response = request.execute()
                for item in response.get("memberships", []):
                    member_type = (item.get("type") or "").upper()
                    if member_type and member_type not in (
                        "USER",
                        "MEMBERSHIP_TYPE_UNSPECIFIED",
                    ):
                        continue
                    key = item.get("preferredMemberKey") or item.get("memberKey") or {}
                    member_email = (key.get("id") or "").strip().lower()
                    if not member_email or "@" not in member_email:
                        continue
                    expire_time = None
                    for role in item.get("roles") or []:
                        detail = role.get("expiryDetail") or {}
                        if detail.get("expireTime"):
                            expire_time = detail["expireTime"]
                            break
                    members.append(
                        {
                            "email": member_email,
                            "create_time": item.get("createTime"),
                            "expire_time": expire_time,
                        }
                    )
                request = (
                    self._cloudidentity_service()
                    .groups()
                    .memberships()
                    .list_next(previous_request=request, previous_response=response)
                )
            logger.info(
                "Found %d user memberships in %s", len(members), email
            )
            return members
        except HttpError as exc:
            status = getattr(exc.resp, "status", None)
            if status == 404:
                raise FileNotFoundError(
                    f"Activation group not found in Cloud Identity: {email}"
                ) from exc
            if status in (401, 403):
                raise PermissionError(
                    f"Cloud Identity memberships denied for {email} (HTTP {status}). "
                    "Needs Groups Admin / Cloud Identity access (Vault SA or DWD). "
                    f"Original: {exc}"
                ) from exc
            raise
        except (TimeoutError, OSError) as exc:
            raise TimeoutError(
                f"Cloud Identity memberships timed out for {email}. "
                "Confirm VPN/proxy (https_proxy). "
                f"Optional: export GCP_DIRECTORY_TIMEOUT_SECONDS=120. Original: {exc}"
            ) from exc

    def _resourcemanager_service(self):
        from googleapiclient.discovery import build

        return build(
            "cloudresourcemanager",
            "v3",
            http=self._authorized_http(),
            cache_discovery=False,
        )

    def check_gcp_api_access(self) -> List[dict]:
        """Probe GCP APIs the audit role already grants (smoke pre-check).

        Runs before any Directory call so a Workspace authorisation problem can
        be told apart from a dead token or blocked network: these probes reuse
        the same credentials, and Resource Manager reuses the same httplib2
        transport that Directory uses.
        """
        from googleapiclient.errors import HttpError

        org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
        if not org_id or org_id.upper() == "N/A":
            raise ValueError("GOOGLE_ORG_ID env var is required")
        scope = f"organizations/{org_id}"
        checks: List[dict] = []

        def record(permission, call):
            try:
                checks.append({"permission": permission, "ok": True, "detail": call()})
            except HttpError as exc:
                status = getattr(exc.resp, "status", None)
                checks.append(
                    {
                        "permission": permission,
                        "ok": False,
                        "detail": f"HTTP {status}: {exc}",
                    }
                )
            except Exception as exc:
                checks.append(
                    {
                        "permission": permission,
                        "ok": False,
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )

        def get_organization():
            org = self._resourcemanager_service().organizations().get(name=scope).execute()
            return org.get("displayName") or org.get("name") or scope

        def search_resources():
            request = asset_v1.SearchAllResourcesRequest(scope=scope, page_size=1)
            first = next(iter(self._asset.search_all_resources(request=request)), None)
            return getattr(first, "name", None) or "(no resources returned)"

        logger.info("Checking GCP API access at %s", scope)
        record("resourcemanager.organizations.get", get_organization)
        record("cloudasset.assets.searchAllResources", search_resources)

        for check in checks:
            logger.info(
                "  %s %s: %s",
                "ok  " if check["ok"] else "FAIL",
                check["permission"],
                check["detail"],
            )
        return checks

    def list_all_directory_groups(self) -> List[dict]:
        """List Workspace groups via Admin Directory groups.list.

        Prefers groups().list(domain=GOOGLE_GROUP_DOMAIN_NAME) so the current
        env lists groups on that domain. GOOGLE_CUSTOMER_ID is only a fallback
        (later org). Returns list of dicts: email, name, id — emails are
        written as returned.
        """
        from googleapiclient.errors import HttpError

        domain = os.environ.get("GOOGLE_GROUP_DOMAIN_NAME", "").strip()
        customer = os.environ.get("GOOGLE_CUSTOMER_ID", "").strip()
        if not domain and not customer:
            raise ValueError(
                "GOOGLE_GROUP_DOMAIN_NAME (or GOOGLE_CUSTOMER_ID) is required "
                "to list Directory groups"
            )

        list_filter = {"domain": domain} if domain else {"customer": customer}
        logger.info(
            "Listing all Directory groups (%s) via admin.directory_v1",
            ", ".join(f"{k}={v}" for k, v in list_filter.items()),
        )
        groups: List[dict] = []
        page_token = None
        max_results = int(os.environ.get("APP_DIRECTORY_PAGE_SIZE", "200"))
        try:
            while True:
                request = {
                    **list_filter,
                    "maxResults": max_results,
                    "orderBy": "email",
                }
                if page_token:
                    request["pageToken"] = page_token
                results = (
                    self._directory_service()
                    .groups()
                    .list(**request)
                    .execute()
                )
                for item in results.get("groups", []):
                    groups.append(
                        {
                            "email": (item.get("email") or "").strip().lower(),
                            "name": item.get("name") or "",
                            "id": item.get("id") or "",
                        }
                    )
                page_token = results.get("nextPageToken")
                if not page_token:
                    break
        except HttpError as exc:
            status = getattr(exc.resp, "status", None)
            if status in (401, 403):
                # Two different root causes share HTTP 403 here: the token
                # lacking the Directory scope (Vault token_scopes) versus the
                # SA lacking an Admin console role for this customer.
                if "insufficient authentication scopes" in str(exc).lower():
                    hint = (
                        "the access token is missing "
                        f"{DIRECTORY_GROUP_SCOPE}; add it to the Vault "
                        "static account token_scopes"
                    )
                else:
                    hint = (
                        "the token has the Directory scope but the service "
                        "account is not authorised for this Workspace — check "
                        "its Admin console role assignment and that "
                        "GOOGLE_GROUP_DOMAIN_NAME is the domain this SA can read"
                    )
                raise PermissionError(
                    f"Directory groups.list denied (HTTP {status}): {hint}. "
                    f"Original: {exc}"
                ) from exc
            raise
        except (TimeoutError, OSError) as exc:
            raise TimeoutError(
                "Directory groups.list timed out. Confirm VPN/proxy "
                "(https_proxy) and that PySocks is installed, otherwise "
                f"httplib2 ignores the proxy. Original: {exc}"
            ) from exc

        logger.info("Directory groups.list complete: %d group(s)", len(groups))
        return groups

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
            status = getattr(exc.resp, "status", None)
            if status in (401, 403):
                raise PermissionError(
                    f"Cloud Identity lookup denied for {email} (HTTP {status}). "
                    "Use the vaulted audit SA with Directory/Groups read "
                    f"(CERT_FILE + Vault). Original: {exc}"
                ) from exc
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
