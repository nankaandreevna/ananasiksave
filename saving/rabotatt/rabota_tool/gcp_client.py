"""GCP crpa policy lookup — standalone, no external sync dependencies."""

import logging
import os
from typing import List

import proto
from google.api_core import exceptions
from google.auth import exceptions as auth_exceptions
from google.cloud import asset_v1
from vaultcreds import VaultCreds

logger = logging.getLogger(__name__)


class GcpPolicyClient:
    """Load group IAM allow policies and check membership group bindings."""

    def __init__(self) -> None:
        self.domain = os.environ["GOOGLE_DOMAIN_NAME"].lower()
        self.credentials = self._load_vault_credentials()
        self._asset = asset_v1.AssetServiceClient(credentials=self.credentials)
        org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
        if not org_id or org_id.upper() == "N/A":
            raise ValueError("GOOGLE_ORG_ID env var is required")
        scope = f"organizations/{org_id}"
        logger.info("Loading crpa allow policies from %s", scope)
        self._policies = self._search_group_policies(scope)
        logger.info("Loaded %d group IAM policies", len(self._policies))

    def _load_vault_credentials(self):
        from rabota_tool.runtime import VAULT_ENV_VARS

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
        group_email = f"{group_name.lower()}@{self.domain}"
        member = f"group:{group_email}"
        for policy in self._policies:
            bindings = policy.get("policy", {}).get("bindings", [])
            for binding in bindings:
                for m in binding.get("members", []):
                    if m.casefold() == member.casefold():
                        return True
        return False
