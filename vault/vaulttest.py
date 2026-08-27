#!/usr/bin/env python3
"""Standalone Vault AppRole and GCP static-account connectivity test."""

import os
import sys

import hvac
import requests

REQUIRED = (
    "VAULT_ADDR",
    "VAULT_NAMESPACE",
    "CERT_FILE",
    "VAULT_ROLE_ID",
    "VAULT_SECRET_ID",
    "GCP_VAULT_MOUNT_POINT",
    "VAULT_GCP_STATIC_ACCOUNT",
)


def main():
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        sys.exit("Missing env: " + ", ".join(missing))

    vault_url = os.environ["VAULT_ADDR"].rstrip("/")
    namespace = os.environ["VAULT_NAMESPACE"]
    cert_file = os.environ["CERT_FILE"]
    role_id = os.environ["VAULT_ROLE_ID"]
    secret_id = os.environ["VAULT_SECRET_ID"]
    mount_point = os.environ["GCP_VAULT_MOUNT_POINT"]
    static_account = os.environ["VAULT_GCP_STATIC_ACCOUNT"]

    # trust_env=False: http(s)_proxy env vars would otherwise override a
    # proxies dict and route internal Vault TLS through an outbound proxy.
    vault_session = requests.Session()
    vault_session.trust_env = False
    vault_session.verify = cert_file

    print(f"url={vault_url} namespace={namespace} cert={cert_file}")
    print(f"mount={mount_point} account={static_account}")

    client = hvac.Client(
        url=vault_url,
        session=vault_session,
        namespace=namespace,
    )
    client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    if not client.is_authenticated():
        sys.exit("AppRole login failed (not authenticated)")
    print("AppRole login OK")

    response = client.secrets.gcp.generate_static_account_oauth2_access_token(
        name=static_account,
        mount_point=mount_point,
    )
    token = response["data"]["token"]
    print(f"GCP token OK (len={len(token)})")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# How to use
# ---------------------------------------------------------------------------
#
# 1. Install the dependency:
#      python -m pip install hvac
#
# 2. Save your organization's CA chain locally, for example:
#      /absolute/path/to/InternalCAChain.pem
#
# 3. Export the required values in your current shell:
#
#      export VAULT_ADDR=https://YOUR_VAULT_URL
#      export VAULT_NAMESPACE=YOUR_VAULT_NAMESPACE
#      export CERT_FILE=/absolute/path/to/InternalCAChain.pem
#      export VAULT_ROLE_ID=YOUR_ROLE_ID
#      export VAULT_SECRET_ID=YOUR_SECRET_ID
#      export GCP_VAULT_MOUNT_POINT=YOUR_GCP_MOUNT_POINT
#      export VAULT_GCP_STATIC_ACCOUNT=YOUR_VAULT_STATIC_ACCOUNT_NAME
#
#    VAULT_GCP_STATIC_ACCOUNT is the Vault static-account name, not the
#    service account email address.
#
# 4. Run:
#      python vaulttest.py
#
# Expected output:
#      AppRole login OK
#      GCP token OK (len=...)
#
# Never commit role IDs, secret IDs, access tokens, or private CA material.
# ---------------------------------------------------------------------------
