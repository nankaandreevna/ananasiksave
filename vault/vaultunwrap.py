#!/usr/bin/env python3
"""Unwrap a one-time Vault response-wrapping token into an AppRole secret ID."""

import getpass
import os
import sys

import hvac
import requests

REQUIRED = ("VAULT_ADDR", "VAULT_NAMESPACE", "CERT_FILE")


def main():
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        sys.exit("Missing env: " + ", ".join(missing))

    wrapped_token = os.environ.get("VAULT_WRAPPED_TOKEN")
    if not wrapped_token:
        wrapped_token = getpass.getpass("Wrapped token (hvs...): ").strip()
    if not wrapped_token:
        sys.exit("Wrapped token is required")

    # trust_env=False: http(s)_proxy env vars would otherwise override a
    # proxies dict and route internal Vault TLS through an outbound proxy.
    cert_file = os.environ["CERT_FILE"]
    vault_session = requests.Session()
    vault_session.trust_env = False
    vault_session.verify = cert_file

    client = hvac.Client(
        url=os.environ["VAULT_ADDR"].rstrip("/"),
        token=wrapped_token,
        session=vault_session,
        namespace=os.environ["VAULT_NAMESPACE"],
    )
    response = client.sys.unwrap()

    try:
        secret_id = response["data"]["secret_id"]
    except (KeyError, TypeError):
        sys.exit("Vault unwrap response did not contain data.secret_id")

    # Keep stdout limited to the secret ID so command substitution works.
    print(secret_id)


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# How to use
# ---------------------------------------------------------------------------
#
# 1. Install the dependency:
#      python -m pip install hvac
#
# 2. Export Vault connection settings:
#      export VAULT_ADDR=https://YOUR_VAULT_URL
#      export VAULT_NAMESPACE=YOUR_VAULT_NAMESPACE
#      export CERT_FILE=/absolute/path/to/InternalCAChain.pem
#
# 3. Unwrap and export the resulting AppRole secret ID:
#      export VAULT_SECRET_ID="$(python vaultunwrap.py)"
#
#    The script securely prompts for the hvs... wrapped token.
#
# Alternative for automation:
#      export VAULT_WRAPPED_TOKEN='YOUR_WRAPPED_TOKEN'
#      export VAULT_SECRET_ID="$(python vaultunwrap.py)"
#      unset VAULT_WRAPPED_TOKEN
#
# 4. Confirm only the format, without printing the whole secret:
#      echo "${VAULT_SECRET_ID:0:8}"
#
# The wrapping token can be used only once and may have a short TTL.
# Never commit or share wrapped tokens or unwrapped secret IDs.
# ---------------------------------------------------------------------------
