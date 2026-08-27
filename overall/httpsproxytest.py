#!/usr/bin/env python3
"""Check whether httplib2 can reach an HTTPS endpoint through the environment proxy.

Google API clients (googleapiclient / google-auth-httplib2) use httplib2, which
reads proxy settings from http_proxy / https_proxy rather than from requests.
This isolates that network path from application code.
"""

import argparse
import os
import sys

try:
    import httplib2
except ImportError:
    sys.exit("httplib2 is not installed. Run: python -m pip install httplib2")

DEFAULT_URLS = (
    "https://admin.googleapis.com/",
    "https://cloudidentity.googleapis.com/",
    "https://oauth2.googleapis.com/",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("urls", nargs="*", default=list(DEFAULT_URLS))
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument(
        "--ca-certs",
        help="Optional CA bundle, for a proxy that terminates TLS",
    )
    args = parser.parse_args()

    for name in ("http_proxy", "https_proxy", "no_proxy"):
        value = os.environ.get(name) or os.environ.get(name.upper())
        print(f"{name:<12} {value or '<unset>'}")

    proxy = httplib2.proxy_info_from_environment("https")
    if proxy is None:
        print("httplib2 proxy: none (direct connection)")
    else:
        print(f"httplib2 proxy: {proxy.proxy_host}:{proxy.proxy_port}")

    # httplib2 tunnels through a proxy using the socks module, and silently
    # connects directly when it is missing. Without PySocks the proxy above is
    # ignored no matter what the environment says.
    if httplib2.socks is None:
        print("socks module:   MISSING -> proxy is IGNORED (pip install PySocks)")
    else:
        print("socks module:   available -> proxy will be used")
    print("-" * 60)

    failures = 0
    for url in args.urls:
        http = httplib2.Http(timeout=args.timeout, ca_certs=args.ca_certs)
        try:
            response, _ = http.request(url)
        except Exception as exc:
            failures += 1
            print(f"FAIL {url}\n     {type(exc).__name__}: {exc}")
            continue
        # Any HTTP status proves the TCP+TLS path works; 401/404 on a bare
        # root path is normal for these APIs.
        print(f"OK   {url} -> HTTP {response.status}")

    print("-" * 60)
    print(f"{len(args.urls) - failures}/{len(args.urls)} reachable")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

# ---------------------------------------------------------------------------
# How to use
# ---------------------------------------------------------------------------
#
# 1. Install the dependencies:
#      python -m pip install httplib2 PySocks
#
#    PySocks is what lets httplib2 use a proxy at all. Install it into the same
#    environment as the application under test, then run this script from that
#    environment so the result reflects what the application sees.
#
# 2. Export the proxy settings your environment requires, for example:
#      export https_proxy=http://YOUR_PROXY_HOST:PORT
#      export http_proxy=http://YOUR_PROXY_HOST:PORT
#      export no_proxy=YOUR_INTERNAL_DOMAIN_SUFFIXES
#
# 3. Run with the default Google API endpoints:
#      python httpsproxytest.py
#
#    Or check specific hosts:
#      python httpsproxytest.py https://example.com/
#
# Reading the output:
#   socks module MISSING       -> the proxy is not being used; a proxy-only
#                                 network will then hang until the timeout
#   OK with any HTTP status    -> network path works (404/401 on a bare root
#                                 path is normal for Google API hosts)
#   timed out                  -> proxy unreachable or host blocked
#   ProxyConnectionError       -> proxy host/port wrong or refusing connections
#   CERTIFICATE_VERIFY_FAILED  -> TLS interception; retry with
#                                 --ca-certs /path/to/proxy-ca.pem
#
# Allow more time with --timeout 60.
# ---------------------------------------------------------------------------
