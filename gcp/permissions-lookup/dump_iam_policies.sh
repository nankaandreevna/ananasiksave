#!/usr/bin/env bash
# Optional helper: dump IAM policies with gcloud (review manually or feed elsewhere).
# Prefer find_uncertified_api_principals.py for the full principal/role/API report.
set -euo pipefail

ORG_ID="${1:?Usage: $0 <ORG_ID> [output.json]}"
OUT="${2:-iam_policies_org_${ORG_ID}.json}"

echo "Searching IAM policies for organizations/${ORG_ID} → ${OUT}"
gcloud asset search-all-iam-policies \
  --scope="organizations/${ORG_ID}" \
  --format=json > "${OUT}"

echo "Done. Rows: $(python3 -c "import json; print(len(json.load(open('${OUT}'))))" 2>/dev/null || echo '?')"
echo "Next: run find_uncertified_api_principals.py --org ${ORG_ID}"
