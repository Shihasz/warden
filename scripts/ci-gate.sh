#!/usr/bin/env bash
# The supply-chain gate step of CI: picks the policy for this kind of run
# and enforces it.
#
# Pushes and tags always get the strict policy, so a missing OIDC token
# there fails closed. A pull_request run may drop to a named,
# no-provenance policy only because GitHub withholds OIDC tokens from fork
# and Dependabot PRs, so provenance can't exist for them. The switch is
# announced in the log and in the job summary.
set -euo pipefail

: "${EVENT_NAME:?EVENT_NAME is required}"
: "${OIDC_AVAILABLE:?OIDC_AVAILABLE is required}"
WARDEN="${WARDEN:-./bin/warden}"

policy=warden-policy.yaml
attest_args=(
  --attestation bin/warden.intoto.jsonl
  --pubkey bin/warden.intoto.jsonl.pub
  --artifact bin/warden
)

if [ "$EVENT_NAME" = "pull_request" ]; then
  policy=warden-policy-pr.yaml
  if [ "$OIDC_AVAILABLE" != "true" ]; then
    policy=warden-policy-no-provenance.yaml
    attest_args=()
    echo "::notice::this pull request run has no OIDC token (fork or Dependabot), so provenance is not evaluated; vulnerabilities and licenses still are"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      echo "**Provenance was not evaluated:** this pull request run has no OIDC token (fork or Dependabot PR). Vulnerability and license rules still applied. Provenance is enforced on the merge to main." >> "$GITHUB_STEP_SUMMARY"
    fi
  fi
fi

echo "warden: evaluating with policy $policy"
"$WARDEN" policy check \
  --sbom sbom.json \
  --policy "$policy" \
  "${attest_args[@]}" \
  -o policy-result.json
