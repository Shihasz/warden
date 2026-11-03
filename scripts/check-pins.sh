#!/usr/bin/env bash
# Fails if a workflow action isn't pinned to a full commit SHA, or a
# Dockerfile FROM isn't pinned to an image digest.
# Usage: check-pins.sh [repo-root]
set -euo pipefail
cd "${1:-.}"
status=0

# Local actions ("uses: ./...") are the repo's own code and need no pin.
unpinned="$(grep -rnE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+[^./[:space:]]' .github/workflows action.yml \
  | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' || true)"
if [ -n "$unpinned" ]; then
  echo "::error::these 'uses:' lines are not pinned to a full commit SHA:"
  echo "$unpinned"
  status=1
fi

loose="$(grep -nE '^FROM[[:space:]]' Dockerfile | grep -vE '@sha256:[0-9a-f]{64}' || true)"
if [ -n "$loose" ]; then
  echo "::error::these Dockerfile FROM lines are not pinned to an image digest:"
  echo "$loose"
  status=1
fi

exit "$status"
