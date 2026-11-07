#!/usr/bin/env bash
# Installs a verified warden release binary and puts it on PATH.
#
# Trust model: the downloaded binary is never run until two checks that
# don't depend on it have passed.
#   1. Integrity: its SHA-256 matches the release's SHA256SUMS.
#   2. Authenticity: GitHub's own attestation for the immutable release
#      covers this exact file ('gh release verify-asset'). This is the real
#      root of trust. SHA256SUMS alone can't provide it, because whoever
#      could replace the binary could replace the checksums too.
# warden can't verify itself: a tampered binary would simply report success.
set -euo pipefail

# shellcheck source=scripts/retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/retry.sh"

: "${VERSION:?VERSION is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${RUNNER_OS:?RUNNER_OS is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
WARDEN_REPO="${WARDEN_REPO:-Shihasz/warden}"

# A gate that silently changes version isn't a gate: require an exact tag.
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "::error::version '$VERSION' must be an exact release tag such as v0.1.0 (floating versions like 'latest' are deliberately not supported)"
  exit 1
fi

if [ "$RUNNER_OS" != "Linux" ]; then
  echo "::error::warden releases are built for Linux only (this runner is $RUNNER_OS)"
  exit 1
fi
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *)
    echo "::error::unsupported architecture $(uname -m)"
    exit 1
    ;;
esac

if ! gh release verify-asset --help >/dev/null 2>&1; then
  echo "::error::this runner's gh CLI has no 'gh release verify-asset'; update gh"
  exit 1
fi

asset="warden_${VERSION}_linux_${arch}"
dir="$RUNNER_TEMP/warden-install"
rm -rf "$dir"
mkdir -p "$dir"

retry gh release download "$VERSION" --repo "$WARDEN_REPO" --dir "$dir" --clobber \
  --pattern "$asset" --pattern SHA256SUMS

# 1. Integrity. awk selects the line for exactly this file; sha256sum
#    fails if the line is missing, so a name mismatch can't pass silently.
(cd "$dir" && awk -v a="$asset" '$2 == a' SHA256SUMS | sha256sum -c -)

# 2. Authenticity, rooted in GitHub rather than in warden.
retry gh release verify-asset "$VERSION" "$dir/$asset" --repo "$WARDEN_REPO"

chmod +x "$dir/$asset"
mv "$dir/$asset" "$dir/warden"
echo "bin=$dir/warden" >> "$GITHUB_OUTPUT"
echo "$dir" >> "$GITHUB_PATH"
"$dir/warden" --version
