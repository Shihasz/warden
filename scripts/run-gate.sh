#!/usr/bin/env bash
# Generates an SBOM from the given dependency files and enforces a warden
# policy against it. Exits non-zero if the policy is violated.
set -euo pipefail

: "${WARDEN:?WARDEN (path to the warden binary) is required}"
: "${POLICY:?POLICY is required}"
: "${OUT_DIR:?OUT_DIR is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
NAME="${NAME:-project}"

sbom_args=()
if [ -n "${GO_MOD:-}" ]; then
  sbom_args+=(--go-mod "$GO_MOD" --go-sum "${GO_SUM:-}")
fi
if [ -n "${NPM_LOCK:-}" ]; then
  sbom_args+=(--npm-lock "$NPM_LOCK")
fi
if [ -n "${PIP_REQUIREMENTS:-}" ]; then
  sbom_args+=(--pip-requirements "$PIP_REQUIREMENTS")
fi
if [ -n "${POETRY_LOCK:-}" ]; then
  sbom_args+=(--poetry-lock "$POETRY_LOCK")
fi
if [ "${#sbom_args[@]}" -eq 0 ]; then
  echo "::error::give at least one of: go-mod (with go-sum), npm-lock, pip-requirements, poetry-lock"
  exit 1
fi

mkdir -p "$OUT_DIR"
sbom="$OUT_DIR/sbom.json"
result="$OUT_DIR/policy-result.json"

# Outputs are set before the check runs, so they exist even when it fails.
{
  echo "sbom-path=$sbom"
  echo "result-path=$result"
} >> "$GITHUB_OUTPUT"

"$WARDEN" sbom generate "${sbom_args[@]}" --name "$NAME" -o "$sbom"

gate_args=(--sbom "$sbom" --policy "$POLICY" -o "$result")
if [ -n "${ATTESTATION:-}" ]; then
  gate_args+=(--attestation "$ATTESTATION" --pubkey "${PUBKEY:-}")
fi
if [ -n "${ARTIFACT:-}" ]; then
  gate_args+=(--artifact "$ARTIFACT")
fi

"$WARDEN" policy check "${gate_args[@]}"
