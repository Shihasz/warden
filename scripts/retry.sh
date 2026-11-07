#!/usr/bin/env bash
# Sourced helper: retry <command...>
#
# Retries a command that may fail for transient reasons, such as GitHub's
# API occasionally answering with a 5xx. Tunable through RETRY_ATTEMPTS
# (default 4) and RETRY_DELAY in seconds (default 2, doubling each
# attempt), so tests can run with no waiting.
retry() {
  local attempts="${RETRY_ATTEMPTS:-4}" delay="${RETRY_DELAY:-2}" n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      echo "::error::giving up after ${attempts} attempts: $*" >&2
      return 1
    fi
    echo "::warning::attempt ${n} of ${attempts} failed: $*; retrying in ${delay}s" >&2
    sleep "$delay"
    n=$((n + 1))
    delay=$((delay * 2))
  done
}
