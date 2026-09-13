#!/usr/bin/env bash
# Runs the OpenID Connect Basic OP certification plan of the OpenID Foundation
# conformance suite against the grantor example provider.
#
# Requirements: Docker, Go, Python 3, git. See README.md.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="${CONFORMANCE_WORKDIR:-$here/.work}"
suite="$work/conformance-suite"
mkdir -p "$work"

if [ ! -d "$suite" ]; then
  git clone --depth 1 https://gitlab.com/openid/conformance-suite.git "$suite"
fi
if [ ! -d "$work/venv" ]; then
  python3 -m venv "$work/venv"
  "$work/venv/bin/pip" install --quiet httpx pyparsing
fi

(cd "$suite" && docker compose -f docker-compose-prebuilt.yml up -d)

(cd "$here/.." && go build -o "$work/conformance-op" ./conformance)
"$work/conformance-op" >"$work/provider.log" 2>&1 &
provider=$!
trap 'kill "$provider" 2>/dev/null || true' EXIT

echo "waiting for the provider and the conformance suite..."
curl -sk --retry 30 --retry-connrefused --retry-delay 1 -o /dev/null https://localhost:9443/.well-known/openid-configuration
curl -sk --retry 60 --retry-connrefused --retry-all-errors --retry-delay 2 -o /dev/null https://localhost.emobix.co.uk:8443/api/runner/available

mkdir -p "$work/results"
cd "$suite/scripts"
CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/ \
CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/ \
CONFORMANCE_DEV_MODE=1 \
  "$work/venv/bin/python" run-test-plan.py \
    --export-dir "$work/results" \
    --expected-skips-file "$here/expected-skips.json" \
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" "$here/basic-op.json" \
    "oidcc-config-certification-test-plan" "$here/basic-op.json" \
    "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" "$here/basic-op.json"
