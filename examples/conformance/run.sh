#!/usr/bin/env bash
# Runs the Basic OP, Config OP and Form Post Basic OP certification plans of
# the OpenID Foundation conformance suite against the grantor example
# provider.
#
# Requirements: Docker, Go, Python 3, git. See README.md.
#
# CONFORMANCE_SUITE_REF selects the suite release (git tag and image tag);
# CONFORMANCE_WORKDIR selects where the suite and results are kept.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="${CONFORMANCE_WORKDIR:-$here/.work}"
ref="${CONFORMANCE_SUITE_REF:-release-v5.2.4}"
export IMAGE_TAG="${IMAGE_TAG:-$ref}"
suite="$work/conformance-suite-$ref"
mkdir -p "$work"

if [ ! -d "$suite" ]; then
  git clone --depth 1 --branch "$ref" https://gitlab.com/openid/conformance-suite.git "$suite"
fi
if [ ! -d "$work/venv" ]; then
  python3 -m venv "$work/venv"
  "$work/venv/bin/pip" install --quiet httpx pyparsing
fi

(cd "$suite" && docker compose -f docker-compose-prebuilt.yml -f "$here/compose-host.yml" up -d)

(cd "$here/.." && go build -o "$work/conformance-op" ./conformance)
"$work/conformance-op" >"$work/provider.log" 2>&1 &
provider=$!
trap 'kill "$provider" 2>/dev/null || true' EXIT

echo "waiting for the provider and the conformance suite..."
curl -sk --retry 30 --retry-connrefused --retry-delay 1 -o /dev/null https://localhost:9443/.well-known/openid-configuration
curl -sk --retry 120 --retry-connrefused --retry-all-errors --retry-delay 2 -o /dev/null https://localhost.emobix.co.uk:8443/api/runner/available

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
