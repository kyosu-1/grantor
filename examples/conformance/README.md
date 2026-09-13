# OpenID conformance suite

This directory runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against the grantor example provider, using the suite's prebuilt Docker images.

```sh
./run.sh
```

The script:

1. clones the suite release named by `CONFORMANCE_SUITE_REF` (default `release-v5.2.4`) into `.work/` and starts its matching Docker images on https://localhost.emobix.co.uk:8443 (this hostname resolves to 127.0.0.1). [compose-host.yml](compose-host.yml) maps `host.docker.internal` to the host, which Linux engines need;
2. starts `go run ./conformance`: the example provider over HTTPS on port 9443, with a self-signed certificate, the static clients the suite expects, and automatic consent. The suite reaches it as `https://host.docker.internal:9443`;
3. runs the Basic OP, Config OP and Form Post Basic OP certification plans with static clients and discovery, signing in as `alice` through the login form ([basic-op.json](basic-op.json)).

Results are printed at the end and exported to `.work/results`; the script exits non-zero when a test fails or warns. The suite's web UI at https://localhost.emobix.co.uk:8443 shows every test log.

The same script runs in CI on every push to main and every pull request ([.github/workflows/conformance.yml](../../.github/workflows/conformance.yml)), which uploads the results as an artifact.

## Expected results

The Basic OP and Form Post Basic OP plans each report:

| Result | Tests | Why |
|---|---|---|
| REVIEW | `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` | The suite captures a screenshot of the login or error page for a human to review. |
| SKIPPED | `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | Request objects are rejected with `request_not_supported`, which is permitted. |
| PASSED | all others | |

The Config OP plan's single test passes.

When you are done, stop the suite with `docker compose -f .work/conformance-suite-release-v5.2.4/docker-compose-prebuilt.yml down`.
