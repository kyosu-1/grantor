# OpenID conformance suite

This directory runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against the grantor example provider, using the suite's prebuilt Docker images.

```sh
./run.sh
```

The script:

1. clones the suite into `.work/` and starts it with Docker Compose on https://localhost.emobix.co.uk:8443 (this hostname resolves to 127.0.0.1);
2. starts `go run ./conformance`: the example provider over HTTPS on port 9443, with a self-signed certificate, the static clients the suite expects, and automatic consent. The suite reaches it as `https://host.docker.internal:9443`;
3. runs `oidcc-basic-certification-test-plan` with static clients and discovery, signing in as `alice` through the login form ([basic-op.json](basic-op.json)).

Results are printed at the end and exported to `.work/results`. The suite's web UI at https://localhost.emobix.co.uk:8443 shows every test log.

## Expected results

| Result | Tests | Why |
|---|---|---|
| REVIEW | `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` | The suite captures a screenshot of the login or error page for a human to review. |
| SKIPPED | `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | Request objects are rejected with `request_not_supported`, which is permitted. |
| PASSED | all others | |

When you are done, stop the suite with `docker compose -f .work/conformance-suite/docker-compose-prebuilt.yml down`.
