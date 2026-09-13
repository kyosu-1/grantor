# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/). Before v1.0.0,
minor versions may contain breaking changes.

## [0.1.0] - Unreleased

First tagged release.

### Added

- OAuth 2.1 authorization server: authorization code flow with PKCE (S256, required by default), refresh token rotation with reuse detection, client credentials, exact redirect URI matching, the RFC 9207 `iss` parameter, and RFC 8252 loopback redirect URIs.
- OpenID Connect Core and Discovery: ID tokens, UserInfo, `nonce`, `prompt`, `max_age`, `id_token_hint`, `acr`/`amr`, the `claims` parameter, `offline_access`, and the `query`, `fragment` and `form_post` response modes.
- Token introspection (RFC 7662) and revocation (RFC 7009) for every access token format.
- Access tokens: opaque, JWT (RFC 9068) or custom formats, with audiences, extra claims and lifetimes per client and per issuance, and `Provider.ValidateAccessToken` for resource servers in the same process.
- Client authentication with `client_secret_basic`, `client_secret_post`, `private_key_jwt` and `none`.
- Two layers: `Provider.ServeHTTP`, or per-endpoint `Serve*` methods and building blocks (`ParseAuthorizationRequest`, `SaveAuthorizationRequest`, `Approve`, `Deny`, `ParseTokenRequest`, `Exchange`), with `Config.BeforeIssue` for every issuance and `Config.Grants` for custom grant types.
- Multiple issuers in one process with per-issuer keys and clients, and signing keys from any `crypto.Signer`.
- The `memory` storage and the `storagetest` suite for storage implementations.
- The OpenID Foundation conformance plans Basic OP, Config OP and Form Post Basic OP, run in CI.

[0.1.0]: https://github.com/kyosu-1/grantor/releases/tag/v0.1.0
