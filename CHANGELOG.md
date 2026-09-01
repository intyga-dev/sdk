# Changelog

All notable changes to `@intyga/sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Tokens are refreshed automatically.** `IntygaClient` now reads `expires_in` from the
  client-credentials exchange and re-exchanges `min(60s, expires_in / 10)` before expiry, so a
  long-lived client (or a `requireApproval` wait longer than the token's life) no longer fails
  every call once the token has expired. A 401 on an exchanged token is retried exactly once with a
  fresh exchange. A response without `expires_in` is cached for the life of the process, as before.
- An explicit `token` is never re-exchanged. A credential saved by `intyga login` is offered until
  its `exp` (read from the JWT as a hint, not verified — the gateway decides) and then, or on a 401,
  refused with `StoredCredentialExpired` (a `GatewayRefused` with status 401, new export) saying to
  run `intyga login` again: there is no client secret behind it, so logging in again is the only
  refresh path, by design.
- A refused token exchange now throws `GatewayRefused` carrying the HTTP status instead of a bare
  `Error` (message unchanged), so a key revoked mid-wait is handled as the verdict it is and never
  routes `requireApproval` into the offline-approval path.

## [1.0.0]

Initial public release.

- One client for every caller — AI agents, humans, backend services: `authorize` / `status` /
  `consume` / `requireApproval`, differing only in which API key or token you hold.
- `target` is required on every approval request (DIV Target Isolation) — there is no `"global"`
  default.
- Offline approval fallback (DIV §5a) with `reconcileOfflineApprovals`, plus trust-bundle
  load/verify helpers.
- Zero-knowledge policy tooling and CLI: `keygen`, `policy-encrypt`, `login`, `authorize`, `await`,
  `notify`, `verify`, `audit-verify`.
- Re-exports the zero-dependency `@intyga/verify` receipt verifier.
