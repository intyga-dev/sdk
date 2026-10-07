# Changelog

All notable changes to `@intyga/sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.2.0]

- **Offline signing keys are their own list in the trust bundle.** `BundleApprover.offlinePublicKeys`
  holds an approver's offline signing keys (DIV §5a.4). `approverAnchor(bundle, dids, purpose)` admits
  them only for `"offline-intent"`; the default, `"ordinary"`, never does, so an offline key cannot seal
  a delegation. A bundle listing one key in both lists is refused.
- **Trust-anchor files carry `purpose`.** `parseTrustAnchorFile(text, { purpose })` refuses a file
  exported for the other kind of verification; the default is `"online"`, and a file without the field
  reads as online. An offline anchor must pin a key for every approver.
- **`signChallengeEnvelope`.** The approver's signing step as a library function; `intyga sign` uses it.
  It now also refuses a key that is not P-256.
- `createOfflineChallenge` accepts an optional `nonce`, for deterministic replay and conformance vectors;
  an empty one is refused, as is a `windowMinutes` that is not a whole number.
- **`requireApproval` falls back offline only when the gateway could not be asked.** A transport failure
  is now the typed `GatewayUnreachable`; it and a 5xx `GatewayRefused` are the only routes to the offline
  path. A local error (a blank target, missing credentials) used to route offline too, and started a
  ceremony that bound the faulty input. Without the `offline` option the typed error is thrown. A
  polling streak that includes a refusal throws it rather than falling back.
- **Reconciliation no longer goes silent over one corrupt record.** `readPendingApprovals` returns the
  readable records and names the unreadable files; `reconcileOfflineApprovals` counts each as failed and
  keeps it. `pendingApprovals` returns the readable ones instead of nothing.
- Envelope decoding is strict base64url and refuses a non-object payload instead of throwing; delegation
  files are tried in name order; the pinned trust-bundle key must be RSA, and bundle timestamps follow the
  strict RFC 3339 grammar (DIV §6.2).
- Shared conformance vectors for the offline-approval layer:
  `packages/mcp-schemas/vectors/offline-approval-vectors.json`, specified in
  `docs/OFFLINE-APPROVAL-SDK.md`.

## [1.1.0]

- **CLI: `--required-approvals <n>` (or `INTYGA_REQUIRED_APPROVALS`) on `authorize` and `await`.** The
  minimum number of independent human approvals your policy demands, passed to the verifier as the
  requirement floor (DIV §5 step 3d). A receipt whose own signed requirement is weaker is refused, so the
  requirement cannot be lowered by whoever composed the signed bytes.
- **CLI: `--request-id` on `authorize`.** Adds a fresh random `approvalRequestId` to the signed params so
  one run's approval cannot be reused by another. Supplying `approvalRequestId` yourself is refused. The
  exact signed params are printed (`--no-wait`) and exported as the `params` output for the `await` step.
- **CLI: `--evidence <file>` on `authorize` and `await`.** Writes the receipt, what was expected, the
  trust anchor and the verification result as JSON (mode 0600), before consumption and again with
  `consumed: true` afterwards.
- The `require-approval` GitHub Action gains `approvers-json` (a trust anchor naming people),
  `required-approvals`, `request-id` and `evidence-file`, installs `@intyga/sdk` **and** `@intyga/verify` at
  exact pinned versions (the SDK only declares the verifier as a caret range), and runs on Node 24 with a
  commit-pinned `actions/setup-node`.

## [1.0.0]

- Verify profile-carried WebAuthn audit signatures with caller-trusted signer keys, origin and RP ID.
  Report explicit per-event signature status and key trust; add strict signature acceptance for
  single and bulk evidence. Audit signature checks do not replace full approval-receipt verification.

- **Security (L21, I11):** `IntygaPlatformClient` and the `intyga` CLI (`login`, `trust-bundle
  export`, the Slack/Teams notifications) no longer follow redirects — a followed 307 re-sent the
  POST body, including the `private_key_jwt` client assertion, to whatever origin the `Location`
  named. Every gateway request now uses `redirect: "manual"` and a 30 s timeout, and a 3xx is
  reported as a refusal that names the fix. `IntygaClient`, `IntygaPlatformClient` and the CLI's
  gateway commands refuse a non-`https://` gateway URL at construction, except loopback hosts
  (`localhost`, `127.0.0.0/8`, `::1`) for local development. New exports: `assertGatewayUrl`,
  `isLoopbackHost`, `isRedirect`, `redirectHint`, `GATEWAY_TIMEOUT_MS`.

- `useOfflineApproval` and delegation discovery now pass the trust bundle's ordinary rule as the DIV
  §5 step 3d requirement floor to `@intyga/verify`, so a signed requirement weaker than the bundle
  rule is refused by the verifier itself. Re-export `RequirementFloor` and
  `WEAKER_REQUIREMENT_REASON`.
- `audit-verify --roots` now passes each roots-file line to the verifier as a trusted checkpoint
  record rather than only its root: evidence-bundle checkpoints that contradict their line fail and
  anchors are held to the line's chain-verified time and chain hash (DEWP §5.3); a single proof's
  covering line is passed as its `trustedCheckpoint`, so with `--root` alone Rekor/TSA anchors no
  longer count.
- `audit-verify` adds `--max-anchor-lag <seconds>` (default one day) and `--rekor-submitter-key <pem>`,
  prints each external witness time, and labels a supplied root as caller-supplied with the flag or
  roots file it came from — never "from the external anchor", which cannot supply a root.
- `createOfflineChallenge` refuses a rule with a non-empty `allowedAaguids`, like `requireHardwareKey`.

- `audit-verify` accepts caller-owned RFC 3161 issuer trust through `--tsa-trust <json-file>` and
  can combine TSA and Rekor evidence in one anchor quorum. Malformed, empty, or missing trust fails
  closed; no trust configuration is read from the bundle. Multi-issuer policies bind the global
  Rekor key to one issuer through `--rekor-issuer`, preventing issuer relabelling from satisfying
  multiple quorum slots.

- Refuse approvals received after the caller's monotonic wait deadline; include challenge creation
  in the wait window and cap polling sleeps to its remaining duration.

- Preserve challenge-issued agent context through approval polling for DIV continuity checks.
- Public witness lookups require no credentials and refuse non-success HTTP responses.
- Default HTTP transports use finite request timeouts and refuse redirects; caller-supplied
  transports remain the caller's responsibility.

- Packaging: source maps are off in the published build, which ships `dist` only — the maps resolved
  to `../src/*.ts` files the tarball does not contain. The tarball is 22 files / 63.9 kB packed
  (was 31 / 82.1 kB).
- Packaging: `gatewayJwk` is typed as `webcrypto.JsonWebKey` (from `node:crypto`) rather than the
  DOM global `JsonWebKey`. The two are field-identical, so calling code is unaffected — but the DOM
  name was EMITTED into `dist/trust-bundle.d.ts` as a bare global, and any consumer without `DOM` in
  their own `lib` got TS2304 from inside this package. The `DOM` lib is now out of the build
  entirely (here and in the published tree), so the compiler refuses the next such leak instead of
  shipping it.
- `authorize()` exposes the gateway's issuer-completed v1 `agentContext`; `requireApproval()` retains
  it so the RP can verify against its request-time context independently of the receipt.
- The first public exact-action bundles use `div-trust-bundle-v1` and sign `unmatchedActionPolicy` (`DENY` or
  `BASELINE`). Offline selection ignores display text, requires a tenant baseline and refuses an
  exception that weakens it. Earlier pre-release v2 bundles are refused; export fresh v1 bundles
  after activating the exact-action policy on the tenant.

- The v1 offline profile is the only accepted trust-bundle format.
  Unsupported requester-attestation, escalation and auto-approval controls remain refused offline;
  historical receipt verification remains independent of bundle generation.

- Rebuilt against the DIV Intent Payload's new REQUIRED `evidence` field (DIV §4.3.4), which is
  `null` in this version. No API change; receipts carry the field inside `canonicalPayload` only.

- Offline delegation seals must satisfy the action's ordinary eligible approvers and sealing
  requirement, including quorum and four-eyes restrictions. Recheck the trust bundle's freshness
  after collecting signatures; delegated approvals also recheck the delegation's expiry at use.
- Pre-release staging bundle selection rechecks all matching constraints rather than trusting
  ranking metadata alone. Ambiguous or incomplete policy metadata is refused.
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
