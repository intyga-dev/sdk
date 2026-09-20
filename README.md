# @intyga/sdk — Universal Governance for Automated Operations

One SDK for every Intyga use case. Intyga is agent-agnostic: the primitive is uniform — **request a challenge → a human approves with a passkey or security key → poll until resolved** — so the same client works for scripts, pipelines, and AI agents. Plus off-platform **zero-knowledge** policy encryption.

This TypeScript package is the reference client. The same primitive is also available for **Go**, **Rust**, **Java** and **Python** backends (see [Other languages](#other-languages-go-rust-java--python)), and offline receipt verification ships in **five** languages (see [Multi-language offline verifiers](#multi-language-offline-verifiers)).

## Require a human approval before a high-risk action

```ts
import { IntygaClient } from "@intyga/sdk";

const intyga = new IntygaClient({
  gatewayUrl: "https://api.intyga.com",
  clientId: process.env.INTYGA_CLIENT_ID!,      // a human or agent API key
  clientSecret: process.env.INTYGA_CLIENT_SECRET!,
});

// Blocks until the human approves with their passkey / security key (or times out).
// `target` is required — it names THIS execution environment, so the approval cannot be
// replayed against a different service (DIV Target Isolation).
const action = { target: "prod-db-cluster-01", actionType: "wipe_production" };
const r = await intyga.requireApproval("Delete production database", action);
if (r.status !== "APPROVED") throw new Error("not authorized");

// Redeem it exactly once, immediately before the action runs — the same action object, so the
// gateway re-binds the approval to what is about to execute. Skip this and the challenge stays
// APPROVED, redeemable again for the rest of its TTL.
const spent = await intyga.consume(r.nonce!, action);
if (!spent.ok) throw new Error(`could not consume the approval: ${spent.reason ?? ""}`);
// …safe to proceed; r.signatureHash is your non-repudiable receipt.
```

Works identically whether the token is a **human key** (backend/service) or an **agent key**. This
is Intyga as a general zero-trust gate for *any* backend action, not just agents.

Tokens are re-exchanged automatically before the `expires_in` the gateway reports, so a long-lived
client needs no token management of its own; an explicit `token` is yours to refresh.

## Verify a witnessed document/policy

```ts
const w = await intyga.verify(sha256Hex);   // { verified, signerDid, signedAt, ... }
```

## Zero-knowledge policy (off-platform)

Encrypt policies on **your** machine so Intyga never sees plaintext or your private key — the
strongest ZK posture (no trust in Intyga-served code):

```bash
intyga keygen --out org                       # → org.public.key (upload) + org.private.key (keep!)
intyga policy-encrypt policy.json --pubkey org.public.key --out blob.json
# publish blob.json (encryptedBlob + blobHash); Intyga stores only ciphertext + hash
```

```ts
import { policy } from "@intyga/sdk";
const blob = policy.encryptPolicy(orgPublicKey, JSON.stringify(manifest));
const hash = policy.blobHash(blob);          // matches the gateway's check
```

## CLI

```
intyga keygen [--out <prefix>]
intyga policy-encrypt <manifest.json> --pubkey <public.key> [--out <blob.json>]
intyga login --did <did> [--gateway <url>]
intyga authorize "<action>" --gateway <url> --target <target> (--token <t> | --client-id <> --client-secret <>) [--type <actionType>] [--params <json>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume] [--allow-auto-approved]
intyga await <nonce> --gateway <url> --target <target> [--type <t>] [--params <json>] [--timeout <s>] [--consume] [--allow-auto-approved]
intyga notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]
intyga sign <DIV1:...> --key <private.pem|private.der> --did <your-did> [--yes]
intyga trust-bundle export --tenant <uuid> [--dir <dir>] [--gateway <url>]   # INTYGA_INTERNAL_TOKEN | --token-file | --token-stdin
intyga trust-bundle show [--dir <dir>]
intyga verify <documentHash> --gateway <url>
intyga audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>] [--trusted-issuer <a,b>] [--anchor-keys <keys.json>] [--require-anchors <n>] [--rekor-key <pem>] [--json]
```

`--target` is not optional on `authorize`/`await`: it names the relying party the approval is bound
to (DIV Target Isolation), and the CLI exits non-zero without it.

Invoke it as `npx @intyga/sdk <command>`, or `npm i -g @intyga/sdk` and then `intyga <command>`.
(`npx intyga` resolves to an unrelated package — the binary is `intyga`, but it ships inside this package.)

**Headless / CI:** split the flow so the approver is pinged where they already are —
`authorize --no-wait` returns the deep-link immediately, `notify` posts an interactive Approve
button to Slack/Teams, and `await <nonce> --consume` blocks until signed, verifies the receipt, and
exits non-zero on failure. Both halves are separate invocations, so both need the same `--gateway`
and `--target`. See [`examples/ci-cd-github-action`](https://github.com/intyga-dev/require-approval).

**Offline approval (DIV §5a):** when the gateway is unreachable, `intyga trust-bundle export` stages
the approver keys ahead of time, `intyga sign` lets an approver sign a `DIV1:` challenge envelope
with no network at all, and the client-side `useOfflineApproval` / `createOfflineChallenge` helpers
assemble the result into an `OFFLINE_APPROVED` receipt — a status deliberately distinct from
`APPROVED`, so adding the fallback cannot silently widen an existing `if (status !== "APPROVED")`
guard. Call `intyga.reconcileOfflineApprovals()` on reconnect: until an offline approval is
reported it exists only on your disk. See [`docs/DIV.md`](../../docs/DIV.md) §5a.

Update the gateway and SDK together, then re-export trust bundles used with overlapping approval
rules. New exports carry signed rule-selection metadata; older bundles with multiple matching rules
are refused because their governing approver set cannot be selected reliably.

Node ≥18 (global `fetch` + `node:crypto`); the only dependency is the zero-dep [`@intyga/verify`](https://github.com/intyga-dev/verify).

## Verify approvals independently

Every APPROVED result carries a **receipt**. Confirm — in your own code, with no Intyga secret — that a
human signed off on the *exact* instruction you're about to run:

The example below is for a human or `SERVICE` key. An `AI_AGENT` key must also send
`agentContext` (reversibility, decimal amount, configuration digest, delegation receipt hash and
session state) and use `verifyAgentForExecution` with a live configuration and its own locked
`AgentSessionState`. Persist the returned head and reserve a global budget atomically with nonce
redemption before the action. `configDigest` is an RP claim, not an agent integrity attestation;
raw prompts and personal data must not enter the new receipt fields. See DIV §4.3.6.

```ts
import { verifyApprovalReceipt } from "@intyga/sdk"; // re-exported from @intyga/verify

// One action object, used for BOTH the request and the verification — re-deriving the payload
// from the same values is what makes a one-byte swap detectable.
const action = {
  target: "prod-payments-eu",     // THIS execution environment (DIV Target Isolation)
  actionType: "wipe_production",
  params: { database: "prod-db-1" },
};

const r = await intyga.requireApproval("Delete production database prod-db-1", action);
if (r.status !== "APPROVED") throw new Error("not authorized");
// `nonce` names the challenge you are redeeming — required, so you can enforce single-use yourself.
const ok = verifyApprovalReceipt(r.receipt!, {
  ...action,
  nonce: r.nonce!,
  // REQUIRED: the approver keys YOU trust, from your own config/directory. Verification never uses
  // the key inside the receipt — that would let a receipt vouch for its own signer. Do NOT fetch
  // these from the gateway: a compromised gateway would then supply both the receipt and the key
  // that validates it. See @intyga/verify's "Whose key?" section.
  approvers: { dids: ["did:intyga:cfo-alice"], resolveKey: (did) => APPROVER_KEYS[did] ?? null },
});
if (!ok.ok) throw new Error(`refusing to proceed: ${ok.reason}`);

// Verifying is not redeeming. Consume re-binds the same target/params gateway-side and marks the
// challenge single-use; without it the approval stays live for the rest of its TTL.
const spent = await intyga.consume(r.nonce!, action);
if (!spent.ok) throw new Error(`could not consume the approval: ${spent.reason ?? ""}`);
```

## Other languages (Go, Rust, Java & Python)

The same **request → approve → poll** primitive is available for Go, Rust and Java backends — the languages that run most payments, ledger, and infrastructure services — and for Python, where the agent frameworks live. Each of those SDKs brings its language's offline verifier with it, so you can verify the receipt in the same process without a second dependency.

### Go — [`github.com/intyga-dev/sdk-go`](https://github.com/intyga-dev/sdk-go)

```go
import (
	"context"

	intyga "github.com/intyga-dev/sdk-go"
	verify "github.com/intyga-dev/verify-go"
)

client := intyga.NewClient(intyga.ClientOptions{
	GatewayURL:   "https://api.intyga.com",
	ClientID:     os.Getenv("INTYGA_CLIENT_ID"),
	ClientSecret: os.Getenv("INTYGA_CLIENT_SECRET"),
})

// Blocks until the human approves with their passkey / security key (or times out).
// Target is required — it names THIS execution environment (DIV Target Isolation), and the
// SAME target/actionType/params are re-asserted at verification below.
params := map[string]interface{}{"database": "prod-db-1"}
r, err := client.RequireApproval(context.Background(), "Delete production database",
	intyga.RequireApprovalOptions{
		AuthorizeOptions: intyga.AuthorizeOptions{
			Target:     "prod-payments-eu",
			ActionType: "wipe_production",
			Params:     params,
		},
	})
if err != nil || r.Status != intyga.StatusApproved {
	log.Fatal("not authorized")
}

// Optional hard binding before executing — no Intyga secret involved:
// Approvers is REQUIRED: verification uses keys YOU resolved, never the one in the receipt.
res := verify.VerifyApprovalReceipt(*r.Receipt, verify.Expected{
	Nonce: r.Nonce, ActionType: "wipe_production", Target: "prod-payments-eu",
	Params:    params,
	Approvers: verify.ApproverTrustAnchor{PublicKeys: []string{alicePubB64}},
}, verify.VerifyOptions{})
if !res.OK {
	log.Fatalf("refusing to proceed: %s", res.Reason)
}
```

> **Quorum caveat.** In `PublicKeys` mode the identity IS the key, so an M-of-N quorum counts credentials, not people — one approver whose two credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form (DIV §4.4.6).

### Rust — [`intyga-sdk`](https://github.com/intyga-dev/sdk-rust)

```rust
use intyga_sdk::{
    verify_approval_receipt_with_options, ApprovalStatus, ApproverTrustAnchor, AuthorizeOptions,
    Client, ClientOptions, Expected, RequireApprovalOptions, VerifyOptions,
};
use serde_json::json;

let mut client = Client::new(ClientOptions {
    gateway_url: "https://api.intyga.com".into(),
    client_id: std::env::var("INTYGA_CLIENT_ID").ok(),
    client_secret: std::env::var("INTYGA_CLIENT_SECRET").ok(),
    ..Default::default()
});

// Blocks until the human approves with their passkey / security key (or times out).
// `target` is required — it names THIS execution environment (DIV Target Isolation), and the
// SAME target/actionType/params are re-asserted at verification below.
let r = client.require_approval("Delete production database", &RequireApprovalOptions {
    authorize: AuthorizeOptions {
        target: Some("prod-payments-eu".into()),
        action_type: Some("wipe_production".into()),
        params: Some(json!({ "database": "prod-db-1" })),
        ..Default::default()
    },
    ..Default::default()
})?;
if r.status != ApprovalStatus::Approved {
    return Err("not authorized".into());
}

// Optional hard binding before executing — no Intyga secret involved. `approvers` is REQUIRED:
// verification uses keys YOU resolved, never the one inside the receipt.
let expected = Expected {
    target: "prod-payments-eu".into(),
    nonce: r.nonce.clone().unwrap(),
    action_type: "wipe_production".into(),
    params: json!({ "database": "prod-db-1" }),
    approvers: ApproverTrustAnchor::PublicKeys(vec![alice_pub_b64]),
};
verify_approval_receipt_with_options(&r.receipt.unwrap(), &expected, &VerifyOptions::default())?;
```

The Rust client is generic over a pluggable `Transport` (default: a built-in blocking `ureq` transport), so you can supply your own async/instrumented HTTP client.

### Java — [`com.intyga:intyga-sdk`](https://github.com/intyga-dev/sdk-java)

The same client (`requireApproval` / `consume`, blocking, `target` required) for JVM backends, plus a one-line `requireApprovalOrThrow` gate for Spring/Quarkus handlers and LangChain4j tool methods. It bundles the Java verifier, so a receipt can be verified in the same process. Not yet published to Maven Central — see [`sdk-java`](https://github.com/intyga-dev/sdk-java) and [`examples/`](https://github.com/intyga-dev/examples) for Spring Boot, Quarkus and LangChain4j examples.

### Python — [`intyga-sdk`](https://github.com/intyga-dev/sdk-python)

The same client (`authorize` / `status` / `require_approval` / `consume`, async) plus the offline
verifier, and — because agent frameworks reduce a tool to a plain callable — a
`require_human_approval` decorator that covers LangChain and CrewAI in one line:

```python
import os
from intyga_sdk import IntygaClient, require_human_approval

intyga = IntygaClient(
    gateway_url=os.environ["INTYGA_GATEWAY_URL"],
    client_id=os.environ["INTYGA_CLIENT_ID"],
    client_secret=os.environ["INTYGA_CLIENT_SECRET"],
    target="agent-payments-prod",
)

# Keyword arguments only: the approver signs each parameter by name, and a refusal raises
# ApprovalRefused rather than returning a value a framework could mistake for a tool result.
@require_human_approval(intyga, description="Send a wire transfer")
def wire_transfer(*, to: str, amount: int, currency: str) -> str:
    return execute_transfer(to, amount, currency)
```

## Multi-language offline verifiers

Every APPROVED result carries a **receipt** you can verify in your own process, with no Intyga secret and no network — against approver keys **you** resolve, never one read out of the receipt. The verifier is available in five languages; all five verify both **ES256** (service-key) and **WebAuthn** (passkey) receipts, and are held byte-identical by shared cross-language test vectors.

| Language | Package | Dependencies |
| :--- | :--- | :--- |
| TypeScript | [`@intyga/verify`](https://github.com/intyga-dev/verify) | none (Node built-in `crypto`) |
| Python | [`intyga-sdk`](https://github.com/intyga-dev/sdk-python) (PyPI) | `cryptography` |
| Go | [`github.com/intyga-dev/verify-go`](https://github.com/intyga-dev/verify-go) | none (standard library) |
| Rust | [`intyga-verify`](https://github.com/intyga-dev/verify-rust) | 6 crates: `serde`, `serde_json`, `p256`, `ecdsa`, `base64`, `sha2` |
| Java | [`com.intyga:intyga-verify`](https://github.com/intyga-dev/verify-java) | `jackson-databind` (JDK crypto) |

TypeScript implements the broadest surface; Python, Go, Rust and Java implement the DEWP **Core Profile** — each README states its own remaining limits precisely.

For **WebAuthn** receipts, verification requires you to pin the expected origin and RP ID (a passkey assertion harvested at any relying party would otherwise verify) — pass them via the verifier's options (`VerifyReceiptOptions` in TS, `VerifyOptions` in Go/Rust/Java, `expected_origin`/`expected_rp_id` in Python). ES256 receipts need no such context.

## Start here
- **Quickstart** (gate a prod DB deletion in an afternoon): [`docs/quickstart.md`](../../docs/quickstart.md)
- **Runnable examples**: [`examples/gate-prod-delete`](https://github.com/intyga-dev/examples/tree/main/gate-prod-delete), [`require-approval` GitHub Action](https://github.com/intyga-dev/require-approval)
- **Independent verification library**: [`@intyga/verify`](https://github.com/intyga-dev/verify) (TypeScript) · also [Go](https://github.com/intyga-dev/verify-go), [Rust](https://github.com/intyga-dev/verify-rust), [Python](https://github.com/intyga-dev/sdk-python), [Java](https://github.com/intyga-dev/verify-java)

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
