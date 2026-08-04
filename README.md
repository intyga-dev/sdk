# @intyga/sdk — Universal Governance for Automated Operations

One SDK for every Intyga use case. Intyga is agent-agnostic: the primitive is uniform — **request a challenge → a human approves with a passkey or security key → poll until resolved** — so the same client works for scripts, pipelines, and AI agents. Plus off-platform **zero-knowledge** policy encryption.

This TypeScript package is the reference client. The same primitive is also available for **Go** and **Rust** backends (see [Other languages](#other-languages-go--rust)), and offline receipt verification ships in **four** languages (see [Multi-language offline verifiers](#multi-language-offline-verifiers)).

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
const r = await intyga.requireApproval("Delete production database", {
  target: "prod-db-cluster-01",
});
if (r.status !== "APPROVED") throw new Error("not authorized");
// …safe to proceed; r.signatureHash is your non-repudiable receipt.
```

Works identically whether the token is a **human key** (backend/service) or an **agent key**. This
is Intyga as a general zero-trust gate for *any* backend action, not just agents.

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
intyga authorize "<action>" --gateway <url> (--token <t> | --client-id <> --client-secret <>) [--type <actionType>] [--params <json>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume]
intyga await <nonce> --gateway <url> [--type <t>] [--params <json>] [--timeout <s>] [--consume]
intyga notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]
intyga verify <documentHash> --gateway <url>
intyga audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>] [--json]
```

Invoke it as `npx @intyga/sdk <command>`, or `npm i -g @intyga/sdk` and then `intyga <command>`.
(`npx intyga` resolves to an unrelated package — the binary is `intyga`, but it ships inside this package.)

**Headless / CI:** split the flow so the approver is pinged where they already are —
`authorize --no-wait` returns the deep-link immediately, `notify` posts an interactive Approve
button to Slack/Teams, and `await <nonce> --consume` blocks until signed, verifies the receipt, and
exits non-zero on failure. See [`examples/ci-cd-github-action`](../../examples/ci-cd-github-action).

Node ≥18 (global `fetch` + `node:crypto`); the only dependency is the zero-dep [`@intyga/verify`](../verify/README.md).

## Verify approvals independently

Every APPROVED result carries a **receipt**. Confirm — in your own code, with no Intyga secret — that a
human signed off on the *exact* instruction you're about to run:

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
```

## Other languages (Go & Rust)

The same **request → approve → poll** primitive is available for Go and Rust backends — the languages that run most payments, ledger, and infrastructure services. Each SDK re-exports its language's offline verifier, so you can verify the receipt in the same process.

### Go — [`github.com/intyga-dev/sdk-go`](../sdk-go)

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

### Rust — [`intyga-sdk`](../sdk-rust)

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

## Multi-language offline verifiers

Every APPROVED result carries a **receipt** you can verify in your own process, with no Intyga secret and no network — against approver keys **you** resolve, never one read out of the receipt. The verifier is available in four languages; all four verify both **ES256** (service-key) and **WebAuthn** (passkey) receipts, and are held byte-identical by shared cross-language test vectors.

| Language | Package | Dependencies |
| :--- | :--- | :--- |
| TypeScript | [`@intyga/verify`](../verify/README.md) | none (Node built-in `crypto`) |
| Python | [`intyga-sdk`](../sdk-python) (PyPI) | `cryptography` |
| Go | [`github.com/intyga-dev/verify-go`](../verify-go) | none (standard library) |
| Rust | [`intyga-verify`](../verify-rust) | `p256` / `sha2` |

For **WebAuthn** receipts, verification requires you to pin the expected origin and RP ID (a passkey assertion harvested at any relying party would otherwise verify) — pass them via the verifier's options (`VerifyReceiptOptions` in TS, `VerifyOptions` in Go/Rust, `expected_origin`/`expected_rp_id` in Python). ES256 receipts need no such context.

## Start here
- **Quickstart** (gate a prod DB deletion in an afternoon): [`docs/quickstart.md`](../../docs/quickstart.md)
- **Runnable examples**: [`examples/gate-prod-delete`](../../examples/gate-prod-delete), [`examples/ci-cd-github-action`](../../examples/ci-cd-github-action)
- **Independent verification library**: [`@intyga/verify`](../verify/README.md) (TypeScript) · also [Go](../verify-go), [Rust](../verify-rust), [Python](../sdk-python)

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
