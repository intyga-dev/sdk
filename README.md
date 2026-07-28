# @intyga/sdk — Universal Governance for Automated Operations

One SDK for every Intyga use case. Intyga is agent-agnostic: the primitive is uniform — **request a challenge → a human approves with a passkey or security key → poll until resolved** — so the same client works for scripts, pipelines, and AI agents. Plus off-platform **zero-knowledge** policy encryption.

This TypeScript package is the reference client. The same primitive is also available for **Go** and **Rust** backends (see [Other languages](#other-languages-go--rust)), and offline receipt verification ships in **four** languages (see [Multi-language offline verifiers](#multi-language-offline-verifiers)).

> Status: publish-ready, **not yet published** to npm. The Go and Rust packages currently live in-repo.

## Require a human approval before a high-risk action

```ts
import { IntygaClient } from "@intyga/sdk";

const intyga = new IntygaClient({
  gatewayUrl: "https://api.intyga.com",
  clientId: process.env.INTYGA_CLIENT_ID,      // a human or agent API key
  clientSecret: process.env.INTYGA_CLIENT_SECRET,
});

// Blocks until the human approves with their passkey / security key (or times out):
const r = await intyga.requireApproval("Delete production database");
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

const r = await intyga.requireApproval("Delete production database", {
  actionType: "wipe_production", params: { target: "prod-db-1" },
});
if (r.status !== "APPROVED") throw new Error("not authorized");
// `nonce` names the challenge you are redeeming — required, so you can enforce single-use yourself.
const ok = verifyApprovalReceipt(r.receipt!, {
  target: "prod-payments-eu", actionType: "wipe_production",
  params: { target: "prod-db-1" }, nonce: r.nonce!,
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

// Blocks until the human approves with their passkey / security key (or times out):
r, err := client.RequireApproval(context.Background(), "Delete production database",
	intyga.RequireApprovalOptions{
		AuthorizeOptions: intyga.AuthorizeOptions{
			ActionType: "wipe_production",
			Params:     map[string]interface{}{"target": "prod-db-1"},
		},
	})
if err != nil || r.Status != intyga.StatusApproved {
	log.Fatal("not authorized")
}

// Optional hard binding before executing — no Intyga secret involved:
// Approvers is REQUIRED: verification uses keys YOU resolved, never the one in the receipt.
res := verify.VerifyApprovalReceipt(*r.Receipt, verify.Expected{
	Nonce: r.Nonce, ActionType: "wipe_production", Target: "prod-payments-eu",
	Params: map[string]interface{}{"target": "prod-db-1"},
	Approvers: verify.ApproverTrustAnchor{PublicKeys: []string{alicePubB64}},
}, verify.VerifyOptions{})
if !res.OK {
	log.Fatalf("refusing to proceed: %s", res.Reason)
}
```

### Rust — [`intyga-sdk`](../sdk-rust)

```rust
use intyga_sdk::{
    verify_approval_receipt_with_options, ApprovalStatus, AuthorizeOptions, Client, ClientOptions,
    Expected, RequireApprovalOptions, VerifyOptions,
};
use serde_json::json;

let mut client = Client::new(ClientOptions {
    gateway_url: "https://api.intyga.com".into(),
    client_id: std::env::var("INTYGA_CLIENT_ID").ok(),
    client_secret: std::env::var("INTYGA_CLIENT_SECRET").ok(),
    ..Default::default()
});

// Blocks until the human approves with their passkey / security key (or times out):
let r = client.require_approval("Delete production database", &RequireApprovalOptions {
    authorize: AuthorizeOptions {
        action_type: Some("wipe_production".into()),
        params: Some(json!({ "target": "prod-db-1" })),
        ..Default::default()
    },
    ..Default::default()
})?;
if r.status != ApprovalStatus::Approved {
    return Err("not authorized".into());
}

// Optional hard binding before executing — no Intyga secret involved:
let expected = Expected {
    nonce: r.nonce.clone().unwrap(),
    action_type: "wipe_production".into(),
    params: json!({ "target": "prod-db-1" }),
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
