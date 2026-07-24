# @sakra-trust/sdk — Universal Governance for Automated Operations

One SDK for every SÄKRA use case. SÄKRA is agent-agnostic: the primitive is uniform — **request a challenge → a human approves with a passkey or security key → poll until resolved** — so the same client works for scripts, pipelines, and AI agents. Plus off-platform **zero-knowledge** policy encryption.

> Status: publish-ready, **not yet published** to npm.

## Require a human approval before a high-risk action

```ts
import { SakraClient } from "@sakra-trust/sdk";

const sakra = new SakraClient({
  gatewayUrl: "https://api.sakra.com",
  clientId: process.env.SAKRA_CLIENT_ID,      // a human or agent API key
  clientSecret: process.env.SAKRA_CLIENT_SECRET,
});

// Blocks until the human approves with their passkey / security key (or times out):
const r = await sakra.requireApproval("Delete production database");
if (r.status !== "APPROVED") throw new Error("not authorized");
// …safe to proceed; r.signatureHash is your non-repudiable receipt.
```

Works identically whether the token is a **human key** (backend/service) or an **agent key**. This
is SÄKRA as a general zero-trust gate for *any* backend action, not just agents.

## Verify a witnessed document/policy

```ts
const w = await sakra.verify(sha256Hex);   // { verified, signerDid, signedAt, ... }
```

## Zero-knowledge policy (off-platform)

Encrypt policies on **your** machine so SÄKRA never sees plaintext or your private key — the
strongest ZK posture (no trust in SÄKRA-served code):

```bash
sakra keygen --out org                       # → org.public.key (upload) + org.private.key (keep!)
sakra policy-encrypt policy.json --pubkey org.public.key --out blob.json
# publish blob.json (encryptedBlob + blobHash); SÄKRA stores only ciphertext + hash
```

```ts
import { policy } from "@sakra-trust/sdk";
const blob = policy.encryptPolicy(orgPublicKey, JSON.stringify(manifest));
const hash = policy.blobHash(blob);          // matches the gateway's check
```

## CLI

```
sakra keygen [--out <prefix>]
sakra policy-encrypt <manifest.json> --pubkey <public.key> [--out <blob.json>]
sakra login --did <did> [--gateway <url>]
sakra authorize "<action>" --gateway <url> (--token <t> | --client-id <> --client-secret <>) [--type <actionType>] [--params <json>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume]
sakra await <nonce> --gateway <url> [--type <t>] [--params <json>] [--timeout <s>] [--consume]
sakra notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]
sakra verify <documentHash> --gateway <url>
sakra audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>] [--json]
```

Invoke it as `npx @sakra-trust/sdk <command>`, or `npm i -g @sakra-trust/sdk` and then `sakra <command>`.
(`npx sakra` resolves to an unrelated package — the binary is `sakra`, but it ships inside this package.)

**Headless / CI:** split the flow so the approver is pinged where they already are —
`authorize --no-wait` returns the deep-link immediately, `notify` posts an interactive Approve
button to Slack/Teams, and `await <nonce> --consume` blocks until signed, verifies the receipt, and
exits non-zero on failure. See [`examples/ci-cd-github-action`](../../examples/ci-cd-github-action).

Node ≥18 (global `fetch` + `node:crypto`); the only dependency is the zero-dep [`@sakra-trust/verify`](../verify/README.md).

## Verify approvals independently

Every APPROVED result carries a **receipt**. Confirm — in your own code, with no SÄKRA secret — that a
human signed off on the *exact* instruction you're about to run:

```ts
import { verifyApprovalReceipt } from "@sakra-trust/sdk"; // re-exported from @sakra-trust/verify

const r = await sakra.requireApproval("Delete production database", {
  actionType: "wipe_production", params: { target: "prod-db-1" },
});
if (r.status !== "APPROVED") throw new Error("not authorized");
// `nonce` names the challenge you are redeeming — required, so you can enforce single-use yourself.
const ok = verifyApprovalReceipt(r.receipt!, {
  actionType: "wipe_production", params: { target: "prod-db-1" }, nonce: r.nonce!,
});
if (!ok.ok) throw new Error(`refusing to proceed: ${ok.reason}`);
```

## Start here
- **Quickstart** (gate a prod DB deletion in an afternoon): [`docs/quickstart.md`](../../docs/quickstart.md)
- **Runnable examples**: [`examples/gate-prod-delete`](../../examples/gate-prod-delete), [`examples/ci-cd-github-action`](../../examples/ci-cd-github-action)
- **Independent verification library**: [`@sakra-trust/verify`](../verify/README.md)

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
