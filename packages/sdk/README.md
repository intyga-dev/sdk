# @sakra/sdk — Universal Governance for Automated Operations

One SDK for every SÄKRA use case. SÄKRA is agent-agnostic: the primitive is uniform — **request a challenge → a human approves on their wallet/key → poll until resolved** — so the same client works for scripts, pipelines, and AI agents. Plus off-platform **zero-knowledge** policy encryption.

> Status: publish-ready, **not yet published** to npm.

## Require a human approval before a high-risk action

```ts
import { SakraClient } from "@sakra/sdk";

const sakra = new SakraClient({
  gatewayUrl: "https://api.sakra.com",
  clientId: process.env.SAKRA_CLIENT_ID,      // a human or agent API key
  clientSecret: process.env.SAKRA_CLIENT_SECRET,
});

// Blocks until the human approves on their wallet (or times out):
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
import { policy } from "@sakra/sdk";
const blob = policy.encryptPolicy(orgPublicKey, JSON.stringify(manifest));
const hash = policy.blobHash(blob);          // matches the gateway's check
```

## CLI

```
sakra keygen [--out <prefix>]
sakra policy-encrypt <manifest.json> --pubkey <public.key> [--out <blob.json>]
sakra authorize "<action>" --gateway <url> (--token <t> | --client-id <> --client-secret <>)
sakra verify <documentHash> --gateway <url>
```

Node ≥18 (global `fetch` + `node:crypto`); the only dependency is the zero-dep [`@sakra/verify`](../verify/README.md).

## Verify approvals independently

Every APPROVED result carries a **receipt**. Confirm — in your own code, with no SÄKRA secret — that a
human signed off on the *exact* instruction you're about to run:

```ts
import { verifyApprovalReceipt } from "@sakra/sdk"; // re-exported from @sakra/verify

const r = await sakra.requireApproval("Delete production database", {
  actionType: "wipe_production", params: { target: "prod-db-1" },
});
if (r.status !== "APPROVED") throw new Error("not authorized");
const ok = verifyApprovalReceipt(r.receipt!, { actionType: "wipe_production", params: { target: "prod-db-1" } });
if (!ok.ok) throw new Error(`refusing to proceed: ${ok.reason}`);
```

## Start here
- **Quickstart** (gate a prod DB deletion in an afternoon): [`docs/quickstart.md`](../../docs/quickstart.md)
- **Runnable examples**: [`examples/gate-prod-delete`](../../examples/gate-prod-delete), [`examples/ci-cd-github-action`](../../examples/ci-cd-github-action)
- **Independent verification library**: [`@sakra/verify`](../verify/README.md)
