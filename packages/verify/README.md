# @sakra-trust/verify

**Independently confirm that a human cryptographically approved exactly the action you're about to run — with no SÄKRA secret.**

When SÄKRA returns an approval, it hands you a **receipt**: the exact canonical payload the human's key signed, plus the signature and public key. This library lets your own code re-derive that payload from *your* parameters, check it byte-for-byte against what was signed, and verify the signature — entirely offline. You don't have to trust SÄKRA's word that the approval is real; you check the math yourself.

- **Zero runtime dependencies** (`node:crypto` only). Read the whole thing — it's ~150 lines.
- **No SÄKRA secret required.** Verification uses only the signer's public key from the receipt.
- Verifies both **raw P-256** (mobile wallet) and **WebAuthn** (passkey / hardware key) approvals, plus policy `AUTO_APPROVED` receipts.

```ts
import { verifyApprovalReceipt } from "@sakra-trust/verify";

// `receipt` came back from SÄKRA when the human approved.
const check = verifyApprovalReceipt(receipt, {
  actionType: "wipe_production",
  params: { target: "prod-db-1", region: "eu-north-1" }, // what you're ACTUALLY about to do
});

if (!check.ok) throw new Error(`Refusing to proceed: ${check.reason}`);
// ✅ A human signed off on THIS exact instruction. Safe to execute.
```

Why re-pass the params? So the approval can't be swapped: if what you're about to execute differs by a
single byte from what the human saw and signed, `verifyApprovalReceipt` returns `{ ok: false }`. This is
your defense-in-depth even against a compromised SÄKRA gateway.

## Policy auto-approvals (break-glass / pre-approval windows)

Some receipts are `sigAlg: "AUTO_APPROVED"` — the action was pre-authorized by a policy window, so **no
human signed it and there is nothing to cryptographically verify**. Such a receipt is trivially
forgeable, so `verifyApprovalReceipt` **refuses it by default** (`{ ok: false, autoApproved: true }`) —
your `if (!verify().ok) throw` correctly blocks it. If your relying party has consciously accepted policy
pre-approval, opt in explicitly:

```ts
verifyApprovalReceipt(receipt, expected, { allowAutoApproved: true }); // → { ok: true, autoApproved: true }
```

`ok: true` without `allowAutoApproved` therefore always means **a real human signature verified**.

## API
- `verifyApprovalReceipt(receipt, { actionType, params }, { allowAutoApproved? })` → `{ ok, reason?, autoApproved? }`
- `canonicalAuthorizationPayload({ nonce, actionType, actionDescription, params })` → the exact signed string
- `verificationCode(canonical)` → the short `XXXX-XXXX` code shown in the wallet
- `verifyEcdsaP256(publicKeyB64, payload, signatureB64)` → `boolean`

> The canonicalization here is byte-for-byte identical to the SÄKRA gateway, the mobile wallet, and
> `@sakra-trust/mcp-schemas`. That identity is the whole point — don't reformat it.

MIT licensed.
