// @sakra-trust/verify — independently confirm that a human cryptographically approved EXACTLY the action
// you are about to run. Zero runtime dependencies (node:crypto only), no network, and NO SÄKRA secret:
// a relying party recomputes the canonical payload from its own params, checks it byte-matches what was
// signed, and verifies the human's P-256 / WebAuthn signature. This is the "inspect-it-yourself" trust
// artifact — the whole point is that you don't have to take SÄKRA's word for it.
//
// The canonicalization + hashing here MUST stay byte-for-byte identical to @sakra-trust/mcp-schemas and the
// mobile wallet, or signatures won't verify. Do not "tidy" the JSON shapes.

import crypto from "node:crypto";

/** A verifiable proof of what the human approved — returned once a challenge is APPROVED. */
export interface ApprovalReceipt {
  canonicalPayload: string; // the exact bytes the human's key signed
  actionType?: string | null;
  actionDescription: string;
  params: Record<string, unknown>;
  signerDid?: string | null;
  signerPublicKey?: string | null; // base64 SPKI or base64 COSE public key
  signature?: string | null; // base64 signature over canonicalPayload
  sigAlg?: string | null; // "ES256" | "WEBAUTHN" | "AUTO_APPROVED"
  authenticatorData?: string | null; // base64url (WEBAUTHN only)
  clientDataJSON?: string | null; // base64url (WEBAUTHN only)
  verificationCode: string;
}

function base64url(str: string | Buffer): string {
  const buf = typeof str === "string" ? Buffer.from(str, "utf-8") : str;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function parseCosePublicKey(coseBuffer: Buffer): { x: string; y: string } {
  const xIdx = coseBuffer.indexOf(Buffer.from([0x21, 0x58, 0x20]));
  const yIdx = coseBuffer.indexOf(Buffer.from([0x22, 0x58, 0x20]));
  if (xIdx === -1 || yIdx === -1) {
    throw new Error("Invalid COSE public key format: coordinates not found");
  }
  const xBytes = coseBuffer.subarray(xIdx + 3, xIdx + 3 + 32);
  const yBytes = coseBuffer.subarray(yIdx + 3, yIdx + 3 + 32);
  return { x: base64url(xBytes), y: base64url(yBytes) };
}

/** Deterministic JSON with recursively sorted keys — identical to mcp-schemas.stableStringify. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

/** v2 agent-authorization canonical payload — identical to mcp-schemas.canonicalAuthorizationPayload. */
export function canonicalAuthorizationPayload(input: {
  nonce: string;
  actionType: string;
  actionDescription: string;
  params: Record<string, unknown>;
}): string {
  return (
    `{"v":2,"type":"agent-authorization","nonce":${JSON.stringify(input.nonce)},` +
    `"actionType":${JSON.stringify(input.actionType)},"action":${JSON.stringify(input.actionDescription)},` +
    `"params":${stableStringify(input.params)}}`
  );
}

/** Short verification code (first 8 hex of SHA-256 of the canonical payload), grouped XXXX-XXXX. */
export function verificationCode(canonical: string): string {
  const hex = crypto.createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex").slice(0, 8).toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
}

/** Verify a raw ECDSA P-256 signature (base64, DER or IEEE-P1363) over `payload` against an SPKI key. */
export function verifyEcdsaP256(publicKeyB64: string, payload: string, signatureB64: string): boolean {
  try {
    const keyObject = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    const signature = Buffer.from(signatureB64, "base64");
    const dsaEncoding = signature.length === 64 ? "ieee-p1363" : "der";
    return crypto.verify("sha256", Buffer.from(payload, "utf8"), { key: keyObject, dsaEncoding }, signature);
  } catch {
    return false;
  }
}

function parseNonce(canonical: string): string {
  try {
    return (JSON.parse(canonical) as { nonce: string }).nonce;
  } catch {
    return "";
  }
}

/**
 * Independently verify an approval receipt against the instruction you are ABOUT to execute. Recomputes
 * the canonical payload from your params, confirms it byte-matches what was signed, and verifies the
 * human's P-256 or WebAuthn signature — with no SÄKRA secret. Defense-in-depth twin of gateway
 * /authorize/verify. Returns `{ ok: false, reason }` on any mismatch.
 */
export function verifyApprovalReceipt(
  receipt: ApprovalReceipt,
  expected: { actionType: string; params: Record<string, unknown> },
  opts: { allowAutoApproved?: boolean } = {},
): { ok: boolean; reason?: string; autoApproved?: boolean } {
  const recomputed = canonicalAuthorizationPayload({
    nonce: parseNonce(receipt.canonicalPayload),
    actionType: expected.actionType,
    actionDescription: receipt.actionDescription,
    params: expected.params,
  });
  if (recomputed !== receipt.canonicalPayload) return { ok: false, reason: "params/actionType do not match what was approved" };
  // A policy AUTO_APPROVED receipt carries NO human signature — there is nothing to cryptographically
  // verify, and such a receipt is trivially forgeable. We therefore REFUSE to attest it by default
  // (so `if (!verify().ok) throw` correctly blocks unsigned approvals). A relying party that has
  // consciously accepted policy pre-approval / break-glass must opt in with `allowAutoApproved: true`.
  if (receipt.sigAlg === "AUTO_APPROVED") {
    return opts.allowAutoApproved
      ? { ok: true, autoApproved: true }
      : { ok: false, autoApproved: true, reason: "auto-approved by policy — no human signature to verify (pass { allowAutoApproved: true } to accept)" };
  }
  if (!receipt.signerPublicKey || !receipt.signature) return { ok: false, reason: "receipt missing signature material" };

  const isWebAuthn = receipt.sigAlg === "WEBAUTHN";

  if (isWebAuthn) {
    if (!receipt.authenticatorData || !receipt.clientDataJSON) {
      return { ok: false, reason: "WebAuthn receipt missing authenticatorData or clientDataJSON" };
    }
    try {
      const clientDataBuf = Buffer.from(receipt.clientDataJSON, "base64");
      const clientDataStr = clientDataBuf.toString("utf-8");
      const clientData = JSON.parse(clientDataStr) as { challenge: string };

      const expectedChallenge = base64url(receipt.canonicalPayload);
      const clientChallengeClean = clientData.challenge.replace(/=/g, "");
      if (clientChallengeClean !== expectedChallenge) {
        return { ok: false, reason: "clientDataJSON challenge does not match canonical payload" };
      }

      const coseBuf = Buffer.from(receipt.signerPublicKey, "base64");
      const { x, y } = parseCosePublicKey(coseBuf);
      const keyObject = crypto.createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x, y } });

      const authDataBuf = Buffer.from(receipt.authenticatorData, "base64");
      const clientDataHash = crypto.createHash("sha256").update(clientDataBuf).digest();
      const signatureVerifyData = Buffer.concat([authDataBuf, clientDataHash]);

      const signatureBuf = Buffer.from(receipt.signature, "base64");
      const verified = crypto.verify(undefined, signatureVerifyData, { key: keyObject, dsaEncoding: "der" }, signatureBuf);

      if (!verified) return { ok: false, reason: "WebAuthn signature does not verify against signer key" };
      return { ok: true };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: `WebAuthn verification failed: ${msg}` };
    }
  } else {
    if (!verifyEcdsaP256(receipt.signerPublicKey, receipt.canonicalPayload, receipt.signature)) {
      return { ok: false, reason: "signature does not verify against signer key" };
    }
    return { ok: true };
  }
}

// ─── Audit ledger inclusion proofs ───────────────────────────────────────────
// The other half of "inspect-it-yourself": confirm an audit event is committed to SÄKRA's append-only
// Merkle log against an independently anchored daily root. Same zero-dependency, no-secret contract as
// the approval-receipt verifier above. See @sakra-trust/ledger (SPEC.md) for the format and the
// published end-of-day roots. Surfaced on the CLI as `sakra audit-verify`.

export {
  sha256Hex,
  hashLeaf,
  hashPair,
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  type ProofStep,
} from "./ledger-merkle.js";

export { canonicalPreimage, leafHash, type AuditLeaf } from "./ledger-leaf.js";

export { verifyInclusionProof, type InclusionProof } from "./ledger-proof.js";

export {
  verifyBundle,
  BUNDLE_KIND,
  type ProofBundle,
  type BundleVerification,
  type CheckResult,
  type VerifyOptions,
} from "./ledger-bundle.js";
export {
  verifyEvidenceBundle,
  EVIDENCE_BUNDLE_KIND,
  type EvidenceBundle,
  type EvidenceEntry,
  type EvidenceVerification,
  type EvidenceVerifyOptions,
} from "./ledger-evidence.js";
