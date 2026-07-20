// @sakra-trust/verify — independently confirm that a human cryptographically approved EXACTLY the action
// you are about to run. Zero runtime dependencies (node:crypto only), no network, and NO SÄKRA secret:
// a relying party recomputes the canonical payload from its own params, checks it byte-matches what was
// signed, and verifies the human's P-256 / WebAuthn signature. This is the "inspect-it-yourself" trust
// artifact — the whole point is that you don't have to take SÄKRA's word for it.
//
// The canonicalization + hashing here MUST stay byte-for-byte identical to @sakra-trust/mcp-schemas and the
// mobile wallet, or signatures won't verify. Do not "tidy" the JSON shapes.

import crypto from "node:crypto"

/** A verifiable proof of what the human approved — returned once a challenge is APPROVED. */
export interface ApprovalReceipt {
  canonicalPayload: string // the exact bytes the human's key signed
  actionType?: string | null
  actionDescription: string
  params: Record<string, unknown>
  signerDid?: string | null
  signerPublicKey?: string | null // base64 SPKI or base64 COSE public key
  signature?: string | null // base64 signature over canonicalPayload
  sigAlg?: string | null // "ES256" | "WEBAUTHN" | "AUTO_APPROVED"
  authenticatorData?: string | null // base64url (WEBAUTHN only)
  clientDataJSON?: string | null // base64url (WEBAUTHN only)
  verificationCode: string
}

function base64url(str: string | Buffer): string {
  const buf = typeof str === "string" ? Buffer.from(str, "utf-8") : str
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

// ─── Minimal CBOR reader (COSE_Key only) ─────────────────────────────────────
// Just enough CBOR to walk a COSE_Key map: ints, byte/text strings, arrays, maps. Deliberately NOT a
// general decoder and deliberately not a dependency — this package ships with zero runtime deps so a
// relying party can audit every byte of it. Anything outside that subset is rejected rather than guessed.

type CborValue = number | Buffer | string | CborValue[] | Map<CborValue, CborValue>

function cborFail(detail: string): never {
  throw new Error(`Invalid COSE public key format: ${detail}`)
}

function requireBytes(buf: Buffer, pos: number, len: number) {
  if (pos + len > buf.length) cborFail("truncated CBOR item")
}

function readHead(buf: Buffer, pos: number): { major: number; value: number; pos: number } {
  requireBytes(buf, pos, 1)
  const initial = buf.readUInt8(pos)
  const major = initial >> 5
  const info = initial & 0x1f
  let next = pos + 1
  let value: number
  if (info < 24) value = info
  else if (info === 24) {
    requireBytes(buf, next, 1)
    value = buf.readUInt8(next)
    next += 1
  } else if (info === 25) {
    requireBytes(buf, next, 2)
    value = buf.readUInt16BE(next)
    next += 2
  } else if (info === 26) {
    requireBytes(buf, next, 4)
    value = buf.readUInt32BE(next)
    next += 4
  } else {
    // 27 = 64-bit, 28-30 reserved, 31 = indefinite length. No COSE_Key needs any of them.
    cborFail("unsupported CBOR length encoding")
  }
  return { major, value, pos: next }
}

function decodeItem(buf: Buffer, pos: number): { value: CborValue; pos: number } {
  const head = readHead(buf, pos)
  switch (head.major) {
    case 0: // unsigned int
      return { value: head.value, pos: head.pos }
    case 1: // negative int — COSE labels like -1 (crv), -2 (x), -3 (y)
      return { value: -1 - head.value, pos: head.pos }
    case 2: // byte string
      requireBytes(buf, head.pos, head.value)
      return { value: buf.subarray(head.pos, head.pos + head.value), pos: head.pos + head.value }
    case 3: // text string
      requireBytes(buf, head.pos, head.value)
      return {
        value: buf.toString("utf-8", head.pos, head.pos + head.value),
        pos: head.pos + head.value,
      }
    case 4: {
      const items: CborValue[] = []
      let cursor = head.pos
      for (let i = 0; i < head.value; i++) {
        const item = decodeItem(buf, cursor)
        items.push(item.value)
        cursor = item.pos
      }
      return { value: items, pos: cursor }
    }
    case 5: {
      const map = new Map<CborValue, CborValue>()
      let cursor = head.pos
      for (let i = 0; i < head.value; i++) {
        const key = decodeItem(buf, cursor)
        const val = decodeItem(buf, key.pos)
        map.set(key.value, val.value)
        cursor = val.pos
      }
      return { value: map, pos: cursor }
    }
    default:
      return cborFail(`unsupported CBOR major type ${head.major}`)
  }
}

/**
 * Extract the P-256 coordinates from a WebAuthn COSE_Key. This walks the CBOR structure rather than
 * scanning for the `0x21 0x58 0x20` / `0x22 0x58 0x20` byte patterns: a raw search can match those
 * bytes *inside* another field's payload, and it cannot tell whether the 32 bytes it slices actually
 * exist (a truncated buffer silently yields a short coordinate). We also pin kty/crv so a key for some
 * other curve can never be reinterpreted as P-256.
 */
function parseCosePublicKey(coseBuffer: Buffer): { x: string; y: string } {
  // Decode only the leading item; trailing bytes are tolerated, as some wallets slice the COSE key out
  // of attestedCredentialData without trimming what follows it.
  const { value } = decodeItem(coseBuffer, 0)
  if (!(value instanceof Map)) cborFail("expected a CBOR map")

  const kty = value.get(1)
  if (kty !== 2) cborFail(`expected kty EC2 (2), got ${String(kty)}`)
  const crv = value.get(-1)
  if (crv !== 1) cborFail(`expected crv P-256 (1), got ${String(crv)}`)
  const alg = value.get(3)
  if (alg !== undefined && alg !== -7) cborFail(`expected alg ES256 (-7), got ${String(alg)}`)

  const coordinate = (label: number, name: string): Buffer => {
    const raw = value.get(label)
    if (!Buffer.isBuffer(raw)) cborFail(`missing ${name} coordinate`)
    if (raw.length !== 32) cborFail(`${name} coordinate must be 32 bytes, got ${raw.length}`)
    return raw
  }
  return { x: base64url(coordinate(-2, "x")), y: base64url(coordinate(-3, "y")) }
}

/** Deterministic JSON with recursively sorted keys — identical to mcp-schemas.stableStringify. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null"
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`
}

/** v2 agent-authorization canonical payload — identical to mcp-schemas.canonicalAuthorizationPayload. */
export function canonicalAuthorizationPayload(input: {
  nonce: string
  actionType: string
  actionDescription: string
  params: Record<string, unknown>
}): string {
  return (
    `{"v":2,"type":"agent-authorization","nonce":${JSON.stringify(input.nonce)},` +
    `"actionType":${JSON.stringify(input.actionType)},"action":${JSON.stringify(input.actionDescription)},` +
    `"params":${stableStringify(input.params)}}`
  )
}

/** Short verification code (first 8 hex of SHA-256 of the canonical payload), grouped XXXX-XXXX. */
export function verificationCode(canonical: string): string {
  const hex = crypto
    .createHash("sha256")
    .update(Buffer.from(canonical, "utf8"))
    .digest("hex")
    .slice(0, 8)
    .toUpperCase()
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`
}

/** Verify a raw ECDSA P-256 signature (base64, DER or IEEE-P1363) over `payload` against an SPKI key. */
export function verifyEcdsaP256(publicKeyB64: string, payload: string, signatureB64: string): boolean {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
    })
    const signature = Buffer.from(signatureB64, "base64")
    const dsaEncoding = signature.length === 64 ? "ieee-p1363" : "der"
    return crypto.verify("sha256", Buffer.from(payload, "utf8"), { key: keyObject, dsaEncoding }, signature)
  } catch {
    return false
  }
}

function parseNonce(canonical: string): string {
  try {
    return (JSON.parse(canonical) as { nonce: string }).nonce
  } catch {
    return ""
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
  })
  if (recomputed !== receipt.canonicalPayload)
    return {
      ok: false,
      reason: "params/actionType do not match what was approved",
    }
  // A policy AUTO_APPROVED receipt carries NO human signature — there is nothing to cryptographically
  // verify, and such a receipt is trivially forgeable. We therefore REFUSE to attest it by default
  // (so `if (!verify().ok) throw` correctly blocks unsigned approvals). A relying party that has
  // consciously accepted policy pre-approval / break-glass must opt in with `allowAutoApproved: true`.
  if (receipt.sigAlg === "AUTO_APPROVED") {
    return opts.allowAutoApproved
      ? { ok: true, autoApproved: true }
      : {
          ok: false,
          autoApproved: true,
          reason:
            "auto-approved by policy — no human signature to verify (pass { allowAutoApproved: true } to accept)",
        }
  }
  if (!receipt.signerPublicKey || !receipt.signature)
    return { ok: false, reason: "receipt missing signature material" }

  const isWebAuthn = receipt.sigAlg === "WEBAUTHN"

  if (isWebAuthn) {
    if (!receipt.authenticatorData || !receipt.clientDataJSON) {
      return {
        ok: false,
        reason: "WebAuthn receipt missing authenticatorData or clientDataJSON",
      }
    }
    try {
      const clientDataBuf = Buffer.from(receipt.clientDataJSON, "base64")
      const clientDataStr = clientDataBuf.toString("utf-8")
      const clientData = JSON.parse(clientDataStr) as { challenge: string }

      const expectedChallenge = base64url(receipt.canonicalPayload)
      const clientChallengeClean = clientData.challenge.replace(/=/g, "")
      if (clientChallengeClean !== expectedChallenge) {
        return {
          ok: false,
          reason: "clientDataJSON challenge does not match canonical payload",
        }
      }

      const coseBuf = Buffer.from(receipt.signerPublicKey, "base64")
      const { x, y } = parseCosePublicKey(coseBuf)
      const keyObject = crypto.createPublicKey({
        format: "jwk",
        key: { kty: "EC", crv: "P-256", x, y },
      })

      const authDataBuf = Buffer.from(receipt.authenticatorData, "base64")
      const clientDataHash = crypto.createHash("sha256").update(clientDataBuf).digest()
      const signatureVerifyData = Buffer.concat([authDataBuf, clientDataHash])

      const signatureBuf = Buffer.from(receipt.signature, "base64")
      const verified = crypto.verify(
        undefined,
        signatureVerifyData,
        { key: keyObject, dsaEncoding: "der" },
        signatureBuf,
      )

      if (!verified)
        return {
          ok: false,
          reason: "WebAuthn signature does not verify against signer key",
        }
      return { ok: true }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      return { ok: false, reason: `WebAuthn verification failed: ${msg}` }
    }
  } else {
    if (!verifyEcdsaP256(receipt.signerPublicKey, receipt.canonicalPayload, receipt.signature)) {
      return {
        ok: false,
        reason: "signature does not verify against signer key",
      }
    }
    return { ok: true }
  }
}

// ─── Audit ledger inclusion proofs ───────────────────────────────────────────
// The other half of "inspect-it-yourself": confirm an audit event is committed to SÄKRA's append-only
// Merkle log against an independently anchored daily root. Same zero-dependency, no-secret contract as
// the approval-receipt verifier above. See @sakra-trust/ledger (SPEC.md) for the format and the
// published end-of-day roots. Surfaced on the CLI as `sakra audit-verify`.

export {
  BUNDLE_KIND,
  type BundleVerification,
  type CheckResult,
  type ProofBundle,
  type VerifyOptions,
  verifyBundle,
} from "./ledger-bundle.js"
export {
  EVIDENCE_BUNDLE_KIND,
  type EvidenceBundle,
  type EvidenceEntry,
  type EvidenceVerification,
  type EvidenceVerifyOptions,
  verifyEvidenceBundle,
} from "./ledger-evidence.js"
export { type AuditLeaf, canonicalPreimage, leafHash } from "./ledger-leaf.js"
export {
  hashLeaf,
  hashPair,
  merkleProof,
  merkleRoot,
  type ProofStep,
  sha256Hex,
  verifyMerkleProof,
} from "./ledger-merkle.js"
export { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"
