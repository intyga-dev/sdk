/**
 * The customer-authored trust-anchor file — the DID-mode counterpart of INTYGA_APPROVER_KEYS.
 *
 * This file IS the relying party's pinning (DIV §4.4.6, identity-associating anchor): it names the
 * approver identities that may sign, and for each stable DID the public keys that speak for it.
 * It is exported from the console (or written by hand) and carried in the RP's own configuration,
 * so — unlike the offline Trust Bundle (`trust-bundle.ts`), which travels through the gateway at
 * incident time and is therefore a gateway-SIGNED artifact — it carries no signature: adopting the
 * file into your configuration is itself the act of trust, exactly like pinning a CA bundle.
 *
 * Self-certifying entries (`did:intyga:key:…`) may list no keys at all: the DID itself commits to
 * the enrolled key, and the verifier checks the receipt-carried key against that commitment
 * (see SELF_CERTIFYING_DID_PREFIX in @intyga/verify).
 */
import { type ApproverTrustAnchor, SELF_CERTIFYING_DID_PREFIX } from "@intyga/verify"
import type { BundleApprover } from "./trust-bundle.js"

export const TRUST_ANCHOR_FILE_TYPE = "intyga-trust-anchor"

/**
 * What an anchor is FOR, and so which keys it may pin. `online` pins passkeys and node keys and
 * verifies ordinary approval receipts; `offline` pins offline signing keys only and verifies DIV §5a
 * offline approvals. Two files, never one: a bare offline key — no origin binding, no user
 * verification — must not satisfy a relying party that verifies online approvals.
 *
 * A file with no `purpose` predates the field. Every file exported before it was an online anchor, so
 * that is how one is read.
 */
export type TrustAnchorPurpose = "online" | "offline"

export interface TrustAnchorFile {
  type: typeof TRUST_ANCHOR_FILE_TYPE
  v: 1
  /** Always set after parsing; absent in the file means `online`. */
  purpose: TrustAnchorPurpose
  /**
   * Monotonic export counter for this scope. Lets a relying party — or a human diffing two copies —
   * detect that one anchor is older than another. It carries no cryptographic weight: freshness of
   * the pinned set is an operational property (rotate the file when approvers come and go), not
   * something the file can prove about itself.
   */
  epoch: number
  /** What the export was scoped to (an approval rule, a service). Display only. */
  label?: string
  /** The approver identities this RP trusts, each with every public key bound to them at export time. */
  approvers: BundleApprover[]
  /**
   * The WebAuthn expectations of the approval console the approvers sign in — its origin and RP ID.
   * Passkey receipts cannot verify without them (the verifier fails closed), so exports SHOULD
   * carry them; a flag or environment variable still wins over the file.
   */
  webauthn?: { origin: string; rpId: string }
  exportedAt?: string
}

const fail = (detail: string): never => {
  throw new Error(`invalid trust-anchor file: ${detail}`)
}

const isBase64 = (s: string): boolean => {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return false
  return Buffer.from(s, "base64").length > 0
}

/**
 * Parse and validate a trust-anchor file. Throws with a precise, single-problem reason — a trust
 * anchor is security configuration, so a malformed one must fail loudly at load time rather than
 * surface later as an unverifiable receipt.
 *
 * `purpose` is what the CALLER is about to verify, and the file must say the same: an offline anchor
 * handed to an online verifier (or the reverse) is refused rather than trusted. It defaults to
 * `online`, so a caller that does not think about it can never pin offline keys by accident.
 */
export function parseTrustAnchorFile(
  jsonText: string,
  opts: { purpose?: TrustAnchorPurpose } = {},
): TrustAnchorFile {
  const expected = opts.purpose ?? "online"
  let raw: unknown
  try {
    raw = JSON.parse(jsonText)
  } catch (err) {
    return fail(`not valid JSON (${err instanceof Error ? err.message : String(err)})`)
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return fail("root must be an object")
  const obj = raw as Record<string, unknown>

  if (obj.type !== TRUST_ANCHOR_FILE_TYPE)
    return fail(
      `type must be "${TRUST_ANCHOR_FILE_TYPE}" — a div-trust-bundle JWS (offline approval) is a different, gateway-signed artifact and cannot be used here`,
    )
  if (obj.v !== 1) return fail(`unsupported version ${JSON.stringify(obj.v)} (expected 1)`)
  const purpose = obj.purpose === undefined ? "online" : obj.purpose
  if (purpose !== "online" && purpose !== "offline")
    return fail(`purpose must be "online" or "offline", got ${JSON.stringify(obj.purpose)}`)
  if (purpose !== expected)
    return fail(
      `this is an ${purpose} anchor, but it is being loaded to verify ${expected} approvals — export the ${expected} anchor instead`,
    )
  if (typeof obj.epoch !== "number" || !Number.isInteger(obj.epoch) || obj.epoch < 0)
    return fail("epoch must be a non-negative integer")
  if (obj.label !== undefined && typeof obj.label !== "string") return fail("label must be a string")
  if (obj.exportedAt !== undefined && typeof obj.exportedAt !== "string")
    return fail("exportedAt must be a string")

  if (!Array.isArray(obj.approvers) || obj.approvers.length === 0)
    return fail("approvers must be a non-empty array — an empty anchor would trust nobody")
  const seen = new Set<string>()
  for (const entry of obj.approvers) {
    if (typeof entry !== "object" || entry === null) return fail("every approvers[] entry must be an object")
    const { did, publicKeys } = entry as Record<string, unknown>
    if (typeof did !== "string" || !did.startsWith("did:"))
      return fail(`approver did ${JSON.stringify(did)} must be a string starting with "did:"`)
    if (seen.has(did)) return fail(`duplicate approver did ${did}`)
    seen.add(did)
    if (!Array.isArray(publicKeys)) return fail(`approver ${did}: publicKeys must be an array`)
    for (const key of publicKeys) {
      if (typeof key !== "string" || !isBase64(key))
        return fail(`approver ${did}: every publicKeys[] entry must be a base64 SPKI or COSE key`)
    }
    // A stable DID with no keys can never satisfy verification — refuse at load, where the problem
    // is diagnosable, instead of at verify time where it reads as a bad receipt. Self-certifying
    // DIDs are the deliberate exception: their key travels in the receipt and is checked by hash.
    // An offline anchor has no such exception: a DID commits to its ONLINE key, not to an offline
    // signing key its owner chose to register.
    if (publicKeys.length === 0 && purpose === "offline")
      return fail(`approver ${did} has no publicKeys — an offline anchor must pin every offline key`)
    if (publicKeys.length === 0 && !did.startsWith(SELF_CERTIFYING_DID_PREFIX))
      return fail(
        `approver ${did} has no publicKeys and is not self-certifying (${SELF_CERTIFYING_DID_PREFIX}…) — a receipt from them could never verify`,
      )
  }

  if (obj.webauthn !== undefined) {
    const w = obj.webauthn as Record<string, unknown>
    if (typeof w !== "object" || w === null) return fail("webauthn must be an object")
    if (typeof w.origin !== "string" || !/^https?:\/\//.test(w.origin))
      return fail("webauthn.origin must be an http(s) origin string")
    if (typeof w.rpId !== "string" || w.rpId.length === 0)
      return fail("webauthn.rpId must be a non-empty string")
  }

  return { ...(obj as unknown as TrustAnchorFile), purpose }
}

/**
 * Build the verifier's trust anchor from a parsed file: DID mode, one identity per approver no
 * matter how many keys they hold. `limitToDids` narrows the eligible set (e.g. to one approval
 * rule's approvers) without widening anything — a DID not in the file resolves to nothing.
 */
export function trustAnchorApprovers(file: TrustAnchorFile, limitToDids?: string[]): ApproverTrustAnchor {
  const eligible = limitToDids ? file.approvers.filter((a) => limitToDids.includes(a.did)) : file.approvers
  const byDid = new Map(eligible.map((a) => [a.did, a.publicKeys]))
  return {
    dids: [...byDid.keys()],
    resolveKey: (did) => {
      const keys = byDid.get(did)
      return keys && keys.length > 0 ? keys : null
    },
  }
}
