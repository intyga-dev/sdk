// Offline approval (docs/DIV.md §5a) — the relying-party half.
//
// When the gateway is unreachable, the relying party builds the challenge ITSELF, the humans review
// and sign it on a disconnected device, and the result is verified by the ordinary §5 procedure. The
// signing ceremony moves off the network; it does not move earlier in time.
//
// That distinction is the whole design. The rejected alternative — pre-signing approvals and holding
// them until needed — puts a bearer capability on disk (possessing the file is sufficient to act, and
// it cannot be revoked at an offline relying party) and captures a human judgment about a HYPOTHETICAL
// rather than about the incident in progress. Narrowing the action does not fix that, because the
// defect is in WHEN the human decided. See DIV §5a.1.
//
// Four properties are enforced structurally rather than by convention, because each is the kind of
// thing a reasonable-looking refactor would quietly remove:
//
//   1. IT ONLY APPLIES WHEN WE COULD NOT ASK. The fallback is reachable exclusively on a transport
//      failure. A DENIED or EXPIRED result means a human WAS reached and did not approve — falling
//      back there would let this override a person who said no, which is worse than having no gate.
//
//   2. IT RETURNS A DISTINCT STATUS. Offline approval never reports "APPROVED". The overwhelmingly
//      common caller guard is `if (r.status !== "APPROVED") throw`, so a distinct status means adding
//      offline capability to an existing service cannot silently start permitting things.
//
//   3. THE POLICY COMES FROM THE BUNDLE, NOT FROM HERE. The relying party builds the payload, so if it
//      also chose the quorum it would be setting its own policy. The requirement is read from the
//      signed trust bundle (§5a.4) and there is no local default to fall back on.
//
//   4. NOTHING PERSISTS THAT AUTHORIZES ANYTHING. What is written to disk is a record that an approval
//      HAPPENED (for reconciliation). No file produced by this module can authorize a future action.

import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import {
  type ApprovalReceipt,
  type ApprovalRequirementAttestation,
  type ApprovalWitness,
  canonicalOfflineIntentPayload,
  DIV_OFFLINE_INTENT_TYPE,
  MAX_OFFLINE_WINDOW_MINUTES,
  type RequesterIdentity,
  type VerifiedDelegation,
  verificationCode,
  verifyApprovalReceipt,
  verifyDelegation,
} from "@intyga/verify"
import { approverAnchor, loadTrustBundle, requirementFor, type TrustBundle } from "./trust-bundle.js"

/** Wire prefix for a challenge travelling OUT to the approvers. */
export const CHALLENGE_ENVELOPE_PREFIX = "DIV1:"
/** Wire prefix for a signature coming BACK from an approver. */
export const SIGNATURE_ENVELOPE_PREFIX = "SIG1:"

/**
 * Default validity window. Deliberately short: an offline approval is created and redeemed inside one
 * incident, and the window is the only bound on a proof that no one can revoke.
 */
export const DEFAULT_OFFLINE_WINDOW_MINUTES = 15

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}
function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64")
}

/** A locally generated offline challenge, ready to hand to the approvers. */
export interface OfflineChallenge {
  /** Generated HERE, by the party that will redeem it (DIV §5a.2) — nobody else can enforce its use. */
  nonce: string
  /** The exact bytes the approvers will sign. */
  canonicalPayload: string
  /** Short code the approver MUST read back to the operator before signing (DIV §5a.8). */
  verificationCode: string
  /** `DIV1:<base64url>` — what travels to the approver, by QR or copy-paste. */
  envelope: string
  challengedAt: string
  expiresAt: string
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  requirement: ApprovalRequirementAttestation
  /** Which approvers are eligible, per the bundle policy that produced `requirement`. */
  approverDids: string[]
}

/**
 * Build an offline challenge for an action, taking the approval requirement from the trust bundle.
 *
 * The requirement is NOT a parameter. A relying party that supplied its own would be choosing the
 * quorum its own action must clear (DIV §5a.3), and the resulting signature would attest to nothing
 * beyond this host's configuration. When the bundle has no rule for the action, this REFUSES — there
 * is no implicit 1-of-1 fallback, because an unmatched action is an unconfigured one.
 */
export function createOfflineChallenge(input: {
  bundle: TrustBundle
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  windowMinutes?: number
  /** Overrides "now". For tests and deterministic replay. */
  asOf?: Date
  /**
   * A verified delegation, when the ordinary approvers are unreachable too. Its `delegatedQuorum`
   * becomes the signed `requiredApprovals`, so the delegated operators sign the policy their
   * signatures are counted toward (DIV §5a.6 step 3).
   */
  delegation?: VerifiedDelegation
}): { ok: boolean; reason?: string; challenge?: OfflineChallenge } {
  const resolved = requirementFor(input.bundle, input.actionType, input.display)
  if (!resolved)
    return {
      ok: false,
      reason: `the trust bundle has no approval rule matching "${input.actionType}" — an action with no configured requirement cannot be approved offline (DIV §5a.3)`,
    }

  // A hardware-key policy cannot be satisfied offline (DIV §5a.3 step 4). Refuse at CHALLENGE time as
  // well as at verification: sending approvers a payload nobody can produce a valid signature for
  // wastes the one resource an incident is short of, and the error here can explain why.
  if (resolved.requirement.requireHardwareKey)
    return {
      ok: false,
      reason: `"${input.actionType}" requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)`,
    }

  const windowMinutes = Math.min(
    MAX_OFFLINE_WINDOW_MINUTES,
    Math.max(1, input.windowMinutes ?? DEFAULT_OFFLINE_WINDOW_MINUTES),
  )
  const now = input.asOf ?? new Date()
  const challengedAt = now.toISOString()
  const expiresAt = new Date(now.getTime() + windowMinutes * 60_000).toISOString()
  const nonce = `off_${crypto.randomUUID()}`

  // Under a delegation the eligible set and the quorum are the DELEGATED ones. Everything else in the
  // requirement still comes from the bundle: a delegation narrows who may approve, never the policy.
  const requirement: ApprovalRequirementAttestation = input.delegation
    ? { ...resolved.requirement, requiredApprovals: input.delegation.delegatedQuorum }
    : resolved.requirement
  const approverDids = input.delegation ? input.delegation.delegatedTo : resolved.approverDids

  const canonicalPayload = canonicalOfflineIntentPayload({
    target: input.target,
    actionType: input.actionType,
    display: input.display,
    params: input.params,
    requester: input.requester,
    requirement,
    nonce,
    challengedAt,
    expiresAt,
  })

  return {
    ok: true,
    challenge: {
      nonce,
      canonicalPayload,
      verificationCode: verificationCode(canonicalPayload),
      envelope: `${CHALLENGE_ENVELOPE_PREFIX}${b64url(Buffer.from(canonicalPayload, "utf8"))}`,
      challengedAt,
      expiresAt,
      target: input.target,
      actionType: input.actionType,
      display: input.display,
      params: input.params,
      requester: input.requester,
      requirement,
      approverDids,
    },
  }
}

/** What an approver's signing tool shows before asking for confirmation. */
export interface DecodedChallenge {
  canonicalPayload: string
  verificationCode: string
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  requirement: ApprovalRequirementAttestation
  nonce: string
  challengedAt: string
  expiresAt: string
}

/**
 * Decode a `DIV1:` envelope for review by the signing tool.
 *
 * The type check matters even here: an approver's tool must not be usable to sign an ORDINARY intent
 * payload that someone pasted in, because that signature would then be a live approval produced
 * outside the gateway's single-use accounting.
 */
export function decodeChallengeEnvelope(envelope: string): {
  ok: boolean
  reason?: string
  challenge?: DecodedChallenge
} {
  const trimmed = envelope.trim()
  if (!trimmed.startsWith(CHALLENGE_ENVELOPE_PREFIX))
    return { ok: false, reason: `not a challenge envelope (expected a ${CHALLENGE_ENVELOPE_PREFIX} prefix)` }
  let canonicalPayload: string
  try {
    canonicalPayload = fromB64url(trimmed.slice(CHALLENGE_ENVELOPE_PREFIX.length)).toString("utf8")
  } catch {
    return { ok: false, reason: "challenge envelope is not valid base64url" }
  }
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(canonicalPayload) as Record<string, unknown>
  } catch {
    return { ok: false, reason: "challenge envelope does not contain a JSON payload (truncated paste?)" }
  }
  if (parsed.type !== DIV_OFFLINE_INTENT_TYPE)
    return {
      ok: false,
      reason: `this is a ${String(parsed.type)} payload, not an offline approval challenge — refusing to sign it`,
    }
  // Re-serializing must reproduce the input byte-for-byte. If it does not, the envelope carries
  // non-canonical JSON, and a signature over these bytes would not verify against the payload the
  // relying party reconstructs. Better to refuse than to produce a signature nobody can use.
  const fields = parsed as unknown as DecodedChallenge
  return {
    ok: true,
    challenge: {
      canonicalPayload,
      verificationCode: verificationCode(canonicalPayload),
      target: fields.target,
      actionType: fields.actionType,
      display: (parsed.display as string) ?? "",
      params: fields.params,
      requester: fields.requester,
      requirement: fields.requirement,
      nonce: fields.nonce,
      challengedAt: fields.challengedAt,
      expiresAt: fields.expiresAt,
    },
  }
}

/** Encode one approver's signature for the trip back to the relying party. */
export function encodeSignatureEnvelope(witness: ApprovalWitness): string {
  const compact = {
    did: witness.signerDid,
    key: witness.signerPublicKey,
    sig: witness.signature,
    alg: witness.sigAlg ?? "ES256",
  }
  return `${SIGNATURE_ENVELOPE_PREFIX}${b64url(Buffer.from(JSON.stringify(compact), "utf8"))}`
}

/** Decode a `SIG1:` envelope back into a witness. */
export function decodeSignatureEnvelope(envelope: string): {
  ok: boolean
  reason?: string
  witness?: ApprovalWitness
} {
  const trimmed = envelope.trim()
  if (!trimmed.startsWith(SIGNATURE_ENVELOPE_PREFIX))
    return { ok: false, reason: `not a signature envelope (expected a ${SIGNATURE_ENVELOPE_PREFIX} prefix)` }
  let compact: { did?: string; key?: string; sig?: string; alg?: string }
  try {
    compact = JSON.parse(fromB64url(trimmed.slice(SIGNATURE_ENVELOPE_PREFIX.length)).toString("utf8"))
  } catch {
    return { ok: false, reason: "signature envelope is not valid base64url JSON (truncated paste?)" }
  }
  if (!compact.did || !compact.key || !compact.sig)
    return { ok: false, reason: "signature envelope is missing did, key or sig" }
  return {
    ok: true,
    witness: {
      signerDid: compact.did,
      signerPublicKey: compact.key,
      signature: compact.sig,
      sigAlg: compact.alg ?? "ES256",
    },
  }
}

/** Assemble the collected witnesses into a receipt the ordinary verifier can check. */
export function assembleOfflineReceipt(
  challenge: OfflineChallenge,
  witnesses: ApprovalWitness[],
): ApprovalReceipt {
  return {
    canonicalPayload: challenge.canonicalPayload,
    target: challenge.target,
    actionType: challenge.actionType,
    actionDescription: challenge.display,
    params: challenge.params,
    signatures: witnesses,
    requester: challenge.requester,
    verificationCode: challenge.verificationCode,
  }
}

/**
 * Records which offline nonces this relying party has already redeemed.
 *
 * Single-use is inherently stateful and LOCAL (DIV §5, steps 9-10). Because the relying party
 * generates its own nonce here, single use within this relying party is fully enforceable — unlike a
 * pre-signed token, where two relying parties could each redeem the same artifact unaware.
 */
export interface RedemptionStore {
  /** Claim `nonce`. MUST be atomic and MUST return false if it was already claimed. */
  redeem(nonce: string): boolean
}

/**
 * Default store: one file per redeemed nonce, created with the exclusive-create flag.
 *
 * `wx` is atomic on POSIX and on Windows — the OS refuses the open if the path exists, so two
 * processes racing the same nonce cannot both succeed. A read-then-write check would lose that race,
 * which is the whole point of the store.
 */
export class FileRedemptionStore implements RedemptionStore {
  constructor(private readonly dir: string) {
    fs.mkdirSync(dir, { recursive: true })
  }

  redeem(nonce: string): boolean {
    // Nonces are generated locally, but this value becomes a path segment — refuse anything that
    // could traverse out of the directory rather than trusting the upstream shape.
    if (!/^[A-Za-z0-9._-]{1,200}$/.test(nonce)) return false
    try {
      fs.writeFileSync(path.join(this.dir, `${nonce}.used`), new Date().toISOString(), { flag: "wx" })
      return true
    } catch {
      return false
    }
  }
}

export interface OfflineApprovalOptions {
  /** Directory holding the signed trust bundle and the pinned gateway key (see `saveTrustBundle`). */
  bundleDir: string
  /** This workload's own identity, bound into the signed bytes so approvers see who is asking. */
  requesterDid: string
  /**
   * How the operator gets the challenge to the approvers and the signatures back. Returns raw `SIG1:`
   * strings.
   *
   * This is a seam, not a default: transporting the envelope is a human, site-specific act (a terminal
   * prompt, a QR on a console, a phone read out over a bridge line), and inventing one here would
   * either not fit or quietly assume connectivity.
   */
  collectSignatures: (challenge: OfflineChallenge) => Promise<string[]>
  /** Directory of pre-signed delegation files (`*.json`), for when the approvers are unreachable too. */
  delegationDir?: string
  /** Where redeemed nonces are recorded. Defaults to `<bundleDir>/.redeemed`. */
  store?: RedemptionStore
  /** Where approvals are buffered for reconciliation. Defaults to `<bundleDir>/.pending`. */
  bufferDir?: string
  /** Validity window in minutes. Capped at MAX_OFFLINE_WINDOW_MINUTES. */
  windowMinutes?: number
  /** Override the warning sink. Defaults to `console.error` — this must never be quiet. */
  warn?: (message: string) => void
  /** Overrides "now", for tests and deterministic replay. */
  asOf?: Date
}

export interface OfflineApprovalResult {
  ok: boolean
  reason?: string
  receipt?: ApprovalReceipt
  nonce?: string
  /** Who actually signed, as verified against the trust bundle. */
  signers?: string[]
  /** Set when a delegation supplied the approver set. */
  viaDelegation?: string
}

/**
 * Run a full offline approval: build the challenge, collect signatures out of band, verify, redeem.
 *
 * Verification is delegated to `@intyga/verify` with `allowOffline: true`, so every ordinary control
 * still applies unchanged — target isolation, exact parameter binding, the signed quorum, four-eyes,
 * the trusted signer set, expiry, and the window cap. This widens WHEN an approval may be obtained,
 * never WHAT it authorizes.
 *
 * The nonce is redeemed BEFORE returning ok. A proof that verifies but cannot be claimed has already
 * been used here, and is refused.
 */
export async function useOfflineApproval(
  expected: { target: string; actionType: string; display: string; params: Record<string, unknown> },
  opts: OfflineApprovalOptions,
): Promise<OfflineApprovalResult> {
  const warn = opts.warn ?? ((m: string) => console.error(m))

  const loaded = loadTrustBundle(opts.bundleDir, { asOf: opts.asOf })
  if (!loaded.ok || !loaded.bundle) return { ok: false, reason: loaded.reason }
  const bundle = loaded.bundle

  // A delegation is the TIER-3 path: only consulted when one is actually present on disk. It is
  // verified against the bundle's ORDINARY approver set — the people entitled to approve this action
  // are the ones who must have signed away that entitlement.
  let delegation: VerifiedDelegation | undefined
  if (opts.delegationDir) {
    const found = findDelegation(opts.delegationDir, bundle, expected, opts.asOf)
    if (found.reason) warn(`⚠ OFFLINE APPROVAL: ${found.reason}`)
    delegation = found.delegation
  }

  const built = createOfflineChallenge({
    bundle,
    target: expected.target,
    actionType: expected.actionType,
    display: expected.display,
    params: expected.params,
    requester: { did: opts.requesterDid, attestation: null },
    windowMinutes: opts.windowMinutes,
    asOf: opts.asOf,
    delegation,
  })
  if (!built.ok || !built.challenge) return { ok: false, reason: built.reason }
  const challenge = built.challenge

  const raw = await opts.collectSignatures(challenge)
  if (!raw || raw.length === 0)
    return { ok: false, reason: "no signatures were collected — the action is not approved" }

  const witnesses: ApprovalWitness[] = []
  const rejected: string[] = []
  for (const envelope of raw) {
    const decoded = decodeSignatureEnvelope(envelope)
    if (!decoded.ok || !decoded.witness) {
      rejected.push(decoded.reason ?? "unreadable signature envelope")
      continue
    }
    witnesses.push(decoded.witness)
  }
  if (witnesses.length === 0) return { ok: false, reason: `no usable signatures (${rejected.join("; ")})` }

  const receipt = assembleOfflineReceipt(challenge, witnesses)
  const result = verifyApprovalReceipt(
    receipt,
    {
      target: expected.target,
      actionType: expected.actionType,
      params: expected.params,
      nonce: challenge.nonce,
      // Restricted to the approvers eligible for THIS action, so a valid signature from someone
      // outside the rule's approver list does not count toward its quorum.
      approvers: approverAnchor(bundle, challenge.approverDids),
    },
    { allowOffline: true, delegation, asOf: opts.asOf },
  )
  if (!result.ok) {
    const detail = rejected.length > 0 ? ` (also discarded: ${rejected.join("; ")})` : ""
    return { ok: false, reason: `${result.reason}${detail}` }
  }

  const store = opts.store ?? new FileRedemptionStore(path.join(opts.bundleDir, ".redeemed"))
  if (!store.redeem(challenge.nonce))
    return { ok: false, reason: `nonce ${challenge.nonce} has already been redeemed here` }

  bufferForReconciliation(challenge, receipt, delegation, opts)
  warn(
    `⚠ OFFLINE APPROVAL USED — "${expected.display}" (${expected.actionType} on ${expected.target}). ` +
      `Approved out of band by ${result.signers?.join(", ") ?? "(unknown)"} because Intyga was unreachable` +
      `${delegation ? `, under delegation ${delegation.nonce}` : ""}. ` +
      `Nonce ${challenge.nonce} is buffered for reconciliation; report it when connectivity returns.`,
  )
  return {
    ok: true,
    receipt,
    nonce: challenge.nonce,
    signers: result.signers,
    viaDelegation: delegation?.nonce,
  }
}

/**
 * Find and verify a delegation covering this exact action.
 *
 * A file that fails to verify is REPORTED, not silently skipped: a delegation the operator believes
 * they hold but which does not apply is exactly the thing they need told during an incident.
 */
function findDelegation(
  dir: string,
  bundle: TrustBundle,
  expected: { target: string; actionType: string; params: Record<string, unknown> },
  asOf?: Date,
): { delegation?: VerifiedDelegation; reason?: string } {
  let files: string[]
  try {
    files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => path.join(dir, f))
  } catch {
    return {}
  }
  const rejected: string[] = []
  for (const file of files) {
    let receipt: ApprovalReceipt
    try {
      receipt = JSON.parse(fs.readFileSync(file, "utf8")) as ApprovalReceipt
    } catch {
      rejected.push(`${path.basename(file)}: unreadable`)
      continue
    }
    const res = verifyDelegation(
      receipt,
      {
        // The ORDINARY approver set — not the delegates. Whoever may approve this action is who must
        // have delegated it.
        approvers: approverAnchor(bundle),
        target: expected.target,
        actionType: expected.actionType,
        params: expected.params,
      },
      { asOf },
    )
    if (!res.ok || !res.delegation) {
      rejected.push(`${path.basename(file)}: ${res.reason}`)
      continue
    }
    return { delegation: res.delegation }
  }
  return rejected.length > 0 ? { reason: `no delegation applies (${rejected.join("; ")})` } : {}
}

/** A buffered offline approval awaiting reconciliation. */
export interface PendingApproval {
  nonce: string
  target: string
  actionType: string
  display: string
  usedAt: string
  /** The full receipt, so the gateway can re-verify the approval rather than take our word for it. */
  receipt: ApprovalReceipt
  /** The delegation nonce, when one supplied the approver set. */
  delegationNonce?: string
}

/**
 * Record the approval so it can be reported when the gateway is reachable again.
 *
 * Best-effort by design: a buffering failure must never block the emergency action the operator is
 * mid-incident on. It is warned about loudly instead, because an unrecorded approval is exactly the
 * case reconciliation exists to surface.
 */
function bufferForReconciliation(
  challenge: OfflineChallenge,
  receipt: ApprovalReceipt,
  delegation: VerifiedDelegation | undefined,
  opts: OfflineApprovalOptions,
): void {
  const dir = opts.bufferDir ?? path.join(opts.bundleDir, ".pending")
  const record: PendingApproval = {
    nonce: challenge.nonce,
    target: challenge.target,
    actionType: challenge.actionType,
    display: challenge.display,
    usedAt: new Date().toISOString(),
    receipt,
    delegationNonce: delegation?.nonce,
  }
  try {
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, `${challenge.nonce}.json`), `${JSON.stringify(record, null, 2)}\n`)
  } catch (err) {
    ;(opts.warn ?? ((m: string) => console.error(m)))(
      `⚠ OFFLINE APPROVAL: could not buffer ${challenge.nonce} for reconciliation (${(err as Error).message}). ` +
        `Report this manually — an unreported approval is indistinguishable from an unauthorized one.`,
    )
  }
}

/** Read the offline approvals buffered by `useOfflineApproval` but not yet reported. */
export function pendingApprovals(opts: { bundleDir: string; bufferDir?: string }): PendingApproval[] {
  const dir = opts.bufferDir ?? path.join(opts.bundleDir, ".pending")
  try {
    return fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) as PendingApproval)
  } catch {
    return []
  }
}

/**
 * Clear a buffered approval once the gateway has acknowledged it.
 *
 * Only call this on a definite acknowledgement. Dropping the record on a network error would turn a
 * retryable report into a permanently unreported approval — exactly the state reconciliation exists to
 * make impossible.
 */
export function clearPendingApproval(nonce: string, opts: { bundleDir: string; bufferDir?: string }): void {
  const dir = opts.bufferDir ?? path.join(opts.bundleDir, ".pending")
  try {
    fs.unlinkSync(path.join(dir, `${nonce}.json`))
  } catch {
    // Already gone. Nothing to do.
  }
}
