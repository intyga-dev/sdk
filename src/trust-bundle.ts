import type { webcrypto } from "node:crypto"
import {
  selectApprovalRule,
  validateExactApprovalPolicy,
  ApprovalPolicyConflict,
  type PolicyRule,
} from "@intyga/verify/approval-policy"
// Offline trust bundle (docs/DIV.md §5a.4) — the relying party's local answer to "whose signature
// counts, and what does policy require?"
//
// Offline verification needs two things the network normally supplies: the approver public keys (DIV
// Invariant 3 forbids taking them from the proof under verification) and the approval REQUIREMENT.
// The requirement matters more than it looks. The relying party builds its own offline challenge, so
// if it also invented the quorum it would be setting its own policy and the resulting proof would
// attest to nothing but that host's configuration. The bundle is the offline projection of the
// tenant's real policy, exported while the gateway was reachable.
//
// Integrity comes from a compact JWS signed with the gateway's existing OIDC key (the one already
// published at /oauth/jwks). No new key material and nothing new to rotate — but note what the
// signature does and does not buy: it proves the bundle is the one Intyga exported, which is why the
// verifying key must be PINNED at export time rather than fetched. Fetching it at incident time is
// both impossible (offline) and pointless (a fetched key is only as good as the fetch).

import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { ensurePrivateDir, writePrivateFile } from "./secure-files.js"
import type { ApproverTrustAnchor, ApprovalRequirementAttestation } from "@intyga/verify"
import { parseRfc3339Ms, SIGNER_CLASS_HUMAN, validControllerDid, validSignerExclusions } from "@intyga/verify"

/** Bundle `type` discriminator, inside the signed JWS payload. */
export const DIV_TRUST_BUNDLE_TYPE = "div-trust-bundle-v1"

/**
 * Hard ceiling on bundle age, enforced here regardless of the `expiresAt` the gateway wrote. A stale
 * bundle is a stale approver set: a revoked approver stays trusted, and a tightened quorum stays
 * loose. The cap bounds how wrong a relying party can be without noticing.
 */
export const MAX_TRUST_BUNDLE_AGE_DAYS = 30

/** One approver and every public key bound to them at export time. */
export interface BundleApprover {
  did: string
  /** base64 SPKI (raw P-256) and/or base64 COSE (WebAuthn credential) keys. All are this ONE approver. */
  publicKeys: string[]
  /**
   * base64 SPKI offline signing keys (DIV §5a.4). They count ONLY toward a `div-offline-intent` —
   * never a delegation or an ordinary intent — so they are kept out of `publicKeys` rather than merged
   * into it. See `approverAnchor`.
   */
  offlinePublicKeys?: string[]
}

/**
 * What a bundle anchor will verify. `ordinary` (the default) admits `publicKeys` only, and is what a
 * delegation or an ordinary intent is checked against. `offline-intent` also admits
 * `offlinePublicKeys`, and is only for verifying a `div-offline-intent` proof.
 */
export type BundleAnchorPurpose = "ordinary" | "offline-intent"

/** The approval requirement in force for one action pattern, as the gateway resolved it. */
export interface BundlePolicy extends PolicyRule {
  signerClass: "human"
  /** Mirrors gateway TrustBundlePolicyEntry (apps/gateway/src/approvalMatch.ts). */
  selectionRank?: number
  selectionKey?: string
  /** Exact actionType ID, or `*` for the tenant baseline. Display text never selects a rule. */
  actionPattern: string
  requiredApprovals: number
  requireHardwareKey: boolean
  allowedAaguids: string[]
  requesterCannotApprove: boolean
  /**
   * DIV §5a.4: only in a version 2 bundle, and only as `true`. No offline challenge can be created
   * under a rule that sets it (an offline key is not an enrolled approver device).
   */
  requireEnrolledDevice?: true
  /** Which approvers are eligible for THIS pattern. A subset of `approvers`. */
  approverDids: string[]
}

export interface TrustBundle {
  /** `2` exactly when some policy entry carries `requireEnrolledDevice` (DIV §5a.4). */
  v: 1 | 2
  type: typeof DIV_TRUST_BUNDLE_TYPE
  tenantId: string
  /** Pinned by the bundle signature; never inferred from a delegation receipt. */
  webauthn?: { origin: string; rpId: string }
  approvers: BundleApprover[]
  policy: BundlePolicy[]
  /** Signed controller snapshots; missing entries cannot support new independent offline requests. */
  requesterControllers?: Record<string, string[]>
  /** Key facts for exclusions only; never expands eligible approver identities or their keys. */
  controllerKeys?: Record<string, string[]>
  unmatchedActionPolicy: "DENY" | "BASELINE"
  issuedAt: string
  expiresAt: string
}

export function validRequesterControllers(value: unknown): value is Record<string, string[]> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([did, controllers]) => validControllerDid(did) && validSignerExclusions(controllers),
    )
  )
}

export function validControllerKeys(value: unknown): value is Record<string, string[]> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([did, keys]) =>
        validControllerDid(did) &&
        Array.isArray(keys) &&
        keys.every((key) => typeof key === "string" && key.length > 0),
    )
  )
}

/** What `loadTrustBundle` writes/reads: the bundle JWS plus the key it must be verified against. */
export interface TrustBundleFiles {
  /** Compact JWS produced by the gateway. */
  jws: string
  /** The gateway public key, as a JWK, PINNED when the bundle was exported. */
  gatewayJwk: webcrypto.JsonWebKey
}

const BUNDLE_FILE = "trust-bundle.jws"
const KEY_FILE = "gateway-key.jwk.json"

/**
 * Strict base64url (RFC 7515 §2; optional `=` padding tolerated as the envelopes do), or null.
 * Node's decoder skips characters outside the alphabet, so a stray character in the signature part
 * used to be ignored and the bundle still verified; every other SDK refuses such input.
 */
function b64urlToBuffer(s: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) return null
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64")
}

/**
 * Verify a compact JWS bundle against a PINNED gateway key and return its payload.
 *
 * Only RS256 is accepted, and the `alg` header is checked against that fixed expectation rather than
 * used to select an algorithm. Trusting the token's own `alg` is the classic JWS confusion bug: `none`
 * would skip verification entirely, and an HMAC alg would have us verify a symmetric MAC using the
 * public key as the secret — a key the attacker also has.
 */
export function verifyTrustBundle(
  jws: string,
  gatewayJwk: webcrypto.JsonWebKey,
  opts: { asOf?: Date } = {},
): { ok: boolean; reason?: string; bundle?: TrustBundle } {
  const parts = jws.split(".")
  if (parts.length !== 3) return { ok: false, reason: "trust bundle is not a compact JWS" }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string]

  let header: { alg?: string; typ?: string }
  try {
    const headerBytes = b64urlToBuffer(headerB64)
    if (!headerBytes) throw new Error("not base64url")
    header = JSON.parse(headerBytes.toString("utf8")) as { alg?: string; typ?: string }
  } catch {
    return { ok: false, reason: "trust bundle header is not JSON" }
  }
  // A JOSE header is a JSON object (RFC 7515 §4); an array is not one, whatever `typeof` says.
  if (!header || typeof header !== "object" || Array.isArray(header))
    return { ok: false, reason: "invalid trust bundle header" }
  if (header.alg !== "RS256")
    return { ok: false, reason: `trust bundle alg must be RS256, got ${header.alg ?? "(none)"}` }

  // RS256 means an RSA key. A pinned EC key would otherwise get ECDSA verification under an RS256
  // header — the key choice deciding the algorithm, which is the confusion the alg check exists for.
  if (gatewayJwk?.kty !== "RSA") return { ok: false, reason: "pinned gateway key must be an RSA JWK" }
  let keyObject: crypto.KeyObject
  try {
    keyObject = crypto.createPublicKey({ format: "jwk", key: gatewayJwk })
  } catch (err) {
    return { ok: false, reason: `pinned gateway key is unusable: ${(err as Error).message}` }
  }

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8")
  const signature = b64urlToBuffer(sigB64)
  let verified = false
  try {
    verified =
      signature !== null &&
      crypto.verify(
        "sha256",
        signingInput,
        { key: keyObject, padding: crypto.constants.RSA_PKCS1_PADDING },
        signature,
      )
  } catch (err) {
    return { ok: false, reason: `trust bundle signature check failed: ${(err as Error).message}` }
  }
  if (!verified)
    return { ok: false, reason: "trust bundle signature does not verify against the pinned gateway key" }

  let bundle: TrustBundle
  try {
    const payloadBytes = b64urlToBuffer(payloadB64)
    if (!payloadBytes) throw new Error("not base64url")
    bundle = JSON.parse(payloadBytes.toString("utf8")) as TrustBundle
  } catch {
    return { ok: false, reason: "trust bundle payload is not JSON" }
  }
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle))
    return { ok: false, reason: "invalid trust bundle payload" }
  // DIV §5a.4: version 2 exists only to carry requireEnrolledDevice, so a version 2 bundle with no
  // such entry is an unsupported version — one policy has one form, and the refusal (and its order)
  // stays exactly what a version 1 reader reports for any unknown version.
  const deviceRule =
    Array.isArray(bundle.policy) && bundle.policy.some((r) => r?.requireEnrolledDevice === true)
  if (bundle.type !== DIV_TRUST_BUNDLE_TYPE || (bundle.v !== 1 && !(bundle.v === 2 && deviceRule)))
    return { ok: false, reason: "unsupported trust bundle type or version" }
  if (typeof bundle.tenantId !== "string" || bundle.tenantId.length === 0)
    return { ok: false, reason: "trust bundle tenantId must be a non-empty string" }
  if (
    bundle.webauthn !== undefined &&
    (!bundle.webauthn ||
      typeof bundle.webauthn.origin !== "string" ||
      !bundle.webauthn.origin.length ||
      typeof bundle.webauthn.rpId !== "string" ||
      !bundle.webauthn.rpId.length)
  )
    return { ok: false, reason: "invalid trust bundle WebAuthn expectations" }
  if (bundle.unmatchedActionPolicy !== "DENY" && bundle.unmatchedActionPolicy !== "BASELINE")
    return { ok: false, reason: "trust bundle has no valid unmatched-action decision" }
  if (!Array.isArray(bundle.approvers) || bundle.approvers.length === 0)
    return { ok: false, reason: "trust bundle names no approvers" }
  if (
    !bundle.approvers.every(
      (a) =>
        a &&
        typeof a.did === "string" &&
        a.did.length &&
        Array.isArray(a.publicKeys) &&
        a.publicKeys.length &&
        a.publicKeys.every((k) => typeof k === "string" && k.length) &&
        (a.offlinePublicKeys === undefined ||
          (Array.isArray(a.offlinePublicKeys) &&
            a.offlinePublicKeys.every((k) => typeof k === "string" && k.length))),
    )
  )
    return { ok: false, reason: "invalid bundle approver keys" }
  // A key listed as both ordinary and offline-only would undo the split the second list exists for.
  const ordinaryKeys = new Set(bundle.approvers.flatMap((a) => a.publicKeys))
  if (bundle.approvers.some((a) => (a.offlinePublicKeys ?? []).some((k) => ordinaryKeys.has(k))))
    return { ok: false, reason: "trust bundle lists an offline signing key as an ordinary key" }
  if (bundle.controllerKeys !== undefined && !validControllerKeys(bundle.controllerKeys))
    return { ok: false, reason: "trust bundle carries malformed controller key facts" }
  if (bundle.requesterControllers !== undefined && !validRequesterControllers(bundle.requesterControllers))
    return { ok: false, reason: "trust bundle carries malformed requester controllers" }
  if (!Array.isArray(bundle.policy) || !bundle.policy.every((entry) => validBundlePolicy(entry, bundle.v)))
    return { ok: false, reason: "trust bundle carries invalid or incomplete policy" }
  try {
    validateExactApprovalPolicy(bundle.policy)
    if (bundle.unmatchedActionPolicy === "BASELINE" && !bundle.policy.some((r) => r.actionPattern === "*"))
      return { ok: false, reason: "trust bundle has no baseline for unknown actions" }
  } catch (error) {
    if (error instanceof ApprovalPolicyConflict)
      return {
        ok: false,
        reason: `trust bundle has invalid exact-action policy: ${error.fields.join(", ")}`,
      }
    throw error
  }

  const freshness = checkTrustBundleFreshness(bundle, opts)
  if (!freshness.ok) return freshness
  return { ok: true, bundle }
}

/** Recheck a verified bundle after an out-of-band signing ceremony, without changing its trust keys. */
export function checkTrustBundleFreshness(
  bundle: TrustBundle,
  opts: { asOf?: Date } = {},
): { ok: boolean; reason?: string } {
  // Two independent staleness checks. The gateway's own `expiresAt` can be set generously, so the
  // local age cap is what actually bounds drift — a relying party must not be able to run for a year
  // on a bundle just because whoever exported it chose a long expiry.
  const now = (opts.asOf ?? new Date()).getTime()
  // The DIV §6.2 grammar, not Date.parse: a bare date or a zone-less time would otherwise be read
  // in the host's timezone, and the other SDKs refuse both.
  const expiryMs = parseRfc3339Ms(bundle.expiresAt)
  if (Number.isNaN(expiryMs))
    return { ok: false, reason: "trust bundle expiresAt is not a valid RFC3339 timestamp" }
  if (now > expiryMs)
    return { ok: false, reason: `trust bundle expired at ${bundle.expiresAt} — export a fresh one` }
  const issuedMs = parseRfc3339Ms(bundle.issuedAt)
  if (Number.isNaN(issuedMs))
    return { ok: false, reason: "trust bundle issuedAt is not a valid RFC3339 timestamp" }
  const ageDays = (now - issuedMs) / 86_400_000
  if (ageDays > MAX_TRUST_BUNDLE_AGE_DAYS)
    return {
      ok: false,
      reason: `trust bundle is ${ageDays.toFixed(1)} days old, over the ${MAX_TRUST_BUNDLE_AGE_DAYS}-day maximum — export a fresh one`,
    }

  return { ok: true }
}

/** Write a bundle and its pinned verification key into `dir`, for use during a later outage. */
export function saveTrustBundle(dir: string, files: TrustBundleFiles): void {
  ensurePrivateDir(dir)
  writePrivateFile(path.join(dir, BUNDLE_FILE), files.jws)
  writePrivateFile(path.join(dir, KEY_FILE), `${JSON.stringify(files.gatewayJwk, null, 2)}\n`)
}

/**
 * Load and verify the bundle from `dir`.
 *
 * Fails closed and LOUDLY: there is deliberately no "continue without a bundle" path, because the
 * fallback would be an unverified approver set, which is the one thing DIV Invariant 3 forbids.
 */
export function loadTrustBundle(
  dir: string,
  opts: { asOf?: Date } = {},
): { ok: boolean; reason?: string; bundle?: TrustBundle } {
  let jws: string
  let jwk: webcrypto.JsonWebKey
  try {
    jws = fs.readFileSync(path.join(dir, BUNDLE_FILE), "utf8").trim()
  } catch {
    return {
      ok: false,
      reason: `no trust bundle at ${path.join(dir, BUNDLE_FILE)} — export one with \`intyga trust-bundle export\` while the gateway is reachable`,
    }
  }
  try {
    jwk = JSON.parse(fs.readFileSync(path.join(dir, KEY_FILE), "utf8")) as webcrypto.JsonWebKey
  } catch {
    return { ok: false, reason: `no pinned gateway key at ${path.join(dir, KEY_FILE)}` }
  }
  return verifyTrustBundle(jws, jwk, opts)
}

/**
 * Build a DID-mode trust anchor from the bundle.
 *
 * DID mode, not `publicKeys` mode, and that is load-bearing: quorum must count distinct APPROVERS, and
 * a delegation (DIV §5a.6) names identities that cannot be enforced against an unverified `signerDid`.
 * Flattening every key into one allowlist — which is what a single-key resolver forces — would let one
 * approver holding a software key and two passkeys satisfy a 3-of-N quorum alone.
 *
 * `purpose` defaults to `ordinary`, which never admits an offline signing key. `offline-intent`
 * requires an explicit DID restriction and otherwise throws: admitting every offline key in a
 * tenant bundle would let an ineligible approver satisfy this action's quorum.
 */
export function approverAnchor(
  bundle: TrustBundle,
  limitToDids?: string[],
  purpose: BundleAnchorPurpose = "ordinary",
  excludedDids: readonly string[] = [],
): ApproverTrustAnchor {
  if (purpose === "offline-intent" && limitToDids === undefined)
    throw new Error("offline-intent anchors require an explicit eligible DID restriction")
  const eligible = limitToDids
    ? bundle.approvers.filter((a) => limitToDids.includes(a.did))
    : bundle.approvers
  const byDid = new Map(
    bundle.approvers.map((a) => [
      a.did,
      purpose === "offline-intent" ? [...a.publicKeys, ...(a.offlinePublicKeys ?? [])] : a.publicKeys,
    ]),
  )
  if (bundle.controllerKeys !== undefined) {
    if (!validControllerKeys(bundle.controllerKeys)) throw new Error("Malformed controller key facts")
    for (const did of excludedDids) {
      const facts = bundle.controllerKeys[did]
      if (facts) byDid.set(did, [...new Set([...(byDid.get(did) ?? []), ...facts])])
    }
  }
  return {
    dids: [...new Set(eligible.map((a) => a.did))],
    resolveKey: (did) => byDid.get(did) ?? null,
  }
}

/**
 * Resolve the requirement for an action from the bundle's offline policy projection.
 *
 * Matching follows the gateway's exact-ID evaluator. Signed rank/key fields are informational;
 * constraints are evaluated from the complete v1 policy. Unsupported offline controls,
 * conflicts, malformed bundles, and unmatched actions return null (refusal). A rule with
 * `requesterCannotApprove` also returns null unless `requesterDid` is given and the bundle's signed
 * `requesterControllers` has an entry for it (DIV §5a.4): there is no requester-only fallback.
 */
export function requirementFor(
  bundle: TrustBundle,
  actionType: string,
  display: string,
  requesterDid?: string,
): { requirement: ApprovalRequirementAttestation; approverDids: string[] } | null {
  if (
    (bundle?.v !== 1 && bundle?.v !== 2) ||
    bundle.type !== DIV_TRUST_BUNDLE_TYPE ||
    (bundle.unmatchedActionPolicy !== "DENY" && bundle.unmatchedActionPolicy !== "BASELINE") ||
    !Array.isArray(bundle.policy) ||
    !bundle.policy.every((entry) => validBundlePolicy(entry, bundle.v))
  )
    return null
  let winner: BundlePolicy | undefined
  try {
    winner = selectApprovalRule(bundle.policy, actionType, display, 3, bundle.unmatchedActionPolicy)
  } catch (error) {
    if (error instanceof ApprovalPolicyConflict) return null
    throw error
  }
  // These online-only conditions cannot be reconstructed by an offline ceremony.
  if (
    !winner ||
    new Set(winner.approverDids).size < winner.requiredApprovals ||
    winner.requireAttestedRequester ||
    winner.allowedIssuers?.length ||
    winner.escalateAfterSeconds ||
    winner.autoApproveRequesterDid
  )
    return null
  let exclusions = winner.excludedSignerDids
  if (winner.requesterCannotApprove) {
    // DIV §5a.4: a four-eyes requirement is incomplete without the requester's controllers, so it is
    // refused when the requester is unknown, exactly as when its controller entry is missing. Returning
    // the rule's own exclusions alone would be the requester-only fallback the spec rules out.
    if (
      requesterDid === undefined ||
      !validRequesterControllers(bundle.requesterControllers) ||
      !Object.hasOwn(bundle.requesterControllers, requesterDid)
    )
      return null
    const controllers = bundle.requesterControllers[requesterDid]
    if (!controllers) return null
    exclusions = [...new Set([...(exclusions ?? []), ...controllers])].sort()
  }
  return {
    requirement: {
      ...(exclusions !== undefined ? { excludedSignerDids: [...new Set(exclusions)].sort() } : {}),
      requiredApprovals: Math.max(1, winner.requiredApprovals),
      requireHardwareKey: winner.requireHardwareKey,
      allowedAaguids: winner.allowedAaguids ?? [],
      requesterCannotApprove: winner.requesterCannotApprove,
      // Carried, never dropped: the offline ceremony refuses it explicitly (DIV §5a.3 step 4) and a
      // relying party's step-3d floor built from this requirement keeps demanding it.
      ...(winner.requireEnrolledDevice === true ? { requireEnrolledDevice: true } : {}),
      signerClass: SIGNER_CLASS_HUMAN,
    },
    approverDids: winner.approverDids ?? [],
  }
}

function validBundlePolicy(value: unknown, version: number): value is BundlePolicy {
  if (!value || typeof value !== "object") return false
  const p = value as Record<string, unknown>
  if (p.signerClass !== "human") return false
  // DIV §5a.4: version 2 admits `requireEnrolledDevice: true` and nothing else under that key; a
  // version 1 bundle never carries it, so an older reader cannot meet it read as weaker.
  if (Object.hasOwn(p, "requireEnrolledDevice") && (version !== 2 || p.requireEnrolledDevice !== true))
    return false
  if (p.excludedSignerDids !== undefined && !validSignerExclusions(p.excludedSignerDids)) return false
  if (
    typeof p.actionPattern !== "string" ||
    !p.actionPattern.trim() ||
    !Number.isSafeInteger(p.requiredApprovals) ||
    Number(p.requiredApprovals) < 1
  )
    return false
  for (const field of ["requireHardwareKey", "requesterCannotApprove", "requireAttestedRequester"]) {
    if (typeof p[field] !== "boolean") return false
  }
  for (const field of ["approverDids", "allowedAaguids", "allowedIssuers", "escalationApproverDids"]) {
    if (
      !Array.isArray(p[field]) ||
      !(p[field] as unknown[]).every((v) => typeof v === "string" && v.length > 0)
    )
      return false
  }
  if (
    p.escalateAfterSeconds !== null &&
    (!Number.isSafeInteger(p.escalateAfterSeconds) || Number(p.escalateAfterSeconds) < 1)
  )
    return false
  for (const field of ["autoApproveRequesterDid", "autoApproveWindowStart", "autoApproveWindowEnd"]) {
    if (p[field] !== null && typeof p[field] !== "string") return false
  }
  return (
    p.autoApproveDayOfWeek === null ||
    (Number.isInteger(p.autoApproveDayOfWeek) &&
      Number(p.autoApproveDayOfWeek) >= 0 &&
      Number(p.autoApproveDayOfWeek) <= 6)
  )
}
