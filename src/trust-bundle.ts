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
import { SIGNER_CLASS_HUMAN } from "@intyga/verify"

/** Bundle `type` discriminator, inside the signed JWS payload. */
export const DIV_TRUST_BUNDLE_TYPE = "div-trust-bundle"

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
}

/** The approval requirement in force for one action pattern, as the gateway resolved it. */
export interface BundlePolicy {
  /** Mirrors gateway TrustBundlePolicyEntry (apps/gateway/src/approvalMatch.ts). Absent only in legacy exports. */
  selectionRank?: number
  selectionKey?: string
  /** Matched against `actionType` + display text, exactly as the gateway matches its own rules. */
  actionPattern: string
  requiredApprovals: number
  requireHardwareKey: boolean
  allowedAaguids: string[]
  requesterCannotApprove: boolean
  /** Which approvers are eligible for THIS pattern. A subset of `approvers`. */
  approverDids: string[]
}

export interface TrustBundle {
  v: number
  type: string
  tenantId: string
  approvers: BundleApprover[]
  policy: BundlePolicy[]
  issuedAt: string
  expiresAt: string
}

/** What `loadTrustBundle` writes/reads: the bundle JWS plus the key it must be verified against. */
export interface TrustBundleFiles {
  /** Compact JWS produced by the gateway. */
  jws: string
  /** The gateway public key, as a JWK, PINNED when the bundle was exported. */
  gatewayJwk: JsonWebKey
}

const BUNDLE_FILE = "trust-bundle.jws"
const KEY_FILE = "gateway-key.jwk.json"

function b64urlToBuffer(s: string): Buffer {
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
  gatewayJwk: JsonWebKey,
  opts: { asOf?: Date } = {},
): { ok: boolean; reason?: string; bundle?: TrustBundle } {
  const parts = jws.split(".")
  if (parts.length !== 3) return { ok: false, reason: "trust bundle is not a compact JWS" }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string]

  let header: { alg?: string; typ?: string }
  try {
    header = JSON.parse(b64urlToBuffer(headerB64).toString("utf8")) as { alg?: string; typ?: string }
  } catch {
    return { ok: false, reason: "trust bundle header is not JSON" }
  }
  if (header.alg !== "RS256")
    return { ok: false, reason: `trust bundle alg must be RS256, got ${header.alg ?? "(none)"}` }

  let keyObject: crypto.KeyObject
  try {
    keyObject = crypto.createPublicKey({ format: "jwk", key: gatewayJwk })
  } catch (err) {
    return { ok: false, reason: `pinned gateway key is unusable: ${(err as Error).message}` }
  }

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8")
  let verified = false
  try {
    verified = crypto.verify(
      "sha256",
      signingInput,
      { key: keyObject, padding: crypto.constants.RSA_PKCS1_PADDING },
      b64urlToBuffer(sigB64),
    )
  } catch (err) {
    return { ok: false, reason: `trust bundle signature check failed: ${(err as Error).message}` }
  }
  if (!verified)
    return { ok: false, reason: "trust bundle signature does not verify against the pinned gateway key" }

  let bundle: TrustBundle
  try {
    bundle = JSON.parse(b64urlToBuffer(payloadB64).toString("utf8")) as TrustBundle
  } catch {
    return { ok: false, reason: "trust bundle payload is not JSON" }
  }
  if (bundle.type !== DIV_TRUST_BUNDLE_TYPE)
    return { ok: false, reason: `not a ${DIV_TRUST_BUNDLE_TYPE} (got ${String(bundle.type)})` }
  if (!Array.isArray(bundle.approvers) || bundle.approvers.length === 0)
    return { ok: false, reason: "trust bundle names no approvers" }
  if (!Array.isArray(bundle.policy)) return { ok: false, reason: "trust bundle carries no policy" }

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
  const expiryMs = Date.parse(bundle.expiresAt)
  if (Number.isNaN(expiryMs))
    return { ok: false, reason: "trust bundle expiresAt is not a valid RFC3339 timestamp" }
  if (now > expiryMs)
    return { ok: false, reason: `trust bundle expired at ${bundle.expiresAt} — export a fresh one` }
  const issuedMs = Date.parse(bundle.issuedAt)
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
  let jwk: JsonWebKey
  try {
    jws = fs.readFileSync(path.join(dir, BUNDLE_FILE), "utf8").trim()
  } catch {
    return {
      ok: false,
      reason: `no trust bundle at ${path.join(dir, BUNDLE_FILE)} — export one with \`intyga trust-bundle export\` while the gateway is reachable`,
    }
  }
  try {
    jwk = JSON.parse(fs.readFileSync(path.join(dir, KEY_FILE), "utf8")) as JsonWebKey
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
 */
export function approverAnchor(bundle: TrustBundle, limitToDids?: string[]): ApproverTrustAnchor {
  const eligible = limitToDids
    ? bundle.approvers.filter((a) => limitToDids.includes(a.did))
    : bundle.approvers
  const byDid = new Map(eligible.map((a) => [a.did, a.publicKeys]))
  return {
    dids: [...byDid.keys()],
    resolveKey: (did) => byDid.get(did) ?? null,
  }
}

/**
 * Resolve the requirement for an action from the bundle's offline policy projection.
 *
 * Matching follows the gateway: the pattern is matched against
 * `actionType` AND the display text together (so a rule keyed to the action type cannot be dodged by
 * wording the description around it), and among several matches the STRICTEST wins rather than the
 * longest. A relying party that picked the first or loosest match would quietly grant itself a weaker
 * policy than the tenant configured.
 * Ranking and tie-breaking come from signed gateway metadata, because even online-only constraints
 * (DIV §4.3.2) affect which rule supplies the ordinary approver set. A legacy bundle with overlapping
 * matches must be refreshed; guessing its lost selection metadata could choose weaker approvers.
 *
 * Returns `null` when nothing matches or selection is ambiguous. That is a REFUSAL, not a default: there is no implicit
 * 1-of-1 fallback here, because inventing a requirement is exactly what §5a.3 forbids.
 */
export function requirementFor(
  bundle: TrustBundle,
  actionType: string,
  display: string,
): { requirement: ApprovalRequirementAttestation; approverDids: string[] } | null {
  const haystack = `${actionType}\n${display}`.toLowerCase()
  const matches = bundle.policy.filter(
    (p) => p.actionPattern === "*" || haystack.includes(p.actionPattern.toLowerCase()),
  )
  if (matches.length === 0) return null
  if (
    matches.length > 1 &&
    matches.some(
      (p) =>
        !Number.isSafeInteger(p.selectionRank) ||
        (p.selectionRank ?? 0) < 1 ||
        typeof p.selectionKey !== "string" ||
        p.selectionKey.length === 0,
    )
  )
    return null
  const winner = [...matches].sort((a, b) => {
    const rank = (b.selectionRank ?? 0) - (a.selectionRank ?? 0)
    if (rank !== 0) return rank
    const ka = a.selectionKey ?? ""
    const kb = b.selectionKey ?? ""
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })[0] as BundlePolicy
  // Expanded groups can expose different eligible sets behind otherwise identical selection keys.
  // Do not let array order resolve a remaining collision with different authorization semantics.
  const policyKey = (p: BundlePolicy) =>
    JSON.stringify([
      p.requiredApprovals,
      p.requireHardwareKey,
      [...(p.allowedAaguids ?? [])].sort(),
      p.requesterCannotApprove,
      [...p.approverDids].sort(),
    ])
  if (
    matches.some(
      (p) =>
        p.selectionRank === winner.selectionRank &&
        p.selectionKey === winner.selectionKey &&
        policyKey(p) !== policyKey(winner),
    )
  )
    return null
  return {
    requirement: {
      requiredApprovals: Math.max(1, winner.requiredApprovals),
      requireHardwareKey: winner.requireHardwareKey,
      allowedAaguids: winner.allowedAaguids ?? [],
      requesterCannotApprove: winner.requesterCannotApprove,
      signerClass: SIGNER_CLASS_HUMAN,
    },
    approverDids: winner.approverDids ?? [],
  }
}
