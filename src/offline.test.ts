// Offline approval, end to end at the relying party (docs/DIV.md §5a).
//
// The interesting assertions here are the ones about where things come FROM: the requirement from the
// signed bundle rather than from the caller, the approver keys from the bundle rather than the receipt,
// and the fallback from a transport failure rather than from a refusal. Those are the properties that
// make this a gate rather than a hole, and each is a plausible casualty of a future refactor.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import type { webcrypto } from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { describe, it } from "node:test"
// Tests run against the BUILT output, matching the convention in index.test.ts / cli.test.ts: this
// package's `npm test` uses `node --test`, which resolves `.js` specifiers to real files.
import { canonicalDelegationPayload, canonicalIntentPayload, verificationCode } from "@intyga/verify"
import {
  clearPendingApproval,
  createOfflineChallenge,
  decodeChallengeEnvelope,
  decodeSignatureEnvelope,
  encodeSignatureEnvelope,
  FileRedemptionStore,
  pendingApprovals,
  signChallengeEnvelope,
  useOfflineApproval,
} from "../dist/offline.js"
import {
  approverAnchor,
  loadTrustBundle,
  MAX_TRUST_BUNDLE_AGE_DAYS,
  requirementFor,
  saveTrustBundle,
  type TrustBundle,
  verifyTrustBundle,
} from "../dist/trust-bundle.js"

// ── fixtures ────────────────────────────────────────────────────────────────────
const GATEWAY = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
const GATEWAY_JWK = GATEWAY.publicKey.export({ format: "jwk" }) as webcrypto.JsonWebKey

function makeApprover(did: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  return {
    did,
    spki: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    pkcs8: privateKey.export({ format: "der", type: "pkcs8" }),
    sign: (payload: string) =>
      crypto
        .sign("sha256", Buffer.from(payload, "utf8"), { key: privateKey, dsaEncoding: "ieee-p1363" })
        .toString("base64"),
  }
}

const ALICE = makeApprover("did:intyga:alice")
const BOB = makeApprover("did:intyga:bob")
const MALLORY = makeApprover("did:intyga:mallory")
const CAROL = makeApprover("did:intyga:carol")

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Sign a bundle exactly as the gateway does: compact JWS, RS256, over the JSON payload. */
function signBundle(bundle: unknown, opts: { alg?: string; key?: crypto.KeyObject } = {}): string {
  const header = b64url(Buffer.from(JSON.stringify({ alg: opts.alg ?? "RS256", kid: "intyga-key-1" })))
  const payload = b64url(Buffer.from(JSON.stringify(bundle), "utf8"))
  const sig = crypto.sign("sha256", Buffer.from(`${header}.${payload}`, "utf8"), {
    key: opts.key ?? GATEWAY.privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  })
  return `${header}.${payload}.${b64url(sig)}`
}

function bundleOf(over: Partial<TrustBundle> = {}): TrustBundle {
  const bundle = {
    v: 1 as const,
    type: "div-trust-bundle-v1" as const,
    tenantId: "11111111-1111-4111-8111-111111111111",
    approvers: [
      { did: ALICE.did, publicKeys: [ALICE.spki] },
      { did: BOB.did, publicKeys: [BOB.spki] },
    ],
    policy: [
      {
        actionPattern: "db.restart",
        requiredApprovals: 2,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
        approverDids: [ALICE.did, BOB.did],
      },
      {
        actionPattern: "*",
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
        approverDids: [ALICE.did, BOB.did],
      },
    ],
    unmatchedActionPolicy: "DENY" as const,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    ...over,
  }
  bundle.policy = bundle.policy.map((p) => ({
    signerClass: "human",
    requireAttestedRequester: false,
    allowedIssuers: [],
    escalationApproverDids: [],
    escalateAfterSeconds: null,
    autoApproveRequesterDid: null,
    autoApproveDayOfWeek: null,
    autoApproveWindowStart: null,
    autoApproveWindowEnd: null,
    ...p,
  }))
  return bundle
}

function tmpdir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "intyga-offline-"))
}

/** A directory with a valid bundle written into it. */
function bundleDir(over: Partial<TrustBundle> = {}): string {
  const dir = tmpdir()
  saveTrustBundle(dir, { jws: signBundle(bundleOf(over)), gatewayJwk: GATEWAY_JWK })
  return dir
}

const ACTION = {
  target: "prod-db-cluster-01",
  actionType: "db.restart",
  display: "Restart the primary database",
  params: { cluster: "primary" },
}

// ── trust bundle ────────────────────────────────────────────────────────────────
describe("trust bundle", () => {
  it("verifies a well-formed bundle against the pinned key", () => {
    const r = verifyTrustBundle(signBundle(bundleOf()), GATEWAY_JWK)
    assert.equal(r.ok, true, r.reason)
    assert.equal(r.bundle?.approvers.length, 2)
  })

  it("refuses legacy types, unknown versions, null, and incomplete constraint metadata", () => {
    const incomplete = bundleOf()
    delete incomplete.policy[0]!.requireAttestedRequester
    for (const value of [
      null,
      { ...bundleOf(), type: "div-trust-bundle", v: 1 },
      { ...bundleOf(), type: "div-trust-bundle-v2", v: 2 },
      { ...bundleOf(), v: 3 },
      incomplete,
    ]) {
      assert.equal(verifyTrustBundle(signBundle(value), GATEWAY_JWK).ok, false)
    }
    assert.equal(requirementFor(incomplete, "db.restart", ""), null)
  })

  it("accepts a stricter winner preserving baseline eligibility and quorum", () => {
    const bundle = bundleOf()
    const selected = requirementFor(bundle, "db.restart", "Recovery")
    assert.equal(selected?.requirement.requiredApprovals, 2)
    assert.deepEqual(selected?.approverDids, [ALICE.did, BOB.did])
  })

  it("refuses a tampered payload", () => {
    const jws = signBundle(bundleOf())
    const [h, p, s] = jws.split(".") as [string, string, string]
    const doctored = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as TrustBundle
    doctored.policy[0]!.requiredApprovals = 1
    const r = verifyTrustBundle(`${h}.${b64url(Buffer.from(JSON.stringify(doctored)))}.${s}`, GATEWAY_JWK)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /signature does not verify/)
  })

  it("refuses a bundle signed by a different key", () => {
    const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    const r = verifyTrustBundle(signBundle(bundleOf(), { key: other.privateKey }), GATEWAY_JWK)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /signature does not verify/)
  })

  it("refuses alg confusion — the header cannot choose the algorithm", () => {
    // `alg: none` is the classic JWS bypass. The verifier pins RS256 rather than reading `alg`.
    for (const alg of ["none", "HS256", "RS512"]) {
      const r = verifyTrustBundle(signBundle(bundleOf(), { alg }), GATEWAY_JWK)
      assert.equal(r.ok, false, `alg ${alg} must be refused`)
      assert.match(r.reason ?? "", /alg must be RS256/)
    }
  })

  it("refuses an expired bundle", () => {
    const r = verifyTrustBundle(
      signBundle(bundleOf({ expiresAt: new Date(Date.now() - 1000).toISOString() })),
      GATEWAY_JWK,
    )
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /expired/)
  })

  it("refuses a bundle older than the local age cap even if its own expiry is generous", () => {
    // A stale bundle enforces stale policy: a revoked approver stays trusted and a tightened quorum
    // stays loose. The local cap bounds that regardless of what the exporter chose.
    const old = new Date(Date.now() - (MAX_TRUST_BUNDLE_AGE_DAYS + 1) * 86_400_000).toISOString()
    const r = verifyTrustBundle(
      signBundle(bundleOf({ issuedAt: old, expiresAt: new Date(Date.now() + 8.64e10).toISOString() })),
      GATEWAY_JWK,
    )
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /over the 30-day maximum/)
  })

  it("refuses a bundle with no approvers rather than trusting nobody silently", () => {
    const r = verifyTrustBundle(signBundle(bundleOf({ approvers: [] })), GATEWAY_JWK)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /names no approvers/)
  })

  it("reports a clear reason when no bundle has been exported", () => {
    const r = loadTrustBundle(tmpdir())
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /trust-bundle export/)
  })

  it("refuses an overlapping rule that widens eligibility or cannot meet its quorum", () => {
    const bundle = bundleOf({
      policy: [
        {
          selectionRank: 32,
          selectionKey: '["*",[],[],["did:intyga:alice"]]',
          actionPattern: "*",
          requiredApprovals: 1,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: false,
          signerClass: "human",
          approverDids: [ALICE.did],
        },
        {
          selectionRank: 100,
          selectionKey: '["db.restart",[],[],["did:intyga:alice","did:intyga:bob"]]',
          // Keyed to the ACTION TYPE, and deliberately absent from the display text — a matcher that
          // only looked at the description would miss this and hand back the 1-of-1 rule.
          actionPattern: "db.restart",
          requiredApprovals: 3,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: true,
          signerClass: "human",
          approverDids: [ALICE.did, BOB.did],
        },
      ],
    })
    const resolved = requirementFor(bundle, "db.restart", "Emergency recovery procedure")
    assert.equal(resolved, null)
  })

  it("uses signed selection metadata regardless of exported rule order", () => {
    const policy: TrustBundle["policy"] = [
      {
        selectionRank: 33,
        selectionKey: '["*",[],["issuer-a"],["did:intyga:alice"]]',
        actionPattern: "*",
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
        approverDids: [ALICE.did],
      },
      {
        selectionRank: 40,
        selectionKey: '["db.restart",[],[],["did:intyga:bob"]]',
        actionPattern: "db.restart",
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
        approverDids: [BOB.did],
      },
    ]
    for (const ordered of [policy, [...policy].reverse()]) {
      const resolved = requirementFor(
        bundleOf({ policy: ordered }),
        "db.restart",
        "Emergency recovery procedure",
      )
      assert.equal(resolved, null)
    }
  })

  it("uses signed tie-break metadata deterministically for equally ranked AAGUID rules", () => {
    const policy: TrustBundle["policy"] = [
      {
        selectionRank: 34,
        selectionKey: '["db.restart",["yubikey"],[],["did:intyga:alice"]]',
        actionPattern: "db.restart",
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: ["yubikey"],
        requesterCannotApprove: false,
        signerClass: "human",
        approverDids: [ALICE.did],
      },
      {
        selectionRank: 34,
        selectionKey: '["db.restart",["titan"],[],["did:intyga:bob"]]',
        actionPattern: "db.restart",
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: ["titan"],
        requesterCannotApprove: false,
        signerClass: "human",
        approverDids: [BOB.did],
      },
    ]
    for (const ordered of [policy, [...policy].reverse()]) {
      const resolved = requirementFor(bundleOf({ policy: ordered }), "db.restart", ACTION.display)
      assert.equal(resolved, null)
    }
  })

  it("refuses colliding rank/key metadata with different expanded eligible sets", () => {
    const common = {
      selectionRank: 32,
      selectionKey: '["db.restart",[],[],["group:ops"]]',
      actionPattern: "db.restart",
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    }
    const bundle = bundleOf({
      policy: [
        { ...common, approverDids: [ALICE.did] },
        { ...common, approverDids: [BOB.did] },
      ],
    })
    assert.equal(requirementFor(bundle, "db.restart", ACTION.display), null)
  })

  it("refuses overlapping legacy rules whose signed selection metadata is absent", () => {
    const legacy = bundleOf({
      policy: [
        {
          actionPattern: "*",
          requiredApprovals: 1,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: false,
          signerClass: "human",
          approverDids: [ALICE.did],
        },
        {
          actionPattern: "db.restart",
          requiredApprovals: 2,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: false,
          signerClass: "human",
          approverDids: [ALICE.did, BOB.did],
        },
      ],
    })
    assert.equal(requirementFor(legacy, "db.restart", ACTION.display), null)
  })

  it("returns null for an unmatched action rather than defaulting to 1-of-1", () => {
    assert.equal(requirementFor(bundleOf(), "billing.refund", "Refund a customer"), null)
  })

  it("the public v1 bundle applies the signed baseline only when enabled and ignores display text", () => {
    const baseline = {
      ...bundleOf().policy[0]!,
      actionPattern: "*",
      requiredApprovals: 1,
      approverDids: [ALICE.did, BOB.did],
    }
    const exact = {
      ...baseline,
      actionPattern: "db.restart",
      requiredApprovals: 2,
      approverDids: [ALICE.did, BOB.did],
    }
    const bundle = bundleOf({
      v: 1,
      type: "div-trust-bundle-v1",
      unmatchedActionPolicy: "DENY",
      policy: [baseline, exact],
    })
    const checked = verifyTrustBundle(signBundle(bundle), GATEWAY_JWK)
    assert.equal(checked.ok, true, checked.reason)
    assert.equal(requirementFor(bundle, "db.restart", "ordinary text")?.requirement.requiredApprovals, 2)
    assert.equal(requirementFor(bundle, "billing.refund", "db.restart"), null)
    bundle.unmatchedActionPolicy = "BASELINE"
    assert.equal(requirementFor(bundle, "billing.refund", "db.restart")?.requirement.requiredApprovals, 1)
    bundle.policy[1]!.requireHardwareKey = false
    bundle.policy[0]!.requireHardwareKey = true
    assert.equal(requirementFor(bundle, "db.restart", "ordinary text"), null)
  })

  it("builds a DID-mode anchor whose keys all map to one identity", () => {
    const extra = makeApprover(ALICE.did)
    const anchor = approverAnchor(
      bundleOf({ approvers: [{ did: ALICE.did, publicKeys: [ALICE.spki, extra.spki] }] }),
    )
    assert.deepEqual(anchor.dids, [ALICE.did])
    assert.deepEqual(anchor.resolveKey?.(ALICE.did), [ALICE.spki, extra.spki])
  })
})

// ── envelopes ───────────────────────────────────────────────────────────────────
describe("wire envelopes", () => {
  it("round-trips a challenge", () => {
    const built = createOfflineChallenge({
      bundle: bundleOf(),
      ...ACTION,
      requester: { did: "did:intyga:service:oncall", attestation: null },
    })
    assert.equal(built.ok, true, built.reason)
    const decoded = decodeChallengeEnvelope(built.challenge!.envelope)
    assert.equal(decoded.ok, true, decoded.reason)
    assert.equal(decoded.challenge?.canonicalPayload, built.challenge?.canonicalPayload)
    assert.equal(decoded.challenge?.verificationCode, built.challenge?.verificationCode)
    assert.equal(decoded.challenge?.actionType, ACTION.actionType)
  })

  it("round-trips a signature", () => {
    const w = {
      signerDid: ALICE.did,
      signerPublicKey: ALICE.spki,
      signature: ALICE.sign("x"),
      sigAlg: "ES256",
    }
    const back = decodeSignatureEnvelope(encodeSignatureEnvelope(w))
    assert.equal(back.ok, true, back.reason)
    assert.deepEqual(back.witness, w)
  })

  it("REFUSES to present an ordinary intent payload as an offline challenge", () => {
    // An approver tool that signed this would mint a live approval outside the gateway's single-use
    // accounting. The type check is what stops an approver being walked into that.
    const ordinary = canonicalIntentPayload({
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
      requirement: {
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      nonce: "n1",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    const r = decodeChallengeEnvelope(`DIV1:${b64url(Buffer.from(ordinary, "utf8"))}`)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /not an offline approval challenge/)
  })

  it("REFUSES to present a delegation as an offline challenge", () => {
    const delegation = canonicalDelegationPayload({
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
      requirement: {
        requiredApprovals: 2,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      delegatedTo: [ALICE.did],
      delegatedQuorum: 1,
      nonce: "n2",
      sealedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    const r = decodeChallengeEnvelope(`DIV1:${b64url(Buffer.from(delegation, "utf8"))}`)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /not an offline approval challenge/)
  })

  it("gives a clear reason for a truncated paste", () => {
    const built = createOfflineChallenge({
      bundle: bundleOf(),
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
    })
    const truncated = built.challenge!.envelope.slice(0, 40)
    const r = decodeChallengeEnvelope(truncated)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /truncated paste/)
  })
})

// ── challenge construction ──────────────────────────────────────────────────────
describe("offline challenge construction", () => {
  it("takes the requirement from the BUNDLE, not from the caller", () => {
    const built = createOfflineChallenge({
      bundle: bundleOf(),
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
    })
    // The bundle says 2-of-2 for db.restart, and there is no argument by which a caller could ask for
    // fewer — a relying party choosing its own quorum would be attesting to its own configuration.
    assert.equal(built.challenge?.requirement.requiredApprovals, 2)
    assert.match(built.challenge!.canonicalPayload, /"requiredApprovals":2/)
  })

  it("refuses an action the bundle has no rule for", () => {
    const r = createOfflineChallenge({
      bundle: bundleOf(),
      ...ACTION,
      actionType: "billing.refund",
      requester: { did: "did:intyga:x", attestation: null },
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /no approval rule matching/)
  })

  it("refuses up front when the policy requires a hardware key", () => {
    // Refused at challenge time as well as at verification: sending approvers a payload nobody can
    // validly sign wastes the one resource an incident is short of.
    const bundle = bundleOf()
    bundle.policy[0]!.requireHardwareKey = true
    const r = createOfflineChallenge({
      bundle,
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /cannot be produced offline/)
  })

  it("refuses up front when the policy pins an authenticator-model allowlist", () => {
    // A non-empty allowedAaguids is the same policy class as requireHardwareKey: a bare offline key
    // has no authenticator model, so no offline signature can ever satisfy it (DIV §4.3.2).
    const bundle = bundleOf()
    bundle.policy[0]!.allowedAaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    const r = createOfflineChallenge({
      bundle,
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /cannot be produced offline/)
  })

  it("caps the window at the verifier's maximum", () => {
    const built = createOfflineChallenge({
      bundle: bundleOf(),
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
      windowMinutes: 60 * 24,
    })
    const p = JSON.parse(built.challenge!.canonicalPayload) as { challengedAt: string; expiresAt: string }
    const minutes = (Date.parse(p.expiresAt) - Date.parse(p.challengedAt)) / 60_000
    assert.equal(minutes, 60)
  })

  it("generates a fresh nonce every time", () => {
    const mk = () =>
      createOfflineChallenge({
        bundle: bundleOf(),
        ...ACTION,
        requester: { did: "did:intyga:x", attestation: null },
      }).challenge?.nonce
    assert.notEqual(mk(), mk())
  })
})

// ── the full flow ───────────────────────────────────────────────────────────────
describe("useOfflineApproval", () => {
  const requesterDid = "did:intyga:service:oncall"

  function collectFrom(...approvers: { did: string; sign: (p: string) => string; spki: string }[]) {
    return async (challenge: { canonicalPayload: string }) =>
      approvers.map((a) =>
        encodeSignatureEnvelope({
          signerDid: a.did,
          signerPublicKey: a.spki,
          signature: a.sign(challenge.canonicalPayload),
          sigAlg: "ES256",
        }),
      )
  }

  it("approves when the quorum signs, and buffers the approval for reconciliation", async () => {
    const dir = bundleDir({
      approvers: [ALICE, BOB, MALLORY, CAROL].map((a) => ({ did: a.did, publicKeys: [a.spki] })),
    })
    const warnings: string[] = []
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      requesterDid,
      collectSignatures: collectFrom(ALICE, BOB),
      warn: (m) => warnings.push(m),
    })
    assert.equal(r.ok, true, r.reason)
    assert.equal(r.signers?.length, 2)

    // Loud by design: an offline approval that happened quietly is indistinguishable from none.
    assert.equal(warnings.length, 1)
    assert.match(warnings[0] ?? "", /OFFLINE APPROVAL USED/)

    const pending = pendingApprovals({ bundleDir: dir })
    assert.equal(pending.length, 1)
    assert.equal(pending[0]?.nonce, r.nonce)
    // The full receipt is buffered so the gateway can RE-VERIFY rather than take the report on trust.
    assert.ok(pending[0]?.receipt.canonicalPayload)
  })

  it("refuses when only part of the quorum signs", async () => {
    const r = await useOfflineApproval(ACTION, {
      bundleDir: bundleDir(),
      requesterDid,
      collectSignatures: collectFrom(ALICE),
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /quorum not met: 1 of 2/)
  })

  it("refuses a signature from someone outside the rule's approver list", async () => {
    const mallory = makeApprover("did:intyga:mallory")
    const r = await useOfflineApproval(ACTION, {
      bundleDir: bundleDir(),
      requesterDid,
      collectSignatures: collectFrom(ALICE, mallory),
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /quorum not met/)
  })

  it("refuses a delegation sealed by a trusted but ineligible approver", async () => {
    const dir = bundleDir({
      approvers: [ALICE, BOB, MALLORY].map((a) => ({ did: a.did, publicKeys: [a.spki] })),
      policy: [
        {
          actionPattern: ACTION.actionType,
          requiredApprovals: 1,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: false,
          signerClass: "human",
          approverDids: [ALICE.did],
        },
      ],
    })
    const delegationDir = path.join(dir, "delegations")
    fs.mkdirSync(delegationDir)
    const payload = canonicalDelegationPayload({
      ...ACTION,
      requester: { did: requesterDid, attestation: null },
      requirement: {
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      delegatedTo: [BOB.did],
      delegatedQuorum: 1,
      nonce: "dlg_ineligible",
      sealedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    const receipt = {
      canonicalPayload: payload,
      actionDescription: ACTION.display,
      params: ACTION.params,
      requester: { did: requesterDid, attestation: null },
      signatures: [
        {
          signerDid: MALLORY.did,
          signerPublicKey: MALLORY.spki,
          signature: MALLORY.sign(payload),
          sigAlg: "ES256",
        },
      ],
      verificationCode: verificationCode(payload),
    }
    fs.writeFileSync(path.join(delegationDir, "bad.json"), JSON.stringify(receipt))
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      delegationDir,
      requesterDid,
      collectSignatures: collectFrom(BOB),
      warn: () => {},
    })
    assert.equal(r.ok, false)
  })

  it("uses a valid ordinary 2-of-N seal to delegate to two other trusted approvers", async () => {
    const dir = bundleDir({
      approvers: [ALICE, BOB, MALLORY, CAROL].map((a) => ({ did: a.did, publicKeys: [a.spki] })),
    })
    const delegationDir = path.join(dir, "delegations")
    fs.mkdirSync(delegationDir)
    const payload = canonicalDelegationPayload({
      ...ACTION,
      requester: { did: requesterDid, attestation: null },
      requirement: {
        requiredApprovals: 2,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      delegatedTo: [MALLORY.did, CAROL.did],
      delegatedQuorum: 2,
      nonce: "dlg-valid-seal",
      sealedAt: new Date(Date.now() - 1_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    fs.writeFileSync(
      path.join(delegationDir, "valid.json"),
      JSON.stringify({
        canonicalPayload: payload,
        actionDescription: ACTION.display,
        params: ACTION.params,
        requester: { did: requesterDid, attestation: null },
        signatures: [ALICE, BOB].map((a) => ({
          signerDid: a.did,
          signerPublicKey: a.spki,
          signature: a.sign(payload),
          sigAlg: "ES256",
        })),
        verificationCode: verificationCode(payload),
      }),
    )
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      delegationDir,
      requesterDid,
      collectSignatures: collectFrom(MALLORY, CAROL),
      warn: () => {},
    })
    assert.equal(r.ok, true, r.reason)
    assert.equal(r.viaDelegation, "dlg-valid-seal")
    assert.deepEqual(r.signers, [CAROL.did, MALLORY.did])
  })

  it("refuses a validly signed seal that drops the ordinary requesterCannotApprove requirement", async () => {
    const dir = bundleDir({
      approvers: [ALICE, BOB, MALLORY, CAROL].map((a) => ({ did: a.did, publicKeys: [a.spki] })),
      policy: [
        {
          actionPattern: ACTION.actionType,
          requiredApprovals: 2,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: true,
          signerClass: "human",
          approverDids: [ALICE.did, BOB.did],
        },
        {
          actionPattern: "*",
          requiredApprovals: 2,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: true,
          signerClass: "human",
          approverDids: [ALICE.did, BOB.did],
        },
      ],
    })
    const delegationDir = path.join(dir, "delegations")
    fs.mkdirSync(delegationDir)
    const payload = canonicalDelegationPayload({
      ...ACTION,
      requester: { did: requesterDid, attestation: null },
      requirement: {
        requiredApprovals: 2,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      delegatedTo: [MALLORY.did, CAROL.did],
      delegatedQuorum: 2,
      nonce: "dlg-dropped-four-eyes",
      sealedAt: new Date(Date.now() - 1_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    fs.writeFileSync(
      path.join(delegationDir, "weaker.json"),
      JSON.stringify({
        canonicalPayload: payload,
        actionDescription: ACTION.display,
        params: ACTION.params,
        requester: { did: requesterDid, attestation: null },
        signatures: [ALICE, BOB].map((a) => ({
          signerDid: a.did,
          signerPublicKey: a.spki,
          signature: a.sign(payload),
          sigAlg: "ES256",
        })),
        verificationCode: verificationCode(payload),
      }),
    )
    const warnings: string[] = []
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      delegationDir,
      requesterDid,
      collectSignatures: collectFrom(MALLORY, CAROL),
      warn: (message) => warnings.push(message),
    })
    assert.equal(r.ok, false)
    assert.equal(r.viaDelegation, undefined)
    assert.ok(
      // Refused by verifyDelegation's DIV §5 step 3d floor (the ordinary rule), before the SDK's own
      // AAGUID-aware comparison is reached.
      warnings.some((warning) =>
        /signed requirement is weaker than the relying party's policy/.test(warning),
      ),
      warnings.join("; "),
    )
  })

  it("refuses when no signatures come back at all", async () => {
    const r = await useOfflineApproval(ACTION, {
      bundleDir: bundleDir(),
      requesterDid,
      collectSignatures: async () => [],
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /not approved/)
  })

  it("enforces single use locally", async () => {
    // The relying party generates its own nonce, so single use here is fully enforceable — unlike a
    // pre-signed token, where two parties could each redeem the same artifact unaware.
    const dir = bundleDir()
    let claimed = false
    const oneShot = {
      redeem: (n: string) => {
        assert.ok(n.startsWith("off_"))
        if (claimed) return false
        claimed = true
        return true
      },
    }

    const opts = {
      bundleDir: dir,
      requesterDid,
      collectSignatures: collectFrom(ALICE, BOB),
      store: oneShot,
      warn: () => {},
    }
    assert.equal((await useOfflineApproval(ACTION, opts)).ok, true)
    const second = await useOfflineApproval(ACTION, opts)
    assert.equal(second.ok, false)
    assert.match(second.reason ?? "", /already been redeemed/)
  })

  it("refuses to run at all without a valid trust bundle", async () => {
    const r = await useOfflineApproval(ACTION, {
      bundleDir: tmpdir(),
      requesterDid,
      collectSignatures: collectFrom(ALICE, BOB),
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /no trust bundle/)
  })

  it("refuses on a stale bundle rather than falling back to an unverified approver set", async () => {
    const dir = bundleDir({
      issuedAt: new Date(Date.now() - (MAX_TRUST_BUNDLE_AGE_DAYS + 1) * 86_400_000).toISOString(),
    })
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      requesterDid,
      collectSignatures: collectFrom(ALICE, BOB),
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /maximum|expired/)
  })

  it("rechecks bundle freshness after signature collection", async () => {
    const asOf = new Date()
    const dir = bundleDir({ expiresAt: new Date(asOf.getTime() + 1_000).toISOString() })
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      requesterDid,
      asOf,
      collectSignatures: async (challenge) => {
        asOf.setTime(asOf.getTime() + 2_000)
        return collectFrom(ALICE, BOB)(challenge)
      },
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /expired|fresh|trust bundle/i)
  })

  it("rechecks delegation expiry after signature collection", async () => {
    const asOf = new Date()
    const delegationDir = path.join(
      bundleDir({
        approvers: [ALICE, BOB, MALLORY, CAROL].map((a) => ({ did: a.did, publicKeys: [a.spki] })),
      }),
      "delegations",
    )
    fs.mkdirSync(delegationDir)
    const sealedAt = new Date(asOf.getTime() - 1_000)
    const expiresAt = new Date(asOf.getTime() + 1_000)
    const payload = canonicalDelegationPayload({
      ...ACTION,
      requester: { did: requesterDid, attestation: null },
      requirement: {
        requiredApprovals: 2,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      delegatedTo: [MALLORY.did, CAROL.did],
      delegatedQuorum: 2,
      nonce: "dlg-short",
      sealedAt: sealedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    })
    fs.writeFileSync(
      path.join(delegationDir, "short.json"),
      JSON.stringify({
        canonicalPayload: payload,
        actionDescription: ACTION.display,
        params: ACTION.params,
        requester: { did: requesterDid, attestation: null },
        signatures: [ALICE, BOB].map((a) => ({
          signerDid: a.did,
          signerPublicKey: a.spki,
          signature: a.sign(payload),
          sigAlg: "ES256",
        })),
        verificationCode: verificationCode(payload),
      }),
    )
    const r = await useOfflineApproval(ACTION, {
      bundleDir: path.dirname(delegationDir),
      delegationDir,
      requesterDid,
      asOf,
      collectSignatures: async (challenge) => {
        asOf.setTime(asOf.getTime() + 60_000)
        return collectFrom(MALLORY, CAROL)(challenge)
      },
      warn: () => {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /delegation.*expired|expired.*delegation/i)
  })
})

// ── the fallback is reachable ONLY from a transport failure ──────────────────────
describe("requireApproval offline gating", () => {
  // This is the single most important property of the whole mechanism and the previous implementation
  // had no test for it. A DENIED result means a human WAS reached and said no; falling back to an
  // offline approval there would let break-glass override a refusal, which is worse than having no
  // gate at all. The distinction is easy to lose in a refactor of the poll loop, so it is pinned here.

  const REQUESTER = "did:intyga:service:oncall"

  /** A client whose HTTP layer is scripted, so each transport outcome can be produced on demand. */
  async function clientWith(
    handler: (url: string) => { status: number; body: unknown } | "throw",
    offlineOpts?: Parameters<typeof useOfflineApproval>[1],
  ) {
    const { IntygaClient } = await import("../dist/index.js")
    const realFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input)
      const out = handler(url)
      if (out === "throw") throw new Error("ECONNREFUSED")
      return new Response(JSON.stringify(out.body), {
        status: out.status,
        headers: { "content-type": "application/json" },
      })
    }) as typeof fetch
    const client = new IntygaClient({ gatewayUrl: "https://gw.invalid", token: "t" })
    return {
      client,
      offlineOpts,
      restore: () => {
        globalThis.fetch = realFetch
      },
    }
  }

  function offlineOptionsFor(dir: string) {
    return {
      bundleDir: dir,
      requesterDid: REQUESTER,
      collectSignatures: async (c: { canonicalPayload: string }) =>
        [ALICE, BOB].map((a) =>
          encodeSignatureEnvelope({
            signerDid: a.did,
            signerPublicKey: a.spki,
            signature: a.sign(c.canonicalPayload),
            sigAlg: "ES256",
          }),
        ),
      warn: () => {},
    }
  }

  it("falls back when the challenge cannot even be raised", async () => {
    const dir = bundleDir()
    const h = await clientWith(() => "throw")
    try {
      const r = await h.client.requireApproval(ACTION.display, {
        target: ACTION.target,
        actionType: ACTION.actionType,
        params: ACTION.params,
        offline: offlineOptionsFor(dir),
      })
      assert.equal(r.status, "OFFLINE_APPROVED")
      // Never "APPROVED": the usual caller guard is a test for that exact string, so a distinct status
      // is what stops an existing service silently accepting out-of-band approvals.
      assert.notEqual(r.status, "APPROVED")
    } finally {
      h.restore()
    }
  })

  // Found porting to Go, Python and Rust (2026-10-06): a local error used to route offline too, so a
  // blank target started a ceremony that bound the blank target.
  it("does NOT fall back on a local error — nothing was asked", async () => {
    const dir = bundleDir()
    let collected = 0
    const h = await clientWith(() => "throw")
    try {
      await assert.rejects(
        h.client.requireApproval(ACTION.display, {
          target: "   ",
          actionType: ACTION.actionType,
          params: ACTION.params,
          offline: {
            ...offlineOptionsFor(dir),
            collectSignatures: async () => {
              collected++
              return []
            },
          },
        }),
        /target is required/,
      )
      assert.equal(collected, 0)
    } finally {
      h.restore()
    }
  })

  it("does NOT fall back when a poll streak contains a refusal", async () => {
    const dir = bundleDir()
    let polls = 0
    let collected = 0
    const h = await clientWith((url) => {
      if (url.endsWith("/authorize")) return { status: 200, body: { nonce: "n-streak" } }
      // Reached once with a verdict (404), then gone: the 404 was an answer, not an outage.
      return polls++ === 0 ? { status: 404, body: { error: "unknown challenge" } } : { status: 503, body: {} }
    })
    try {
      await assert.rejects(
        h.client.requireApproval(ACTION.display, {
          target: ACTION.target,
          actionType: ACTION.actionType,
          params: ACTION.params,
          intervalMs: 1,
          offline: {
            ...offlineOptionsFor(dir),
            collectSignatures: async () => {
              collected++
              return []
            },
          },
        }),
        (err: unknown) => (err as { status?: number }).status === 404,
      )
      assert.equal(collected, 0)
    } finally {
      h.restore()
    }
  })

  it("without an offline opt-in, an outage surfaces as a typed GatewayUnreachable", async () => {
    const { GatewayUnreachable } = await import("../dist/index.js")
    const h = await clientWith(() => "throw")
    try {
      await assert.rejects(
        h.client.requireApproval(ACTION.display, { target: ACTION.target, actionType: ACTION.actionType }),
        (err: unknown) =>
          err instanceof GatewayUnreachable && /could not reach Intyga/.test((err as Error).message),
      )
    } finally {
      h.restore()
    }
  })

  it("does NOT fall back on DENIED — a human was reached and refused", async () => {
    const dir = bundleDir()
    // `POST /authorize` creates the challenge; `GET /authorize/<nonce>` polls it.
    const h = await clientWith((url) =>
      url.endsWith("/authorize")
        ? { status: 200, body: { nonce: "n1" } }
        : { status: 200, body: { status: "DENIED", nonce: "n1" } },
    )
    try {
      const r = await h.client.requireApproval(ACTION.display, {
        target: ACTION.target,
        actionType: ACTION.actionType,
        params: ACTION.params,
        offline: offlineOptionsFor(dir),
      })
      assert.equal(r.status, "DENIED")
      // And nothing was buffered — no offline ceremony was even attempted.
      assert.equal(pendingApprovals({ bundleDir: dir }).length, 0)
    } finally {
      h.restore()
    }
  })

  it("does NOT fall back on EXPIRED — nobody approved in time", async () => {
    const dir = bundleDir()
    const h = await clientWith((url) =>
      url.endsWith("/authorize")
        ? { status: 200, body: { nonce: "n2" } }
        : { status: 200, body: { status: "EXPIRED", nonce: "n2" } },
    )
    try {
      const r = await h.client.requireApproval(ACTION.display, {
        target: ACTION.target,
        actionType: ACTION.actionType,
        params: ACTION.params,
        offline: offlineOptionsFor(dir),
      })
      assert.equal(r.status, "EXPIRED")
      assert.equal(pendingApprovals({ bundleDir: dir }).length, 0)
    } finally {
      h.restore()
    }
  })

  it("throws rather than falling back when no offline options were passed", async () => {
    // Omitting `offline` means no fallback, ever. Opting in has to be an explicit code change at the
    // call site permitted to run under one.
    const h = await clientWith(() => "throw")
    try {
      await assert.rejects(
        h.client.requireApproval(ACTION.display, {
          target: ACTION.target,
          actionType: ACTION.actionType,
          params: ACTION.params,
        }),
        /could not reach Intyga/,
      )
    } finally {
      h.restore()
    }
  })
})

// ── the browser signing page ────────────────────────────────────────────────────
describe("offline-sign.html signing path", () => {
  // The page cannot be loaded here, but its crypto CAN be: it imports a PKCS#8 P-256 key with
  // WebCrypto and signs with ECDSA/SHA-256 in raw r||s form. If that combination did not produce a
  // signature @intyga/verify accepts, the page would be quietly useless in exactly the situation it
  // exists for — so the same calls are exercised against the same verifier.
  it("produces a signature the verifier accepts", async () => {
    const built = createOfflineChallenge({
      bundle: bundleOf({
        policy: [
          {
            actionPattern: "db.restart",
            requiredApprovals: 1,
            requireHardwareKey: false,
            allowedAaguids: [],
            requesterCannotApprove: false,
            signerClass: "human",
            approverDids: [ALICE.did],
          },
          {
            actionPattern: "*",
            requiredApprovals: 1,
            requireHardwareKey: false,
            allowedAaguids: [],
            requesterCannotApprove: false,
            signerClass: "human",
            approverDids: [ALICE.did],
          },
        ],
      }),
      ...ACTION,
      requester: { did: "did:intyga:x", attestation: null },
    })
    const canonical = built.challenge!.canonicalPayload

    const key = await crypto.webcrypto.subtle.importKey(
      "pkcs8",
      ALICE.pkcs8,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    )
    const sig = await crypto.webcrypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      new TextEncoder().encode(canonical),
    )
    const sigB64 = Buffer.from(new Uint8Array(sig)).toString("base64")

    const { verifyApprovalReceipt } = await import("@intyga/verify")
    const r = verifyApprovalReceipt(
      {
        canonicalPayload: canonical,
        target: ACTION.target,
        actionType: ACTION.actionType,
        actionDescription: ACTION.display,
        params: ACTION.params,
        signatures: [
          { signerDid: ALICE.did, signerPublicKey: ALICE.spki, signature: sigB64, sigAlg: "ES256" },
        ],
        requester: { did: "did:intyga:x", attestation: null },
        verificationCode: built.challenge!.verificationCode,
      },
      {
        target: ACTION.target,
        actionType: ACTION.actionType,
        params: ACTION.params,
        nonce: built.challenge!.nonce,
        approvers: { dids: [ALICE.did], resolveKey: () => ALICE.spki },
      },
      { allowOffline: true },
    )
    assert.equal(r.ok, true, r.reason)
  })

  it("computes the same verification code as the verifier", async () => {
    // The approver reads this code back to the operator. If the two implementations disagreed the
    // check would be worse than useless — it would reliably fail on legitimate requests and train
    // people to ignore it.
    const canonical = '{"a":1,"type":"div-offline-intent"}'
    const digest = await crypto.webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))
    const hex = [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 8)
      .toUpperCase()
    assert.equal(`${hex.slice(0, 4)}-${hex.slice(4, 8)}`, verificationCode(canonical))
  })
})

// ── delegation may narrow WHO, never HOW MANY (DIV §5a.5) ───────────────────────
describe("delegation quorum floor", () => {
  const delegationFor = (delegatedQuorum: number) => ({
    delegatedTo: [ALICE.did, BOB.did],
    delegatedQuorum,
    target: ACTION.target,
    actionType: ACTION.actionType,
    params: ACTION.params,
    nonce: "dlg_00000000-0000-4000-8000-000000000000",
    signers: [ALICE.did, BOB.did],
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  })

  it("REFUSES a delegation that would lower the bundle's quorum", () => {
    // The bundle requires 2 approvals for db.restart. The delegation branch used to overwrite
    // `requiredApprovals` with `delegatedQuorum` unconditionally, so 1 replaced 2 and the resulting
    // receipt verified perfectly — the signed requiredApprovals equalled delegatedQuorum, exactly as
    // §5a.6 step 3 requires. Nothing at the relying party compared it against the policy it holds.
    //
    // §5a.6 step 2 compares only target/actionType/params, so `display` is free to differ between
    // sealing and use — and `display` is what requirementFor matches on. That is the gap: seal against
    // a permissive rule, present against a strict one.
    const r = createOfflineChallenge({
      bundle: bundleOf(),
      ...ACTION,
      requester: { did: "did:intyga:service:oncall", attestation: null },
      delegation: delegationFor(1),
    })
    assert.equal(r.ok, false, "a delegation lowered a 2-of-N action to 1-of-N")
    assert.match(r.reason!, /narrow WHO approves, never HOW MANY/)
  })

  it("ALLOWS a delegation that matches the quorum, and one that raises it", () => {
    for (const quorum of [2, 3]) {
      const r = createOfflineChallenge({
        bundle: bundleOf(),
        ...ACTION,
        requester: { did: "did:intyga:service:oncall", attestation: null },
        delegation: delegationFor(quorum),
      })
      assert.equal(r.ok, true, `quorum ${quorum} should be permitted: ${r.reason}`)
      // The delegated quorum is what gets signed, so the delegates sign the policy they are counted
      // toward — a delegation may still be STRICTER than the bundle.
      assert.match(r.challenge!.canonicalPayload, new RegExp(`"requiredApprovals":${quorum}`))
    }
  })
})

describe("nonces used as path segments", () => {
  // In the documented flow every nonce is a locally generated `off_<uuid>`. But clearPendingApproval
  // is public API, and a reconciliation loop plausibly feeds it a nonce echoed back by the gateway —
  // so a hostile gateway must not be able to turn it into an arbitrary-unlink primitive.
  it("clearPendingApproval refuses a traversal nonce", () => {
    const dir = tmpdir()
    const bufferDir = path.join(dir, "buf")
    fs.mkdirSync(bufferDir)
    const victim = path.join(dir, "victim.json")
    fs.writeFileSync(victim, "{}")

    clearPendingApproval("../victim", { bundleDir: dir, bufferDir })
    assert.ok(fs.existsSync(victim), "a traversal nonce escaped the buffer directory")
  })

  it("clearPendingApproval still removes a legitimately buffered record", () => {
    const dir = tmpdir()
    const bufferDir = path.join(dir, "buf")
    fs.mkdirSync(bufferDir)
    fs.writeFileSync(path.join(bufferDir, "off_abc123.json"), "{}")

    clearPendingApproval("off_abc123", { bundleDir: dir, bufferDir })
    assert.equal(fs.existsSync(path.join(bufferDir, "off_abc123.json")), false)
  })

  it("FileRedemptionStore refuses a traversal nonce", () => {
    const dir = tmpdir()
    const store = new FileRedemptionStore(path.join(dir, "used"))
    assert.equal(store.redeem("../escape"), false)
    assert.equal(fs.existsSync(path.join(dir, "escape.used")), false)
  })
})

describe("offline-sign.html source pin", () => {
  // The parity tests above re-implement the page's WebCrypto calls — they cannot execute the HTML
  // itself, so an edit to the page's own script used to pass this suite unnoticed. Pinning the
  // source text of the security-relevant lines makes a page edit fail here until the parity tests
  // are re-checked against it.
  const html = fs.readFileSync(new URL("../offline-sign.html", import.meta.url), "utf8")

  it("still derives the verification code exactly as @intyga/verify does", () => {
    assert.match(html, /crypto\.subtle\.digest\("SHA-256", new TextEncoder\(\)\.encode\(canonical\)\)/)
    assert.match(html, /\.slice\(0, 8\)/)
    assert.match(html, /\.toUpperCase\(\)/)
    assert.match(html, /hex\.slice\(0, 4\)\}-\$\{hex\.slice\(4, 8\)\}/)
  })

  it("still signs P-256 ECDSA (raw P1363) over the canonical bytes", () => {
    assert.match(html, /namedCurve: "P-256"/)
    assert.match(html, /\{ name: "ECDSA", hash: "SHA-256" \}/)
    assert.match(html, /new TextEncoder\(\)\.encode\(current\.canonical\)/)
  })

  it("re-checks expiry at sign time, not only at decode time", () => {
    assert.match(html, /Date\.parse\(current\.expiresAt\) < Date\.now\(\)/)
  })
})

// Security review 2026-10-06, finding 2. Offline signing keys travel in their own list, and count only
// toward a div-offline-intent: a delegation verified against the same bundle is sealed by the ORDINARY
// quorum, which a bare offline key must never be able to stand in for.
describe("offline signing keys in the trust bundle (DIV §5a.4)", () => {
  const requesterDid = "did:intyga:service:oncall"
  const ALICE_OFF = { ...makeApprover(ALICE.did) }
  const BOB_OFF = { ...makeApprover(BOB.did) }
  const withOfflineKeys = {
    approvers: [
      { did: ALICE.did, publicKeys: [ALICE.spki], offlinePublicKeys: [ALICE_OFF.spki] },
      { did: BOB.did, publicKeys: [BOB.spki], offlinePublicKeys: [BOB_OFF.spki] },
      { did: MALLORY.did, publicKeys: [MALLORY.spki] },
      { did: CAROL.did, publicKeys: [CAROL.spki] },
    ],
  }
  const collectFrom =
    (...approvers: { did: string; sign: (p: string) => string; spki: string }[]) =>
    async (challenge: { canonicalPayload: string }) =>
      approvers.map((a) =>
        encodeSignatureEnvelope({
          signerDid: a.did,
          signerPublicKey: a.spki,
          signature: a.sign(challenge.canonicalPayload),
          sigAlg: "ES256",
        }),
      )

  it("admits offline keys only to an offline-intent anchor", () => {
    const bundle = bundleOf(withOfflineKeys)
    assert.deepEqual(approverAnchor(bundle).resolveKey?.(ALICE.did), [ALICE.spki])
    assert.deepEqual(approverAnchor(bundle, undefined, "ordinary").resolveKey?.(ALICE.did), [ALICE.spki])
    assert.deepEqual(approverAnchor(bundle, undefined, "offline-intent").resolveKey?.(ALICE.did), [
      ALICE.spki,
      ALICE_OFF.spki,
    ])
  })

  it("refuses a bundle that lists one key as both ordinary and offline-only", () => {
    const mixed = bundleOf({
      approvers: [{ did: ALICE.did, publicKeys: [ALICE.spki], offlinePublicKeys: [ALICE.spki] }],
    })
    const r = verifyTrustBundle(signBundle(mixed), GATEWAY_JWK)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /offline signing key as an ordinary key/)
    const malformed = bundleOf({
      approvers: [
        { did: ALICE.did, publicKeys: [ALICE.spki], offlinePublicKeys: "x" as unknown as string[] },
      ],
    })
    assert.equal(verifyTrustBundle(signBundle(malformed), GATEWAY_JWK).ok, false)
  })

  it("approves an offline intent signed with the approvers' offline keys", async () => {
    const r = await useOfflineApproval(ACTION, {
      bundleDir: bundleDir(withOfflineKeys),
      requesterDid,
      collectSignatures: collectFrom(ALICE_OFF, BOB_OFF),
      warn: () => {},
    })
    assert.equal(r.ok, true, r.reason)
    assert.deepEqual(r.signers, [ALICE.did, BOB.did])
  })

  it("never accepts a delegation sealed with offline keys", async () => {
    const dir = bundleDir(withOfflineKeys)
    const delegationDir = path.join(dir, "delegations")
    fs.mkdirSync(delegationDir)
    const payload = canonicalDelegationPayload({
      ...ACTION,
      requester: { did: requesterDid, attestation: null },
      requirement: {
        requiredApprovals: 2,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      delegatedTo: [MALLORY.did, CAROL.did],
      delegatedQuorum: 2,
      nonce: "dlg-offline-seal",
      sealedAt: new Date(Date.now() - 1_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    fs.writeFileSync(
      path.join(delegationDir, "offline-sealed.json"),
      JSON.stringify({
        canonicalPayload: payload,
        actionDescription: ACTION.display,
        params: ACTION.params,
        requester: { did: requesterDid, attestation: null },
        signatures: [ALICE_OFF, BOB_OFF].map((a) => ({
          signerDid: a.did,
          signerPublicKey: a.spki,
          signature: a.sign(payload),
          sigAlg: "ES256",
        })),
        verificationCode: verificationCode(payload),
      }),
    )
    const warnings: string[] = []
    const r = await useOfflineApproval(ACTION, {
      bundleDir: dir,
      delegationDir,
      requesterDid,
      collectSignatures: collectFrom(MALLORY, CAROL),
      warn: (m) => warnings.push(m),
    })
    assert.equal(r.ok, false, "the delegates must not count: the seal is not an ordinary quorum")
    assert.equal(r.viaDelegation, undefined)
    assert.match(warnings.join("\n"), /no delegation applies/)
  })
})

describe("signChallengeEnvelope", () => {
  const bundle = bundleOf()
  const fixedNonce = "off_sign-test"
  const challengeAt = (asOf: Date) => {
    const built = createOfflineChallenge({
      bundle,
      ...ACTION,
      requester: { did: "did:intyga:service:oncall", attestation: null },
      asOf,
      nonce: fixedNonce,
    })
    assert.equal(built.ok, true, built.reason)
    return built.challenge!
  }

  it("signs a canonical offline challenge into a SIG1 envelope the receipt verifier accepts", () => {
    const c = challengeAt(new Date())
    const signed = signChallengeEnvelope(c.envelope, { privateKey: ALICE.pkcs8, signerDid: ALICE.did })
    assert.equal(signed.ok, true, signed.reason)
    const witness = decodeSignatureEnvelope(signed.envelope!).witness!
    assert.equal(witness.signerDid, ALICE.did)
    assert.equal(witness.signerPublicKey, ALICE.spki)
    assert.equal(
      crypto.verify(
        "sha256",
        Buffer.from(c.canonicalPayload, "utf8"),
        {
          key: crypto.createPublicKey({
            key: Buffer.from(ALICE.spki, "base64"),
            format: "der",
            type: "spki",
          }),
          dsaEncoding: "ieee-p1363",
        },
        Buffer.from(witness.signature, "base64"),
      ),
      true,
    )
  })

  it("refuses an expired challenge, an ordinary intent and a non-P-256 key", () => {
    const old = challengeAt(new Date(Date.now() - 3_600_000))
    assert.match(
      signChallengeEnvelope(old.envelope, { privateKey: ALICE.pkcs8, signerDid: ALICE.did }).reason ?? "",
      /expired/,
    )
    const ordinary = canonicalIntentPayload({
      target: ACTION.target,
      actionType: ACTION.actionType,
      display: ACTION.display,
      params: ACTION.params,
      requester: { did: "did:intyga:service:oncall", attestation: null },
      requirement: {
        requiredApprovals: 1,
        requireHardwareKey: false,
        allowedAaguids: [],
        requesterCannotApprove: false,
        signerClass: "human",
      },
      nonce: "n-ordinary",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    const ordinaryEnvelope = `DIV1:${b64url(Buffer.from(ordinary, "utf8"))}`
    assert.equal(
      signChallengeEnvelope(ordinaryEnvelope, { privateKey: ALICE.pkcs8, signerDid: ALICE.did }).ok,
      false,
    )
    const ed = crypto.generateKeyPairSync("ed25519").privateKey
    assert.match(
      signChallengeEnvelope(challengeAt(new Date()).envelope, { privateKey: ed, signerDid: ALICE.did })
        .reason ?? "",
      /P-256/,
    )
  })
})

describe("robustness found porting to other languages", () => {
  it("refuses a SIG1 or DIV1 envelope whose payload is not an object, instead of throwing", () => {
    for (const payload of ["null", "[]", "7"]) {
      const env = Buffer.from(payload, "utf8").toString("base64url")
      assert.equal(decodeSignatureEnvelope(`SIG1:${env}`).ok, false, payload)
      assert.equal(decodeChallengeEnvelope(`DIV1:${env}`).ok, false, payload)
    }
  })

  it("refuses base64url with stray characters rather than skipping them", () => {
    const valid = encodeSignatureEnvelope({
      signerDid: ALICE.did,
      signerPublicKey: ALICE.spki,
      signature: "c2ln",
      sigAlg: "ES256",
    })
    assert.equal(decodeSignatureEnvelope(valid).ok, true)
    assert.equal(decodeSignatureEnvelope(`${valid.slice(0, 20)}!${valid.slice(20)}`).ok, false)
  })

  it("one unreadable pending record hides none of the others, and reconcile counts it as failed", async () => {
    const dir = tmpdir()
    fs.mkdirSync(path.join(dir, ".pending"), { recursive: true })
    fs.writeFileSync(path.join(dir, ".pending", "a-corrupt.json"), "{not json")
    fs.writeFileSync(
      path.join(dir, ".pending", "b-good.json"),
      JSON.stringify({
        nonce: "b-good",
        target: "t",
        actionType: "a",
        display: "d",
        usedAt: "2026-10-06T00:00:00.000Z",
        receipt: {},
      }),
    )
    assert.deepEqual(
      pendingApprovals({ bundleDir: dir }).map((p: { nonce: string }) => p.nonce),
      ["b-good"],
    )
    const { IntygaClient } = await import("../dist/index.js")
    const realFetch = globalThis.fetch
    globalThis.fetch = (async () => new Response("{}", { status: 200 })) as typeof fetch
    try {
      const r = await new IntygaClient({
        gatewayUrl: "https://gw.invalid",
        token: "t",
      }).reconcileOfflineApprovals({
        bundleDir: dir,
      })
      assert.equal(r.reported, 1)
      assert.equal(r.failed, 1)
      assert.match(r.reasons.join("\n"), /a-corrupt\.json: unreadable/)
      assert.ok(fs.existsSync(path.join(dir, ".pending", "a-corrupt.json")), "an unreadable record is kept")
    } finally {
      globalThis.fetch = realFetch
    }
  })

  it("refuses a pinned gateway key that is not RSA, and a bundle timestamp outside RFC 3339", () => {
    const ec = crypto
      .generateKeyPairSync("ec", { namedCurve: "prime256v1" })
      .publicKey.export({ format: "jwk" })
    assert.match(verifyTrustBundle(signBundle(bundleOf()), ec as webcrypto.JsonWebKey).reason ?? "", /RSA/)
    const dateOnly = bundleOf({ issuedAt: new Date().toISOString().slice(0, 10) })
    assert.equal(verifyTrustBundle(signBundle(dateOnly), GATEWAY_JWK).ok, false)
  })

  it("refuses a fractional window and an empty nonce", () => {
    const base = {
      bundle: bundleOf(),
      ...ACTION,
      requester: { did: "did:intyga:service:oncall", attestation: null },
    }
    assert.equal(createOfflineChallenge({ ...base, windowMinutes: 2.5 }).ok, false)
    assert.equal(createOfflineChallenge({ ...base, nonce: "" }).ok, false)
  })
})
