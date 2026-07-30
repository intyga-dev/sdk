// Offline approval, end to end at the relying party (docs/DIV.md §5a).
//
// The interesting assertions here are the ones about where things come FROM: the requirement from the
// signed bundle rather than from the caller, the approver keys from the bundle rather than the receipt,
// and the fallback from a transport failure rather than from a refusal. Those are the properties that
// make this a gate rather than a hole, and each is a plausible casualty of a future refactor.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { describe, it } from "node:test"
// Tests run against the BUILT output, matching the convention in index.test.ts / cli.test.ts: this
// package's `npm test` uses `node --test`, which resolves `.js` specifiers to real files.
import { canonicalDelegationPayload, canonicalIntentPayload, verificationCode } from "@intyga/verify"
import {
  createOfflineChallenge,
  decodeChallengeEnvelope,
  decodeSignatureEnvelope,
  encodeSignatureEnvelope,
  pendingApprovals,
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
const GATEWAY_JWK = GATEWAY.publicKey.export({ format: "jwk" }) as JsonWebKey

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
  return {
    v: 1,
    type: "div-trust-bundle",
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
        approverDids: [ALICE.did, BOB.did],
      },
    ],
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    ...over,
  }
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

  it("resolves the STRICTEST matching rule, matching on actionType as well as display", () => {
    const bundle = bundleOf({
      policy: [
        {
          actionPattern: "*",
          requiredApprovals: 1,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: false,
          approverDids: [ALICE.did],
        },
        {
          // Keyed to the ACTION TYPE, and deliberately absent from the display text — a matcher that
          // only looked at the description would miss this and hand back the 1-of-1 rule.
          actionPattern: "db.restart",
          requiredApprovals: 3,
          requireHardwareKey: false,
          allowedAaguids: [],
          requesterCannotApprove: true,
          approverDids: [ALICE.did, BOB.did],
        },
      ],
    })
    const resolved = requirementFor(bundle, "db.restart", "Emergency recovery procedure")
    assert.equal(resolved?.requirement.requiredApprovals, 3)
    assert.equal(resolved?.requirement.requesterCannotApprove, true)
  })

  it("returns null for an unmatched action rather than defaulting to 1-of-1", () => {
    assert.equal(requirementFor(bundleOf(), "billing.refund", "Refund a customer"), null)
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
    const dir = bundleDir()
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
    const client = new IntygaClient({ gatewayUrl: "http://gw.invalid", token: "t" })
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
