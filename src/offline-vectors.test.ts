// The TypeScript SDK against the shared offline-approval conformance vectors
// (packages/mcp-schemas/vectors/offline-approval-vectors.json, docs/OFFLINE-APPROVAL-SDK.md).
//
// This file is also the reference harness for the other ports: Python, Go, Rust and Java run the same
// sections the same way. It reads the COMMITTED file, never the generator, so a change to the
// TypeScript behaviour that is not regenerated and reviewed fails here.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import type { webcrypto } from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { describe, it } from "node:test"
import {
  createOfflineChallenge,
  decodeChallengeEnvelope,
  decodeSignatureEnvelope,
  encodeSignatureEnvelope,
  signChallengeEnvelope,
  useOfflineApproval,
} from "../dist/offline.js"
import {
  parseTrustAnchorFile,
  trustAnchorApprovers,
  trustAnchorEnrolledDeviceKeys,
} from "../dist/trust-anchor.js"
import { approverAnchor, requirementFor, type TrustBundle, verifyTrustBundle } from "../dist/trust-bundle.js"

const V = JSON.parse(
  fs.readFileSync(
    new URL("../vectors/offline-approval-vectors.json", import.meta.url),
    "utf8",
  ),
)

/** api-name-hints.json: rewrite the TypeScript API names in an expected reason into this language's. */
const HINTS = JSON.parse(
  fs.readFileSync(new URL("../vectors/api-name-hints.json", import.meta.url), "utf8"),
) as { tokens: string[]; typescript: Record<string, string> }
assert.deepEqual(
  Object.keys(HINTS.typescript).sort(),
  [...HINTS.tokens].sort(),
  "api-name-hints typescript map",
)
function localized(text: string): string {
  const order = [...HINTS.tokens].sort((a, b) => b.length - a.length)
  let out = text
  order.forEach((token, i) => {
    out = out.split(token).join(`\u0000${i}\u0000`)
  })
  order.forEach((token, i) => {
    out = out.split(`\u0000${i}\u0000`).join(HINTS.typescript[token] ?? token)
  })
  return out
}
const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
function keyFromSeed(seed: string): crypto.KeyObject {
  const h = BigInt(`0x${crypto.createHash("sha256").update(seed, "utf8").digest("hex")}`)
  const d = Buffer.from(((h % (P256_N - 1n)) + 1n).toString(16).padStart(64, "0"), "hex")
  const ecdh = crypto.createECDH("prime256v1")
  ecdh.setPrivateKey(d)
  const point = ecdh.getPublicKey()
  return crypto.createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      d: d.toString("base64url"),
      x: point.subarray(1, 33).toString("base64url"),
      y: point.subarray(33).toString("base64url"),
    },
    format: "jwk",
  })
}
type Person = { did: string; keys: Record<string, { seed: string; spki: string }> }
const person = (id: string): Person => V.people[id]
const keyOf = (id: string, kind: string) => {
  const k = person(id).keys[kind]
  if (!k) throw new Error(`${id} has no ${kind} key`)
  return k
}
const sign = (id: string, kind: string, payload: string) =>
  crypto
    .sign("sha256", Buffer.from(payload, "utf8"), {
      key: keyFromSeed(keyOf(id, kind).seed),
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64")
const GATEWAY_JWK = V.gatewayJwk as webcrypto.JsonWebKey
/** Every refusal carries the reference reason: exact `reason`, or `reasonPrefix` where the text embeds a library message. */
function assertReason(c: { name: string; reason?: string; reasonPrefix?: string }, got: string | undefined) {
  if (c.reason !== undefined) assert.equal(got, localized(c.reason), `${c.name}: reason`)
  else if (c.reasonPrefix !== undefined)
    assert.ok(
      got?.startsWith(localized(c.reasonPrefix)),
      `${c.name}: reason ${got} lacks prefix ${c.reasonPrefix}`,
    )
  else assert.fail(`${c.name}: a refusal vector must carry reason or reasonPrefix`)
}
const bundleWith = (over: Record<string, unknown>): TrustBundle => ({ ...V.bundle, ...over })

describe("offline-approval vectors", () => {
  it("derives every published key from its seed", () => {
    for (const id of Object.keys(V.people)) {
      for (const [kind, k] of Object.entries(person(id).keys)) {
        const spki = crypto
          .createPublicKey(keyFromSeed(k.seed))
          .export({ format: "der", type: "spki" })
          .toString("base64")
        assert.equal(spki, k.spki, `${id}/${kind}`)
      }
    }
  })

  it("trustBundle", () => {
    for (const c of V.trustBundle) {
      const r = verifyTrustBundle(c.jws, c.gatewayJwk ?? GATEWAY_JWK, { asOf: new Date(c.asOf) })
      assert.equal(r.ok, c.ok, `${c.name}: ${r.reason}`)
      if (c.ok) assert.deepEqual(r.bundle, c.bundle, c.name)
      else assertReason(c, r.reason)
    }
  })

  it("bundleAnchor", () => {
    for (const c of V.bundleAnchor) {
      let anchor: ReturnType<typeof approverAnchor> | null = null
      let reason: string | undefined
      try {
        anchor = approverAnchor(
          {
            ...V.bundle,
            ...(c.approvers ? { approvers: c.approvers } : {}),
            ...(c.controllerKeys ? { controllerKeys: c.controllerKeys } : {}),
          },
          c.limitToDids ?? undefined,
          c.purpose,
          c.excludedDids ?? [],
        )
      } catch (err) {
        reason = (err as Error).message
      }
      assert.equal(anchor !== null, c.ok, c.name)
      if (!c.ok) assertReason(c, reason)
      if (!anchor || !c.expect) continue
      assert.deepEqual(anchor.dids, c.expect.dids)
      for (const [did, keys] of Object.entries(c.expect.keys))
        assert.deepEqual(anchor.resolveKey?.(did) ?? null, keys)
    }
  })

  it("requirementFor", () => {
    for (const c of V.requirementFor) {
      const bundle = bundleWith({
        ...(c.bundleVersion !== undefined ? { v: c.bundleVersion } : {}),
        policy: c.policy,
        unmatchedActionPolicy: c.unmatchedActionPolicy,
        ...(c.requesterControllers !== undefined ? { requesterControllers: c.requesterControllers } : {}),
      })
      assert.deepEqual(requirementFor(bundle, c.actionType, c.display, c.requesterDid), c.expect, c.name)
    }
  })

  it("trustAnchorFile", () => {
    for (const c of V.trustAnchorFile) {
      let got: unknown = null
      let reason: string | undefined
      try {
        const parsed = parseTrustAnchorFile(c.text, { purpose: c.purpose })
        const anchor = trustAnchorApprovers(parsed)
        const enrolledDeviceKeys = trustAnchorEnrolledDeviceKeys(parsed)
        got = {
          purpose: parsed.purpose,
          epoch: parsed.epoch,
          ...(parsed.tenantId !== undefined ? { tenantId: parsed.tenantId } : {}),
          dids: anchor.dids,
          keys: Object.fromEntries(anchor.dids.map((d: string) => [d, anchor.resolveKey?.(d) ?? null])),
          ...(enrolledDeviceKeys.length > 0 ? { enrolledDeviceKeys } : {}),
        }
      } catch (err) {
        reason = (err as Error).message
      }
      assert.equal(got !== null, c.ok, c.name)
      if (c.ok) assert.deepEqual(got, c.expect, c.name)
      else assertReason(c, reason)
    }
  })

  it("createChallenge", () => {
    for (const c of V.createChallenge) {
      const {
        delegation,
        asOf,
        bundleTenantId,
        bundleRequesterControllers,
        bundleVersion,
        bundlePolicy,
        ...input
      } = c.input
      const bundle = { ...V.bundle } as Record<string, unknown>
      if (bundleVersion !== undefined) bundle.v = bundleVersion
      if (bundlePolicy !== undefined) bundle.policy = bundlePolicy
      if (bundleTenantId === null) delete bundle.tenantId
      else if (bundleTenantId !== undefined) bundle.tenantId = bundleTenantId
      if (bundleRequesterControllers === null) delete bundle.requesterControllers
      const r = createOfflineChallenge({
        bundle: bundle as never,
        ...input,
        asOf: new Date(asOf),
        ...(delegation
          ? {
              delegation: {
                ...delegation,
                target: input.target,
                actionType: input.actionType,
                params: input.params,
                signers: [],
              },
            }
          : {}),
      })
      assert.equal(r.ok, c.ok, `${c.name}: ${r.reason}`)
      if (!c.ok) {
        assertReason(c, r.reason)
        continue
      }
      for (const field of Object.keys(c.expect))
        assert.deepEqual(
          (r.challenge as Record<string, unknown>)[field],
          c.expect[field],
          `${c.name}.${field}`,
        )
    }
  })

  it("challengeEnvelope", () => {
    for (const c of V.challengeEnvelope) {
      const r = decodeChallengeEnvelope(c.envelope)
      assert.equal(r.ok, c.ok, `${c.name}: ${r.reason}`)
      if (c.ok) assert.deepEqual(r.challenge, c.expect, c.name)
      else assertReason(c, r.reason)
    }
  })

  it("signatureEnvelope", () => {
    for (const c of V.signatureEnvelope.encode) assert.equal(encodeSignatureEnvelope(c.witness), c.envelope)
    for (const c of V.signatureEnvelope.decode) {
      const r = decodeSignatureEnvelope(c.envelope)
      assert.equal(r.ok, c.ok, c.name)
      if (c.ok) assert.deepEqual(r.witness, c.witness, c.name)
      else assertReason(c, r.reason)
    }
  })

  it("signChallenge", () => {
    for (const c of V.signChallenge) {
      const r = signChallengeEnvelope(c.envelope, {
        privateKey: keyFromSeed(keyOf(c.signer.person, c.signer.key).seed),
        signerDid: c.signerDid,
        asOf: new Date(c.asOf),
      })
      assert.equal(r.ok, c.ok, `${c.name}: ${r.reason}`)
      if (!c.ok) {
        assertReason(c, r.reason)
        continue
      }
      const w = decodeSignatureEnvelope(r.envelope ?? "").witness
      assert.equal(w?.signerDid, c.expect.signerDid)
      assert.equal(w?.signerPublicKey, c.expect.signerPublicKey)
      assert.equal(w?.sigAlg, c.expect.sigAlg)
      const payload = decodeChallengeEnvelope(c.envelope).challenge?.canonicalPayload ?? ""
      const pub = crypto.createPublicKey({
        key: Buffer.from(c.expect.signerPublicKey, "base64"),
        format: "der",
        type: "spki",
      })
      assert.ok(
        crypto.verify(
          "sha256",
          Buffer.from(payload, "utf8"),
          { key: pub, dsaEncoding: "ieee-p1363" },
          Buffer.from(w?.signature ?? "", "base64"),
        ),
        c.name,
      )
    }
  })

  it("offlineApproval", async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-offline-vectors-"))
    try {
      for (const c of V.offlineApproval) {
        const dir = fs.mkdtempSync(path.join(scratch, "case-"))
        fs.writeFileSync(path.join(dir, "trust-bundle.jws"), c.bundleJws ?? V.bundleJws)
        fs.writeFileSync(path.join(dir, "gateway-key.jwk.json"), JSON.stringify(V.gatewayJwk))
        let delegationDir: string | undefined
        if (c.delegation || c.delegationArtifacts) {
          const currentDelegationDir = path.join(dir, "delegations")
          delegationDir = currentDelegationDir
          fs.mkdirSync(currentDelegationDir)
          if (c.delegationArtifacts) {
            c.delegationArtifacts.forEach((artifact: unknown, index: number) => {
              fs.writeFileSync(
                path.join(currentDelegationDir, `00-invalid-${String(index).padStart(2, "0")}.json`),
                JSON.stringify(artifact),
              )
            })
          }
          if (c.delegation) {
            fs.writeFileSync(
              path.join(currentDelegationDir, `${c.delegation}.json`),
              JSON.stringify(V.delegations[c.delegation]),
            )
          }
        }
        const bufferDir = c.bufferFailure ? path.join(dir, "not-a-directory") : undefined
        if (bufferDir) fs.writeFileSync(bufferDir, "buffer failure")
        const r = await useOfflineApproval(c.action, {
          bundleDir: dir,
          bufferDir,
          delegationDir,
          requesterDid: c.requesterDid ?? V.requesterDid,
          asOf: new Date(c.asOf),
          warn: () => {},
          collectSignatures: async (challenge) =>
            c.signers.map((s: { raw?: string; person: string; key: string; claimDid?: string }) =>
              s.raw !== undefined
                ? s.raw
                : encodeSignatureEnvelope({
                    signerDid: person(s.claimDid ?? s.person).did,
                    signerPublicKey: keyOf(s.person, s.key).spki,
                    signature: sign(s.person, s.key, challenge.canonicalPayload),
                    sigAlg: "ES256",
                  }),
            ),
        })
        assert.equal(r.ok, c.ok, `${c.name}: ${r.reason}`)
        if (c.bufferFailure) {
          assert.match(r.reason ?? "", /could not buffer/)
          assert.deepEqual(fs.readdirSync(path.join(dir, ".redeemed")), [])
        }
        if (!c.ok) {
          assertReason(c, r.reason)
          continue
        }
        assert.deepEqual([...(r.signers ?? [])].sort(), c.expect.signers, c.name)
        assert.equal(r.viaDelegation ?? null, c.expect.viaDelegation, c.name)
      }
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true })
    }
  })
})
