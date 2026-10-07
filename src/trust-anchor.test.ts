import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { selfCertifyingDid } from "@intyga/verify"

// Exercise the BUILT module consumers install, matching the rest of this package's tests.
const { parseTrustAnchorFile, TRUST_ANCHOR_FILE_TYPE, trustAnchorApprovers } = await import(
  "../dist/trust-anchor.js"
)

const KEY = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const SPKI_B64 = KEY.publicKey.export({ format: "der", type: "spki" }).toString("base64")

/** A minimal valid file; tests copy and break exactly one thing at a time. */
const VALID = {
  type: TRUST_ANCHOR_FILE_TYPE,
  v: 1,
  epoch: 3,
  approvers: [
    { did: "did:intyga:human-alice", publicKeys: [SPKI_B64] },
    { did: selfCertifyingDid(SPKI_B64), publicKeys: [] },
  ],
  webauthn: { origin: "https://console.example", rpId: "console.example" },
}

test("parses a valid file and builds a DID-mode anchor from it", () => {
  const file = parseTrustAnchorFile(JSON.stringify(VALID))
  assert.equal(file.epoch, 3)
  const anchor = trustAnchorApprovers(file)
  assert.deepEqual(anchor.dids, ["did:intyga:human-alice", selfCertifyingDid(SPKI_B64)])
  assert.deepEqual(anchor.resolveKey?.("did:intyga:human-alice"), [SPKI_B64])
  // A DID outside the file resolves to nothing — the anchor never widens.
  assert.equal(anchor.resolveKey?.("did:intyga:human-mallory"), null)
})

test("limitToDids narrows the anchor without widening it", () => {
  const file = parseTrustAnchorFile(JSON.stringify(VALID))
  const anchor = trustAnchorApprovers(file, ["did:intyga:human-alice", "did:intyga:not-in-file"])
  assert.deepEqual(anchor.dids, ["did:intyga:human-alice"])
})

test("refuses a stable DID with no keys — it could never verify", () => {
  const broken = { ...VALID, approvers: [{ did: "did:intyga:human-alice", publicKeys: [] }] }
  assert.throws(
    () => parseTrustAnchorFile(JSON.stringify(broken)),
    /has no publicKeys and is not self-certifying/,
  )
})

test("accepts a self-certifying DID with no keys — the DID itself commits to the key", () => {
  const file = parseTrustAnchorFile(
    JSON.stringify({ ...VALID, approvers: [{ did: selfCertifyingDid(SPKI_B64), publicKeys: [] }] }),
  )
  // The resolver hands back nothing; the verifier's self-certifying branch never consults it.
  assert.equal(trustAnchorApprovers(file).resolveKey?.(selfCertifyingDid(SPKI_B64)), null)
})

test("refuses the wrong artifact type, naming the offline bundle to prevent the mixup", () => {
  assert.throws(
    () => parseTrustAnchorFile(JSON.stringify({ ...VALID, type: "div-trust-bundle" })),
    /div-trust-bundle.*different, gateway-signed artifact/,
  )
})

test("refuses malformed inputs with a precise reason", () => {
  assert.throws(() => parseTrustAnchorFile("not json"), /not valid JSON/)
  assert.throws(() => parseTrustAnchorFile(JSON.stringify({ ...VALID, v: 2 })), /unsupported version/)
  assert.throws(() => parseTrustAnchorFile(JSON.stringify({ ...VALID, epoch: -1 })), /epoch/)
  assert.throws(() => parseTrustAnchorFile(JSON.stringify({ ...VALID, epoch: 1.5 })), /epoch/)
  assert.throws(() => parseTrustAnchorFile(JSON.stringify({ ...VALID, approvers: [] })), /non-empty/)
  assert.throws(
    () =>
      parseTrustAnchorFile(
        JSON.stringify({ ...VALID, approvers: [{ did: "not-a-did", publicKeys: [SPKI_B64] }] }),
      ),
    /must be a string starting with "did:"/,
  )
  assert.throws(
    () =>
      parseTrustAnchorFile(
        JSON.stringify({
          ...VALID,
          approvers: [{ did: "did:intyga:human-alice", publicKeys: ["not base64!!"] }],
        }),
      ),
    /base64/,
  )
  assert.throws(
    () =>
      parseTrustAnchorFile(
        JSON.stringify({
          ...VALID,
          approvers: [VALID.approvers[0], VALID.approvers[0]],
        }),
      ),
    /duplicate/,
  )
  assert.throws(
    () =>
      parseTrustAnchorFile(JSON.stringify({ ...VALID, webauthn: { origin: "console.example", rpId: "x" } })),
    /http\(s\) origin/,
  )
  assert.throws(
    () => parseTrustAnchorFile(JSON.stringify({ ...VALID, webauthn: { origin: "https://x", rpId: "" } })),
    /rpId/,
  )
})

// An anchor says what it is for, and the caller says what it is about to verify. They must agree:
// pinning an offline anchor where online approvals are verified would let a bare offline key — no
// origin binding, no user verification — satisfy that relying party.
test("purpose: absent reads as online, and a mismatch is refused either way", () => {
  assert.equal(parseTrustAnchorFile(JSON.stringify(VALID)).purpose, "online")
  const online = { ...VALID, purpose: "online" }
  assert.equal(parseTrustAnchorFile(JSON.stringify(online)).purpose, "online")
  assert.throws(() => parseTrustAnchorFile(JSON.stringify(online), { purpose: "offline" }), /online anchor/)

  const offline = {
    ...VALID,
    purpose: "offline",
    approvers: [{ did: "did:intyga:human-alice", publicKeys: [SPKI_B64] }],
  }
  assert.throws(() => parseTrustAnchorFile(JSON.stringify(offline)), /offline anchor/)
  const parsed = parseTrustAnchorFile(JSON.stringify(offline), { purpose: "offline" })
  assert.equal(parsed.purpose, "offline")
  assert.deepEqual(trustAnchorApprovers(parsed).resolveKey?.("did:intyga:human-alice"), [SPKI_B64])

  assert.throws(() => parseTrustAnchorFile(JSON.stringify({ ...VALID, purpose: "both" })), /purpose must be/)
})

test("an offline anchor pins a key for every approver — no self-certifying exception", () => {
  const offline = { ...VALID, purpose: "offline" }
  assert.throws(
    () => parseTrustAnchorFile(JSON.stringify(offline), { purpose: "offline" }),
    /offline anchor must pin/,
  )
})
