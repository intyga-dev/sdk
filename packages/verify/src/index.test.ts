import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  type ApprovalReceipt,
  canonicalAuthorizationPayload,
  verificationCode,
  verifyApprovalReceipt,
} from "./index.ts"

// Build a genuinely-signed ES256 receipt the way the gateway would.
function es256Receipt(input: {
  actionType: string
  actionDescription: string
  params: Record<string, unknown>
}): { receipt: ApprovalReceipt; pubB64: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  })
  const pubB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const canonical = canonicalAuthorizationPayload({
    nonce: "nonce-1",
    ...input,
  })
  const signature = crypto
    .sign("sha256", Buffer.from(canonical, "utf8"), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64")
  return {
    pubB64,
    receipt: {
      canonicalPayload: canonical,
      actionType: input.actionType,
      actionDescription: input.actionDescription,
      params: input.params,
      signerPublicKey: pubB64,
      signature,
      sigAlg: "ES256",
      verificationCode: verificationCode(canonical),
    },
  }
}

const EXPECTED = {
  actionType: "wipe_production",
  params: { target: "prod-db-1", region: "eu-north-1" },
}

test("verifies a genuine ES256 approval receipt", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...EXPECTED,
  })
  assert.deepEqual(verifyApprovalReceipt(receipt, EXPECTED), { ok: true })
})

test("rejects when params differ from what was approved", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...EXPECTED,
  })
  const r = verifyApprovalReceipt(receipt, {
    actionType: "wipe_production",
    params: { target: "prod-db-2", region: "eu-north-1" },
  })
  assert.equal(r.ok, false)
  assert.match(r.reason!, /do not match/)
})

test("rejects when actionType differs", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...EXPECTED,
  })
  const r = verifyApprovalReceipt(receipt, {
    actionType: "read_only_report",
    params: EXPECTED.params,
  })
  assert.equal(r.ok, false)
})

test("rejects a signature from a different key", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...EXPECTED,
  })
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  receipt.signerPublicKey = other.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("AUTO_APPROVED is REFUSED by default (no human signature to verify), accepted only on opt-in", () => {
  const canonical = canonicalAuthorizationPayload({
    nonce: "n",
    actionDescription: "deploy",
    ...EXPECTED,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: EXPECTED.params,
    sigAlg: "AUTO_APPROVED",
    verificationCode: verificationCode(canonical),
  }
  const denied = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(denied.ok, false)
  assert.equal(denied.autoApproved, true)

  const allowed = verifyApprovalReceipt(receipt, EXPECTED, {
    allowAutoApproved: true,
  })
  assert.deepEqual(allowed, { ok: true, autoApproved: true })
})

test("rejects a receipt missing signature material", () => {
  const canonical = canonicalAuthorizationPayload({
    nonce: "n",
    actionDescription: "deploy",
    ...EXPECTED,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: EXPECTED.params,
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED).ok, false)
})

test("WebAuthn receipt missing assertion components is rejected", () => {
  const canonical = canonicalAuthorizationPayload({
    nonce: "n",
    actionDescription: "deploy",
    ...EXPECTED,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: EXPECTED.params,
    signerPublicKey: "AAAA",
    signature: "BBBB",
    sigAlg: "WEBAUTHN",
    verificationCode: verificationCode(canonical),
  }
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /authenticatorData or clientDataJSON/)
})
