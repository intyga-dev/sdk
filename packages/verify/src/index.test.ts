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

// ─── WebAuthn / COSE ─────────────────────────────────────────────────────────

/** CBOR head byte(s) for a given major type and length/value (only the short forms COSE_Key needs). */
function cborHead(major: number, value: number): Buffer {
  if (value < 24) return Buffer.from([(major << 5) | value])
  if (value < 0x100) return Buffer.from([(major << 5) | 24, value])
  return Buffer.from([(major << 5) | 25, value >> 8, value & 0xff])
}
const cborUint = (n: number) => cborHead(0, n)
const cborNint = (n: number) => cborHead(1, -1 - n) // -1 → 0x20, -2 → 0x21, -3 → 0x22
const cborBytes = (b: Buffer) => Buffer.concat([cborHead(2, b.length), b])

/** Encode an EC2 COSE_Key. Overrides let a test bend one field at a time. */
function coseKey(
  x: Buffer,
  y: Buffer,
  over: { kty?: number; alg?: number; crv?: number; extra?: Buffer } = {},
): Buffer {
  const entries = [
    Buffer.concat([cborUint(1), cborUint(over.kty ?? 2)]), // kty: EC2
    Buffer.concat([cborUint(3), cborNint(over.alg ?? -7)]), // alg: ES256
    Buffer.concat([cborNint(-1), cborUint(over.crv ?? 1)]), // crv: P-256
  ]
  // `extra` goes BEFORE the coordinates on purpose: a decoy is only a real test of the parser if a
  // naive forward byte-scan would hit it first.
  if (over.extra) entries.push(over.extra)
  entries.push(Buffer.concat([cborNint(-2), cborBytes(x)]), Buffer.concat([cborNint(-3), cborBytes(y)]))
  return Buffer.concat([cborHead(5, entries.length), ...entries])
}

/** A genuinely-signed WebAuthn receipt, built the way an authenticator + the gateway would. */
function webauthnReceipt(
  input: { actionType: string; actionDescription: string; params: Record<string, unknown> },
  mutateCose?: (x: Buffer, y: Buffer) => Buffer,
): ApprovalReceipt {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string }
  const x = Buffer.from(jwk.x, "base64url")
  const y = Buffer.from(jwk.y, "base64url")

  const canonical = canonicalAuthorizationPayload({ nonce: "nonce-1", ...input })
  // The authenticator signs authenticatorData || SHA-256(clientDataJSON); the challenge is the payload.
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonical, "utf-8").toString("base64url"),
      origin: "https://wallet.example",
    }),
    "utf-8",
  )
  const authenticatorData = crypto.randomBytes(37)
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([authenticatorData, crypto.createHash("sha256").update(clientDataJSON).digest()]),
    { key: privateKey, dsaEncoding: "der" },
  )

  return {
    canonicalPayload: canonical,
    actionType: input.actionType,
    actionDescription: input.actionDescription,
    params: input.params,
    signerPublicKey: (mutateCose ? mutateCose(x, y) : coseKey(x, y)).toString("base64"),
    signature: signature.toString("base64"),
    sigAlg: "WEBAUTHN",
    authenticatorData: authenticatorData.toString("base64"),
    clientDataJSON: clientDataJSON.toString("base64"),
    verificationCode: verificationCode(canonical),
  }
}

const WEBAUTHN_INPUT = { actionDescription: "Wipe production database", ...EXPECTED }

test("verifies a genuine WebAuthn receipt end to end", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  assert.deepEqual(verifyApprovalReceipt(receipt, EXPECTED), { ok: true })
})

test("WebAuthn verification tolerates trailing bytes after the COSE key", () => {
  // Some wallets slice the COSE key out of attestedCredentialData without trimming what follows.
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) =>
    Buffer.concat([coseKey(x, y), crypto.randomBytes(16)]),
  )
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED).ok, true)
})

test("WebAuthn verification is not fooled by coordinate byte patterns inside another field", () => {
  // 0x21 0x58 0x20 is what the old scanning parser searched for. Planting it inside an unrelated
  // byte-string value must not be mistaken for the real x coordinate.
  const decoy = Buffer.concat([
    Buffer.from([0x18, 0x63]), // label 99
    cborBytes(Buffer.concat([Buffer.from([0x21, 0x58, 0x20]), crypto.randomBytes(32)])),
  ])
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { extra: decoy }))
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED).ok, true)
})

test("WebAuthn rejects a COSE key with a short coordinate rather than silently truncating", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x.subarray(0, 31), y))
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /must be 32 bytes/)
})

test("WebAuthn rejects a truncated COSE key", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => {
    const full = coseKey(x, y)
    return full.subarray(0, full.length - 10)
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /truncated/)
})

test("WebAuthn rejects a COSE key pinned to another curve or key type", () => {
  const wrongCrv = verifyApprovalReceipt(
    webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { crv: 2 })),
    EXPECTED,
  )
  assert.equal(wrongCrv.ok, false)
  assert.match(wrongCrv.reason!, /crv P-256/)

  const wrongKty = verifyApprovalReceipt(
    webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { kty: 1 })),
    EXPECTED,
  )
  assert.equal(wrongKty.ok, false)
  assert.match(wrongKty.reason!, /kty EC2/)
})

test("WebAuthn rejects a signature made by a different key", () => {
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = other.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, () =>
    coseKey(Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")),
  )
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("WebAuthn rejects a clientDataJSON challenge that is not the canonical payload", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  receipt.clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: "c29tZXRoaW5nLWVsc2U" }),
    "utf-8",
  ).toString("base64")
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /challenge does not match/)
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
