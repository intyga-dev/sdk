import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
// Exercises the BUILT module (run `pnpm build` first), matching cli.test.ts: the sources use
// NodeNext ".js" specifiers, which Node's type stripping does not remap back to ".ts".
import { blobHash, decryptPolicy, encryptPolicy, generateOrgKeypair } from "../dist/policy.js"

// Off-platform policy crypto: RSA-OAEP(SHA-256) wrapping an AES-256-GCM key. The security claim is
// that Intyga never sees plaintext, so what matters is that a blob only opens with the org's private
// key and that any modification to it fails closed rather than yielding altered policy.

// RSA-2048 keygen is the expensive part; generate one pair and reuse it across the suite.
const org = generateOrgKeypair()
const MANIFEST = JSON.stringify({
  version: 1,
  rules: [{ action: "payments.wire", effect: "require_approval", maxAmount: 5000 }],
})

test("round-trips a manifest", () => {
  const blob = encryptPolicy(org.publicKey, MANIFEST)
  assert.equal(decryptPolicy(org.privateKey, blob), MANIFEST)
})

test("blob has the documented v1.<wrappedKey>.<iv>.<ct> shape", () => {
  const parts = encryptPolicy(org.publicKey, MANIFEST).split(".")
  assert.equal(parts.length, 4)
  assert.equal(parts[0], "v1")
  // 12-byte GCM IV, and an RSA-2048 wrap is always 256 bytes.
  assert.equal(Buffer.from(parts[2]!, "base64").length, 12)
  assert.equal(Buffer.from(parts[1]!, "base64").length, 256)
})

test("encrypting the same plaintext twice yields different blobs", () => {
  // A fresh AES key + IV per call: identical policy must not produce a recognisable ciphertext,
  // otherwise Intyga could fingerprint which customers run the same manifest.
  const a = encryptPolicy(org.publicKey, MANIFEST)
  const b = encryptPolicy(org.publicKey, MANIFEST)
  assert.notEqual(a, b)
  assert.equal(decryptPolicy(org.privateKey, a), decryptPolicy(org.privateKey, b))
})

test("round-trips non-ASCII and empty plaintext", () => {
  for (const text of ["Intyga — pålitlig 🔐", ""]) {
    const blob = encryptPolicy(org.publicKey, text)
    assert.equal(decryptPolicy(org.privateKey, blob), text)
  }
})

test("a different org key cannot open the blob", () => {
  const other = generateOrgKeypair()
  const blob = encryptPolicy(org.publicKey, MANIFEST)
  assert.throws(() => decryptPolicy(other.privateKey, blob))
})

test("tampering with the ciphertext fails the GCM tag", () => {
  // The whole point of GCM over CBC: a flipped byte must fail loudly, never decrypt to altered
  // policy. An attacker who could silently weaken maxAmount would defeat the control entirely.
  const [v, wrapped, iv, ct] = encryptPolicy(org.publicKey, MANIFEST).split(".")
  const raw = Buffer.from(ct!, "base64")
  raw[0] = raw[0]! ^ 0x01
  const tampered = [v, wrapped, iv, raw.toString("base64")].join(".")
  assert.throws(() => decryptPolicy(org.privateKey, tampered))
})

test("truncating the GCM tag fails", () => {
  const [v, wrapped, iv, ct] = encryptPolicy(org.publicKey, MANIFEST).split(".")
  const raw = Buffer.from(ct!, "base64")
  const short = [v, wrapped, iv, raw.subarray(0, raw.length - 1).toString("base64")].join(".")
  assert.throws(() => decryptPolicy(org.privateKey, short))
})

test("substituting a foreign wrapped key fails", () => {
  // Swapping in an AES key the attacker knows, wrapped to the same org public key, must not let
  // them supply their own ciphertext: the GCM tag is computed under the original key.
  const blob = encryptPolicy(org.publicKey, MANIFEST)
  const [v, , iv, ct] = blob.split(".")
  const pub = crypto.createPublicKey({
    key: Buffer.from(org.publicKey, "base64"),
    format: "der",
    type: "spki",
  })
  const foreign = crypto.publicEncrypt(
    {
      key: pub,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    crypto.randomBytes(32),
  )
  const swapped = [v, foreign.toString("base64"), iv, ct].join(".")
  assert.throws(() => decryptPolicy(org.privateKey, swapped))
})

test("malformed blobs are rejected by shape before any crypto runs", () => {
  const blob = encryptPolicy(org.publicKey, MANIFEST)
  const [, wrapped, iv, ct] = blob.split(".")
  for (const bad of [
    "",
    "v1",
    "v1.only.three",
    `v2.${wrapped}.${iv}.${ct}`, // unknown version
    `v1..${iv}.${ct}`, // empty wrapped key
    `v1.${wrapped}..${ct}`, // empty iv
    `v1.${wrapped}.${iv}.`, // empty ciphertext
  ]) {
    assert.throws(() => decryptPolicy(org.privateKey, bad), /malformed policy blob/, `accepted: ${bad}`)
  }
})

test("blobHash is the stable sha256 hex of the blob string", () => {
  // The gateway and browser console index policies by this value, so it must be the hash of the
  // blob *string* — not of the decoded bytes — or cross-surface lookups silently miss.
  const blob = encryptPolicy(org.publicKey, MANIFEST)
  const h = blobHash(blob)
  assert.match(h, /^[0-9a-f]{64}$/)
  assert.equal(h, crypto.createHash("sha256").update(blob, "utf8").digest("hex"))
  assert.equal(h, blobHash(blob))
})
