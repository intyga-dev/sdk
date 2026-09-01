// IntygaPlatformClient: the private_key_jwt exchange (hand-rolled ES256 JWS — verified here with
// real crypto, not string-matched), the canonicalize-and-hash helper, and the request surface.
// Network is a recorded fetch stub, matching index.test.ts; the module under test is the BUILT dist.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { stableStringify } from "@intyga/verify"
import type { PlatformReceipt, PlatformReceiptExpectation } from "@intyga/verify"

// The BUILT module (run `pnpm build` first), matching index.test.ts — see policy.test.ts for why.
const { hashPayload, IntygaPlatformClient } = await import("../dist/platform.js")

interface Call {
  url: string
  method: string
  headers: Record<string, string>
  body: unknown
}

/** Replace global fetch with a recorder that replies from a queue. */
function mockFetch(replies: Array<{ status?: number; body?: unknown }>) {
  const calls: Call[] = []
  const original = globalThis.fetch
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const reply = replies.shift() ?? { status: 500, body: { error: "queue empty" } }
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]),
      ),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    })
    return new Response(JSON.stringify(reply.body ?? {}), {
      status: reply.status ?? 200,
      headers: { "content-type": "application/json" },
    })
  }) as typeof fetch
  return { calls, restore: () => (globalThis.fetch = original) }
}

const KEYS = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const GATEWAY = "https://gw.example"

function client() {
  return new IntygaPlatformClient({
    gatewayUrl: GATEWAY,
    clientId: "sk_platform_1",
    privateKey: KEYS.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  })
}

test("hashPayload is SHA-256 over the RFC 8785 canonicalization", () => {
  const payload = { b: 2, a: { z: [1, 2], y: "x" } }
  const expected = crypto.createHash("sha256").update(stableStringify(payload), "utf8").digest("hex")
  assert.equal(hashPayload(payload), expected)
  // Key order must not matter — the canonicalization is the contract.
  assert.equal(hashPayload({ a: { y: "x", z: [1, 2] }, b: 2 }), expected)
})

test("the client assertion is a genuine ES256 JWS with the RFC 7523 claims", async (t) => {
  const now = 1_787_000_000_000
  t.mock.method(Date, "now", () => now)
  const { calls, restore } = mockFetch([{ body: { access_token: "tok", expires_in: 900 } }])
  try {
    await client().token()
  } finally {
    restore()
  }
  const body = calls[0]?.body as { client_assertion_type: string; client_assertion: string }
  assert.equal(calls[0]?.url, `${GATEWAY}/oauth/token`)
  assert.equal(body.client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

  const [h, p, s] = body.client_assertion.split(".")
  assert.ok(h && p && s)
  assert.equal((JSON.parse(Buffer.from(h, "base64url").toString()) as { alg: string }).alg, "ES256")
  const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as {
    iss: string
    sub: string
    aud: string
    iat: number
    jti: string
  }
  assert.equal(claims.iss, "sk_platform_1")
  assert.equal(claims.sub, "sk_platform_1")
  assert.equal(claims.aud, `${GATEWAY}/oauth/token`)
  assert.equal(claims.iat, Math.floor(now / 1000))
  assert.ok(claims.jti)
  // The signature verifies under the registered public key — raw r||s per JWS ES256.
  const verified = crypto.verify(
    "sha256",
    Buffer.from(`${h}.${p}`, "utf8"),
    { key: KEYS.publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(s, "base64url"),
  )
  assert.equal(verified, true)
})

test("the token is cached until shortly before expires_in, then re-exchanged", async (t) => {
  let now = 1_787_000_000_000
  t.mock.method(Date, "now", () => now)
  const { calls, restore } = mockFetch([
    { body: { access_token: "tok-1", expires_in: 900 } },
    { body: { subject: { externalId: "u1", did: "d" } } },
    { body: { access_token: "tok-2", expires_in: 900 } },
    { body: { subject: { externalId: "u2", did: "d" } } },
  ])
  try {
    const c = client()
    await c.createSubject("u1")
    assert.equal(calls[1]?.headers.authorization, "Bearer tok-1")
    now += 900_000 // past expiry — the next call must re-exchange first
    await c.createSubject("u2")
    assert.equal(calls[2]?.url, `${GATEWAY}/oauth/token`)
    assert.equal(calls[3]?.headers.authorization, "Bearer tok-2")
  } finally {
    restore()
  }
})

test("requestSignature hashes an inline payload and refuses neither form", async () => {
  const { calls, restore } = mockFetch([
    { body: { access_token: "tok", expires_in: 900 } },
    { body: { nonce: "n-1", expiresAt: "e", options: {} } },
  ])
  try {
    const res = await client().requestSignature({
      externalId: "u1",
      origin: "https://app.example",
      payload: { amount: 500 },
    })
    assert.equal(res.nonce, "n-1")
  } finally {
    restore()
  }
  const body = calls[1]?.body as { payloadHash: string; externalId: string; origin: string }
  assert.equal(body.externalId, "u1")
  assert.equal(body.origin, "https://app.example")
  assert.equal(body.payloadHash, hashPayload({ amount: 500 }))
})

test("the platform client covers the complete subject, enrollment, signing, and proof surface", async (t) => {
  const f = mockFetch([
    { body: { access_token: "tok", expires_in: 900 } },
    { body: { subject: { externalId: "customer/one", did: "did:intyga:key:subject", credentials: [] } } },
    { body: { options: { challenge: "register-me" } } },
    {
      body: {
        subject: { externalId: "customer/one", did: "did:intyga:key:subject" },
        credential: { credentialId: "cred/one", publicKey: "cose" },
      },
    },
    { body: { revokedAt: "2026-08-31T12:00:00.000Z" } },
    { body: { receipt: { canonicalPayload: "{}" }, ledger: { receiptSeq: "42", receiptTenantSeq: "7" } } },
    { body: { status: "APPROVED", receipt: { canonicalPayload: "{}" } } },
    { body: { ok: true } },
    { body: { root: "abc", siblings: [] } },
  ])
  t.after(f.restore)

  const c = client()
  assert.equal((await c.getSubject("customer/one")).externalId, "customer/one")
  assert.deepEqual(await c.beginEnrollment("customer/one", "https://app.example", "app.example"), {
    challenge: "register-me",
  })
  assert.equal(
    (await c.completeEnrollment("customer/one", { id: "registration-response" })).credential.credentialId,
    "cred/one",
  )
  assert.equal((await c.revokeCredential("cred/one", "lost device")).revokedAt, "2026-08-31T12:00:00.000Z")
  assert.equal((await c.completeSignature("nonce/one", { id: "assertion-response" })).ledger.receiptSeq, "42")
  assert.equal((await c.getSignature("nonce/one")).status, "APPROVED")
  assert.equal((await c.rejectSignature("nonce/one")).ok, true)
  assert.equal((await c.getReceiptProof("nonce/one")).root, "abc")

  assert.deepEqual(
    f.calls.slice(1).map(({ url, method }) => ({ url, method })),
    [
      { url: `${GATEWAY}/platform/subjects/customer%2Fone`, method: "GET" },
      { url: `${GATEWAY}/platform/credentials/register/options`, method: "POST" },
      { url: `${GATEWAY}/platform/credentials/register/verify`, method: "POST" },
      { url: `${GATEWAY}/platform/credentials/cred%2Fone/revoke`, method: "POST" },
      { url: `${GATEWAY}/platform/sign/challenges/nonce%2Fone/complete`, method: "POST" },
      { url: `${GATEWAY}/platform/sign/challenges/nonce%2Fone`, method: "GET" },
      { url: `${GATEWAY}/platform/sign/challenges/nonce%2Fone/reject`, method: "POST" },
      { url: `${GATEWAY}/platform/receipts/nonce%2Fone/proof`, method: "GET" },
    ],
  )
  assert.deepEqual(f.calls[2]?.body, {
    externalId: "customer/one",
    origin: "https://app.example",
    rpId: "app.example",
  })
  assert.deepEqual(f.calls[4]?.body, { reason: "lost device" })
})

test("verifyReceipt delegates to the offline platform verifier", () => {
  const receipt = { canonicalPayload: "{}" } as PlatformReceipt
  const expected = {} as PlatformReceiptExpectation
  const verdict = client().verifyReceipt(receipt, expected)
  assert.equal(verdict.ok, false)
  assert.match(verdict.reason ?? "", /unsupported DIV payload version/)
})

test("a refusal surfaces as GatewayRefused with the status, and 401 retries exactly once", async () => {
  const { calls, restore } = mockFetch([
    { body: { access_token: "tok-1", expires_in: 900 } },
    { status: 401, body: { error: "expired" } },
    { body: { access_token: "tok-2", expires_in: 900 } },
    { status: 409, body: { error: "a subject with this externalId already exists" } },
  ])
  try {
    await assert.rejects(
      () => client().createSubject("u1"),
      (err: Error & { status?: number }) => {
        assert.equal(err.status, 409)
        assert.match(err.message, /createSubject failed: 409/)
        return true
      },
    )
  } finally {
    restore()
  }
  // exchange, 401'd call, re-exchange, retried call — and nothing after the terminal 409.
  assert.equal(calls.length, 4)
})
