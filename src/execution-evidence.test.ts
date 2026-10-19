import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { executionPayloadSha256, parseExecutionEvidenceStatement } from "@intyga/verify"
import { buildExecutionEvidence, signExecutionEvidence } from "./execution-evidence.ts"

const approvalPayload = '{"nonce":"n-1","type":"div-intent-verification","v":1}'

test("a source builds a canonical statement bound to the approved bytes and signs it ES256", () => {
  const statement = buildExecutionEvidence({
    approvalPayload,
    nonce: "n-1",
    source: "did:example:relay-7",
    verdict: "confirmed",
    observation: { breaker: "open", currentA: 0 },
    observedAt: "2026-10-05T14:02:11.000Z",
    sampledAt: "2026-10-05T14:02:09.500Z",
    sequence: 418,
  })
  const parsed = parseExecutionEvidenceStatement(statement)
  assert.ok(parsed.ok)
  assert.equal(parsed.statement.approval.payloadSha256, executionPayloadSha256(approvalPayload))
  assert.equal(parsed.statement.sampledAt, "2026-10-05T14:02:09.500Z")
  assert.equal(parsed.statement.sequence, 418)
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const signature = signExecutionEvidence(statement, pair.privateKey)
  assert.equal(Buffer.from(signature, "base64").length, 64)
  assert.ok(
    crypto.verify(
      "sha256",
      Buffer.from(statement),
      { key: pair.publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature, "base64"),
    ),
  )
  // PEM works too; a non-P-256 key is refused rather than producing a signature nobody verifies.
  const pem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString()
  assert.equal(Buffer.from(signExecutionEvidence(statement, pem), "base64").length, 64)
  const ed = crypto.generateKeyPairSync("ed25519").privateKey
  assert.throws(() => signExecutionEvidence(statement, ed), /P-256/)
})

test("observedAt defaults to now, sampledAt to observedAt, and invalid input is refused at build time", () => {
  const statement = buildExecutionEvidence({
    approvalPayload,
    nonce: "n-1",
    source: "s",
    verdict: "contradicted",
    observation: {},
    sequence: 1,
  })
  const parsed = parseExecutionEvidenceStatement(statement)
  assert.ok(parsed.ok)
  assert.equal(parsed.statement.sampledAt, parsed.statement.observedAt)
  const refused = [
    { observation: { x: 1e16 } },
    { sequence: 0 },
    { sequence: 2.5 },
    { sampledAt: "2099-01-01T00:00:00.000Z" }, // later than observedAt
  ]
  for (const over of refused)
    assert.throws(
      () =>
        buildExecutionEvidence({
          approvalPayload,
          nonce: "n-1",
          source: "s",
          verdict: "confirmed",
          observation: {},
          sequence: 1,
          ...over,
        }),
      JSON.stringify(over),
    )
})
