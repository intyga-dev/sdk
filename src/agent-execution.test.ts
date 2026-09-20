import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  agentConfigDigest,
  canonicalIntentPayload,
  type AgentIntentContext,
  type ApprovalReceipt,
} from "@intyga/verify"
import { verifyAgentForExecution } from "./agent-execution.ts"

test("execution PEP recomputes the monetary aggregate and rejects drift", () => {
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const liveConfig = {
    model: { provider: "test", version: "model-v1" },
    tools: [{ id: "pay", version: "1", schemaDigest: `sha256:${"1".repeat(64)}` }],
    systemPrompt: "Pay only approved invoices",
  }
  const prev = `sha256:${"2".repeat(64)}`
  const agentContext: AgentIntentContext = {
    action: { reversibility: "irreversible", amount: { amount: "10.25", currency: "SEK" } },
    agent: { label: "did:intyga:agent:pay", configDigest: agentConfigDigest(liveConfig), delegatedBy: null },
    session: {
      id: `sha256:${"3".repeat(64)}`,
      seq: "2",
      prev,
      aggregate: { amount: "13.25", currency: "SEK" },
    },
    nbf: "2026-09-20T12:00:00.000Z",
  }
  const canonicalPayload = canonicalIntentPayload({
    target: "payments-prod",
    actionType: "payments.send",
    display: "Pay invoice",
    params: { invoice: "test" },
    requester: { did: "did:intyga:agent:pay", attestation: null },
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: true,
      signerClass: "human",
    },
    nonce: "invoice-test-nonce",
    expiresAt: "2026-09-20T12:05:00.000Z",
    agentContext,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload,
    actionDescription: "Pay invoice",
    params: { invoice: "test" },
    requester: { did: "did:intyga:agent:pay", attestation: null },
    signerDid: "did:intyga:owner",
    signerPublicKey: publicKey,
    signature: crypto
      .sign("sha256", Buffer.from(canonicalPayload), {
        key: keys.privateKey,
        dsaEncoding: "ieee-p1363",
      })
      .toString("base64"),
    sigAlg: "ES256",
    verificationCode: "unused",
  }
  const expected = {
    target: "payments-prod",
    actionType: "payments.send",
    params: { invoice: "test" },
    nonce: "invoice-test-nonce",
    requesterDid: "did:intyga:agent:pay",
    approvers: { dids: ["did:intyga:owner"], resolveKey: () => publicKey },
    agentContext,
  }
  const opts = { asOf: new Date("2026-09-20T12:02:00.000Z") }
  const state = { head: prev, seq: "1", aggregate: { amount: "3.00", currency: "SEK" } }
  const accepted = verifyAgentForExecution(receipt, expected, liveConfig, state, opts)
  assert.equal(accepted.ok, true, accepted.reason)
  assert.match(accepted.nextHead ?? "", /^sha256:[0-9a-f]{64}$/)
  assert.match(
    verifyAgentForExecution(
      receipt,
      expected,
      liveConfig,
      { ...state, aggregate: { amount: "2.00", currency: "SEK" } },
      opts,
    ).reason ?? "",
    /aggregate/,
  )
  assert.match(
    verifyAgentForExecution(receipt, expected, liveConfig, { ...state, seq: "0" }, opts).reason ?? "",
    /sequence/,
  )
  assert.match(
    verifyAgentForExecution(receipt, expected, { ...liveConfig, systemPrompt: "Changed" }, state, opts)
      .reason ?? "",
    /drifted/,
  )
  for (const amount of ["1.2.3", "1.1234567890", "-3", "01", "9999999999999999999999999999999"]) {
    const malformed = verifyAgentForExecution(
      receipt,
      expected,
      liveConfig,
      { ...state, aggregate: { amount, currency: "SEK" } },
      opts,
    )
    assert.equal(malformed.ok, false, amount)
    assert.match(malformed.reason ?? "", /invalid agent session amount/)
  }
})
