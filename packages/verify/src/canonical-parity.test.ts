// The canonical payload exists in TWO packages — @sakra-trust/verify (zero-dependency, shipped to
// relying parties) and @sakra-trust/mcp-schemas (used by the gateway and the browser signing
// ceremony). They must produce byte-identical strings or signatures silently stop verifying.
//
// This is the guard for that. It is deliberately in `verify`, which depends on nothing, and imports
// mcp-schemas only as a devDependency for the comparison.

import assert from "node:assert/strict"
import { describe, it } from "node:test"
import {
  canonicalAuthorizationPayload as schemasV2,
  canonicalAuthorizationPayloadV3 as schemasV3,
} from "@sakra-trust/mcp-schemas"
import {
  canonicalAuthorizationPayload as verifyV2,
  canonicalAuthorizationPayloadV3 as verifyV3,
} from "./index.js"

const CASES: { name: string; input: Parameters<typeof verifyV2>[0] }[] = [
  {
    name: "simple",
    input: {
      nonce: "n-1",
      actionType: "payments.wire",
      actionDescription: "Wire $500",
      params: { amount: 500 },
    },
  },
  {
    name: "unsorted keys (stableStringify must sort them the same way on both sides)",
    input: {
      nonce: "n-2",
      actionType: "a.b",
      actionDescription: "x",
      params: { zeta: 1, alpha: 2, mid: { z: 1, a: 2 } },
    },
  },
  {
    name: "characters that JSON must escape",
    input: {
      nonce: 'n"3\\',
      actionType: "a\nb",
      actionDescription: 'He said "delete prod" — now',
      params: { "key\"with'quotes": "tab\there", unicode: "åäö→" },
    },
  },
  {
    name: "nested arrays, nulls and empty containers",
    input: {
      nonce: "n-4",
      actionType: "t",
      actionDescription: "d",
      params: { list: [1, "two", null, { k: [] }], empty: {}, nil: null },
    },
  },
]

describe("canonical payload parity across packages", () => {
  for (const c of CASES) {
    it(`v2 — ${c.name}`, () => {
      assert.equal(verifyV2(c.input), schemasV2(c.input))
    })
  }

  for (const c of CASES) {
    for (const attestation of [
      null,
      {
        method: "oidc",
        issuer: "https://token.actions.githubusercontent.com",
        subject: "repo:acme/billing:ref:refs/heads/main",
      },
    ]) {
      const label = attestation ? "attested" : "unattested"
      it(`v3 ${label} — ${c.name}`, () => {
        const input = { ...c.input, requester: { did: "did:sakra:agent-001", attestation } }
        assert.equal(verifyV3(input), schemasV3(input))
      })
    }
  }

  it("v2 and v3 are distinguishable — a v3 payload never collides with a v2 one", () => {
    const base = CASES[0]!.input
    const v2 = verifyV2(base)
    const v3 = verifyV3({ ...base, requester: { did: "did:sakra:agent-001", attestation: null } })
    assert.notEqual(v2, v3)
    assert.match(v2, /^\{"v":2,/)
    assert.match(v3, /^\{"v":3,/)
  })

  it("the requester is actually covered — changing only the DID changes the bytes", () => {
    const base = CASES[0]!.input
    const a = verifyV3({ ...base, requester: { did: "did:sakra:agent-001", attestation: null } })
    const b = verifyV3({ ...base, requester: { did: "did:sakra:agent-002", attestation: null } })
    assert.notEqual(a, b)
  })

  it("attestation is covered — same DID, different issuer, different bytes", () => {
    const base = CASES[0]!.input
    const mk = (issuer: string) =>
      verifyV3({
        ...base,
        requester: { did: "did:sakra:agent-001", attestation: { method: "oidc", issuer, subject: "s" } },
      })
    assert.notEqual(mk("https://good.example"), mk("https://evil.example"))
  })

  it("v3 payload with expiresAt is byte-identical across packages", () => {
    const input = {
      nonce: "c_8f91a2",
      actionType: "deleteDatabase",
      actionDescription: "Delete staging database",
      params: { environment: "staging" },
      requester: { did: "did:sakra:service:deploy-pipeline", attestation: null },
      expiresAt: "2026-07-23T19:30:00Z",
    }
    const fromSchemas = schemasV3(input)
    const fromVerify = verifyV3(input)
    assert.equal(fromSchemas, fromVerify)
    assert.match(fromSchemas, /,"expiresAt":"2026-07-23T19:30:00Z"\}$/)
  })
})
