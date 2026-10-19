import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { test } from "node:test"
import {
  EVIDENCE_SOURCES_FILE_TYPE,
  evidencePolicyFromFile,
  parseEvidenceSourcesFile,
} from "./evidence-sources.ts"

// The shared trust-file contract every SDK's loader is held to (verifier-parity-vectors.json,
// executionEvidence.trustFiles). Python, Go, Rust and Java run the same cases.
test("shared trust-file vectors: every SDK loads and refuses the same files", () => {
  const vectors = JSON.parse(
    readFileSync(new URL("../vectors/verifier-parity-vectors.json", import.meta.url), "utf8"),
  ) as {
    executionEvidence: {
      trustFiles: Array<{ name: string; text: string; ok: boolean; policy?: Record<string, unknown[]> }>
    }
  }
  const cases = vectors.executionEvidence.trustFiles
  assert.ok(cases.length > 0)
  for (const c of cases) {
    if (!c.ok) {
      assert.throws(() => parseEvidenceSourcesFile(c.text), /invalid evidence-sources file/, c.name)
      continue
    }
    const policy = evidencePolicyFromFile(parseEvidenceSourcesFile(c.text))
    assert.deepEqual(Object.entries(policy.trustedSources), Object.entries(c.policy ?? {}), c.name)
  }
})

const KEY =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFapJVK9jXaesH8lZ1Xk3QylMJW/8oKuLLr+3DSXgWjHI4TwJye6MhBYcWxfgh3goR2H4ESC2+3j7dPB8IhUbIw=="
const valid = {
  type: EVIDENCE_SOURCES_FILE_TYPE,
  v: 1,
  sources: [{ did: "did:example:relay-7", publicKeys: [KEY] }],
}

test("a valid evidence-sources file becomes an evidence policy", () => {
  const file = parseEvidenceSourcesFile(JSON.stringify(valid))
  // A null-prototype map, so a source named "__proto__" cannot reach Object.prototype.
  const sources = evidencePolicyFromFile(file).trustedSources
  assert.equal(Object.getPrototypeOf(sources), null)
  assert.deepEqual(Object.entries(sources), [["did:example:relay-7", [KEY]]])
})

test("keys may carry validity intervals (DEWP §4.7.5), passed through to the policy as given", () => {
  const bounded = {
    ...valid,
    sources: [
      {
        did: "did:example:relay-7",
        publicKeys: [
          { key: KEY, notBefore: "2026-10-01T00:00:00.000Z", notAfter: "2026-10-05T18:00:00.000Z" },
          KEY,
        ],
      },
    ],
  }
  const policy = evidencePolicyFromFile(parseEvidenceSourcesFile(JSON.stringify(bounded)))
  assert.deepEqual(policy.trustedSources["did:example:relay-7"], bounded.sources[0]?.publicKeys)
  // Either bound alone is fine.
  for (const interval of [
    { notBefore: "2026-10-01T00:00:00.000Z" },
    { notAfter: "2026-10-05T18:00:00.000Z" },
  ])
    assert.doesNotThrow(() =>
      parseEvidenceSourcesFile(
        JSON.stringify({ ...valid, sources: [{ did: "d", publicKeys: [{ key: KEY, ...interval }] }] }),
      ),
    )
})

test("evidence-sources files fail loudly on the first problem", () => {
  const cases: Array<[unknown, RegExp]> = [
    ["{", /not valid JSON/],
    [[], /root must be an object/],
    [{ ...valid, type: "intyga-trust-anchor" }, /approver trust .* is a separate file/],
    [{ ...valid, v: 2 }, /unsupported version/],
    [{ ...valid, sources: [] }, /non-empty array/],
    [{ ...valid, sources: [null] }, /must be an object/],
    [{ ...valid, sources: [{ did: "", publicKeys: [KEY] }] }, /non-empty did/],
    [{ ...valid, sources: [valid.sources[0], valid.sources[0]] }, /duplicate source/],
    [{ ...valid, sources: [{ did: "d", publicKeys: [] }] }, /publicKeys must be a non-empty array/],
    [{ ...valid, sources: [{ did: "d", publicKeys: ["not base64!"] }] }, /base64 SPKI/],
    [{ ...valid, sources: [{ did: "d", publicKeys: [KEY], label: 1 }] }, /label must be a string/],
    [
      { ...valid, sources: [{ did: "d", publicKeys: [{ notAfter: "2026-10-05T18:00:00.000Z" }] }] },
      /carry a base64 SPKI key/,
    ],
    [
      { ...valid, sources: [{ did: "d", publicKeys: [{ key: KEY, notAfter: "2026-10-05" }] }] },
      /notAfter must be a/,
    ],
    [
      {
        ...valid,
        sources: [
          {
            did: "d",
            publicKeys: [
              { key: KEY, notBefore: "2026-10-05T18:00:00.000Z", notAfter: "2026-10-05T17:00:00.000Z" },
            ],
          },
        ],
      },
      /later than notAfter/,
    ],
    [{ ...valid, sources: [{ did: "d", publicKeys: [42] }] }, /base64 SPKI key or/],
    // A misspelt bound must never read as "no bound".
    [
      { ...valid, sources: [{ did: "d", publicKeys: [{ key: KEY, notafter: "2026-10-05T18:00:00.000Z" }] }] },
      /unexpected member "notafter"/,
    ],
    [{ ...valid, sources: [{ did: "d", publicKeys: [{ key: KEY, revokedAt: null }] }] }, /unexpected member/],
  ]
  for (const [input, reason] of cases)
    assert.throws(
      () => parseEvidenceSourcesFile(typeof input === "string" ? input : JSON.stringify(input)),
      reason,
      JSON.stringify(input),
    )
})
