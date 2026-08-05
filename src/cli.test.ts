import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

// The GitHub Action relies on the CLI's exit-code contract: 0 when it succeeds/prints help, non-zero
// when the request is malformed or approval fails. These spawn the BUILT binary (run `pnpm build` first).
const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url))

function run(args: string[]) {
  return spawnSync("node", [cli, ...args], { encoding: "utf8", timeout: 60_000 })
}

function runAuditVerifyWithRoots(roots: string) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-audit-verify-test-"))
  const bundlePath = path.join(tmp, "bundle.json")
  const rootsPath = path.join(tmp, "roots.jsonl")
  try {
    fs.writeFileSync(bundlePath, JSON.stringify({ proof: { seq: "1", anchorRef: null } }))
    fs.writeFileSync(rootsPath, roots)
    return run(["audit-verify", bundlePath, "--roots", rootsPath])
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

test("no command prints help and exits 0", () => {
  const r = run([])
  assert.equal(r.status, 0)
  assert.match(r.stdout, /Intyga CLI/)
})

test("unknown command prints help and exits 1", () => {
  const r = run(["unknown-command"])
  assert.equal(r.status, 1)
  assert.match(r.stdout, /Intyga CLI/)
})

test("keygen refuses to print an organization private key", () => {
  const r = run(["keygen"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /--out <private-key-prefix>/)
})

test("keygen --out writes key files and exits 0", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-keygen-test-"))
  const prefix = path.join(tmp, "org")
  try {
    const r = run(["keygen", "--out", prefix])
    assert.equal(r.status, 0)
    assert.ok(fs.existsSync(`${prefix}.public.key`))
    assert.ok(fs.existsSync(`${prefix}.private.key`))
    assert.equal(fs.statSync(tmp).mode & 0o777, 0o700)
    assert.equal(fs.statSync(`${prefix}.private.key`).mode & 0o777, 0o600)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test("trust-bundle export refuses an internal token passed on the command line", () => {
  const r = run([
    "trust-bundle",
    "export",
    "--tenant",
    "00000000-0000-0000-0000-000000000000",
    "--token",
    "secret",
  ])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /--token is not accepted/)
})

test("policy-encrypt without args exits non-zero", () => {
  const r = run(["policy-encrypt"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga policy-encrypt/)
})

test("login without --did exits non-zero", () => {
  const r = run(["login"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga login/)
})

test("verify without hash exits non-zero", () => {
  const r = run(["verify"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga verify/)
})

test("audit-verify without bundle exits non-zero", () => {
  const r = run(["audit-verify"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga audit-verify/)
})

test("audit-verify reports malformed roots seqStart without a stack trace", () => {
  const r = runAuditVerifyWithRoots(JSON.stringify({ seqStart: "abc", seqEnd: "2", root: "0".repeat(64) }))
  assert.equal(r.status, 1)
  assert.match(r.stderr, /error: .*seqStart/)
  assert.doesNotMatch(r.stderr, /\n {4}at /)
})

test("audit-verify reports a non-object roots line without a stack trace", () => {
  const r = runAuditVerifyWithRoots("null\n")
  assert.equal(r.status, 1)
  assert.match(r.stderr, /error: roots file line 1 is not an object/)
  assert.doesNotMatch(r.stderr, /\n {4}at /)
})

test("audit-verify preserves contextual invalid JSON errors", () => {
  const r = runAuditVerifyWithRoots("{not-json}\n")
  assert.equal(r.status, 1)
  assert.match(r.stderr, /error: roots file line 1 is not valid JSON/)
  assert.doesNotMatch(r.stderr, /\n {4}at /)
})

test("authorize without an action description exits non-zero", () => {
  const r = run(["authorize"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga authorize/)
})

test("authorize with invalid --params JSON exits non-zero", () => {
  const r = run([
    "authorize",
    "do a thing",
    "--params",
    "{not-json}",
    "--token",
    "t",
    "--gateway",
    "http://127.0.0.1:9",
  ])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /Invalid JSON in --params/)
})

// Non-object params used to pass the unchecked cast: `params ?? {}` then signs `{}` while the later
// verify call rebinds against the raw value, so what was signed and what is checked diverge.
for (const bad of ["null", "[1,2]", "42", '"hello"']) {
  test(`authorize with non-object --params (${bad}) exits non-zero`, () => {
    const r = run([
      "authorize",
      "do a thing",
      "--params",
      bad,
      "--token",
      "t",
      "--gateway",
      "http://127.0.0.1:9",
    ])
    assert.notEqual(r.status, 0)
    assert.match(r.stderr, /--params must be a JSON object/)
  })
}

test("await without a nonce exits non-zero", () => {
  const r = run(["await"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga await/)
})

test("notify without --url exits non-zero", () => {
  const r = run(["notify", "--context", "x"])
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /usage: intyga notify/)
})

for (const badTimeout of ["abc", "-10", "0"]) {
  test(`authorize with invalid --timeout (${badTimeout}) exits non-zero`, () => {
    const r = run([
      "authorize",
      "do a thing",
      "--timeout",
      badTimeout,
      "--token",
      "t",
      "--gateway",
      "http://127.0.0.1:9",
    ])
    assert.notEqual(r.status, 0)
    assert.match(r.stderr, /Invalid --timeout value/)
  })

  test(`await with invalid --timeout (${badTimeout}) exits non-zero`, () => {
    const r = run([
      "await",
      "nonce-123",
      "--timeout",
      badTimeout,
      "--token",
      "t",
      "--gateway",
      "http://127.0.0.1:9",
    ])
    assert.notEqual(r.status, 0)
    assert.match(r.stderr, /Invalid --timeout value/)
  })
}

// ─── AUTO_APPROVED must not be accepted implicitly ───────────────────────────
//
// `sigAlg: "AUTO_APPROVED"` means policy let the action through with NO human signature. It is a
// plain receipt field, not part of the signed bytes, and @intyga/verify deliberately returns
// `{ ok: false, autoApproved: true }` for it so that `if (!ok) die` blocks unsigned approvals.
//
// The CLI used to read `if (!v.ok && !v.autoApproved) die(...)` and then proceed on the autoApproved
// branch — inverting that refusal at every call site, with no flag to turn it off. Anything that
// could answer the status poll could authorize any action, and no approver key was ever consulted:
// a $1,000,000 wire with zero signatures against a signed 3-of-3 hardware-key requirement exited 0.

test("authorize refuses an AUTO_APPROVED receipt by default, and accepts it only on opt-in", async () => {
  const { canonicalIntentPayload, verificationCode } = (await import(
    "../dist/index.js"
  )) as typeof import("./index.ts")

  const NONCE = "11111111-1111-1111-1111-111111111111"
  const TARGET = "prod-payments"
  const ACTION_TYPE = "wire_transfer"
  const PARAMS = { amount: 1_000_000 }
  const DISPLAY = "Wire $1,000,000 to Attacker"
  const requester = { did: "did:intyga:agent:test", attestation: null }

  const canonicalPayload = canonicalIntentPayload({
    target: TARGET,
    actionType: ACTION_TYPE,
    display: DISPLAY,
    params: PARAMS,
    requester,
    // The strictest requirement the product can express — and none of it was enforced.
    requirement: {
      requiredApprovals: 3,
      requireHardwareKey: true,
      allowedAaguids: [],
      requesterCannotApprove: true,
      signerClass: "human",
    },
    nonce: NONCE,
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  })

  const receipt = {
    canonicalPayload,
    target: TARGET,
    actionDescription: DISPLAY,
    params: PARAMS,
    requester,
    sigAlg: "AUTO_APPROVED",
    verificationCode: verificationCode(canonicalPayload),
    signatures: [], // no human signed anything
  }

  const http = await import("node:http")
  const server = http.createServer((req, res) => {
    res.setHeader("content-type", "application/json")
    req.resume()
    if (req.url === "/authorize" && req.method === "POST") {
      res.end(JSON.stringify({ nonce: NONCE, status: "PENDING" }))
      return
    }
    if (req.url === "/authorize/verify") {
      res.end(JSON.stringify({ ok: true }))
      return
    }
    res.end(JSON.stringify({ status: "APPROVED", receipt }))
  })
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r))
  const { port } = server.address() as { port: number }

  const baseArgs = [
    "authorize",
    DISPLAY,
    "--gateway",
    `http://127.0.0.1:${port}`,
    "--target",
    TARGET,
    "--type",
    ACTION_TYPE,
    "--params",
    JSON.stringify(PARAMS),
    "--approver-key",
    "AAAA", // never consulted on this path — that is the point
    "--token",
    "t",
    "--no-open",
  ]

  // Async spawn, not the spawnSync `run` helper above: spawnSync blocks this process's event loop,
  // so the stub gateway living in it could never answer and the CLI would hang until killed.
  const runAsync = (args: string[]) =>
    new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn("node", [cli, ...args], { encoding: "utf8" })
      let stdout = ""
      let stderr = ""
      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString()
      })
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString()
      })
      child.on("error", reject)
      child.on("close", (status) => resolve({ status, stdout, stderr }))
    })

  try {
    const refused = await runAsync(baseArgs)
    assert.notEqual(refused.status, 0, "an unsigned AUTO_APPROVED receipt was accepted")
    assert.match(refused.stderr, /NO human signature/)
    assert.doesNotMatch(refused.stdout, /CONSUMED/)

    const optedIn = await runAsync([...baseArgs, "--allow-auto-approved"])
    assert.equal(optedIn.status, 0, optedIn.stderr)
    assert.match(optedIn.stdout, /without a human signature/)
  } finally {
    server.closeAllConnections()
    server.close()
  }
})
