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

test("audit-verify applies caller-owned RFC 3161 trust without counting one issuer twice", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-audit-tsa-test-"))
  try {
    const vectors = JSON.parse(
      fs.readFileSync(
        path.join(import.meta.dirname, "../vectors/rfc3161-vectors.json"),
        "utf8",
      ),
    ) as { cases: Array<{ name: string; anchor: Record<string, unknown>; trust: Record<string, unknown> }> }
    const fixture = vectors.cases.find((entry) => entry.name === "valid-unchecked")
    assert.ok(fixture)
    const issuer = String(fixture.anchor.issuer)
    const root = String(fixture.anchor.dailyRoot)
    const bundlePath = path.join(tmp, "bundle.json")
    const trustPath = path.join(tmp, "tsa.json")
    fs.writeFileSync(
      bundlePath,
      JSON.stringify({
        protocol: "DEWP",
        kind: "dewp.audit.evidence-bundle",
        version: "1.0",
        entries: [],
        // The checkpoint states the position and time its anchors bind: without them nothing can hold
        // the TSA's genTime to anything and the root never counts as anchored (DEWP §5.3).
        checkpoints: [
          {
            root,
            seqStart: fixture.anchor.seqStart,
            seqEnd: fixture.anchor.seqEnd,
            chainHash: fixture.anchor.chainHash,
            anchoredAt: fixture.anchor.timestamp,
            anchors: [fixture.anchor, fixture.anchor],
          },
        ],
      }),
    )
    fs.writeFileSync(trustPath, JSON.stringify({ [issuer]: fixture.trust }))

    const invoke = (extra: string[]) =>
      run([
        "audit-verify",
        bundlePath,
        "--root",
        root,
        "--trusted-issuer",
        issuer,
        "--tsa-trust",
        trustPath,
        "--json",
        ...extra,
      ])
    const valid = invoke(["--require-anchors", "1"])
    assert.equal(valid.status, 1) // empty evidence bundle is invalid, but its root quorum is evaluated
    const validReport = JSON.parse(valid.stdout) as { roots: Array<{ anchorVerified: boolean }> }
    assert.equal(validReport.roots[0]?.anchorVerified, true)

    const duplicate = invoke(["--require-anchors", "2"])
    const duplicateReport = JSON.parse(duplicate.stdout) as { roots: Array<{ anchorVerified: boolean }> }
    assert.equal(duplicateReport.roots[0]?.anchorVerified, false)

    fs.writeFileSync(
      trustPath,
      JSON.stringify({ [issuer]: { ...fixture.trust, signerCertificateSha256: "00".repeat(32) } }),
    )
    const tampered = invoke(["--require-anchors", "1"])
    const tamperedReport = JSON.parse(tampered.stdout) as { roots: Array<{ anchorVerified: boolean }> }
    assert.equal(tamperedReport.roots[0]?.anchorVerified, false)

    const missing = run(["audit-verify", bundlePath, "--root", root, "--trusted-issuer", issuer, "--json"])
    const missingReport = JSON.parse(missing.stdout) as { roots: Array<{ anchorVerified: boolean }> }
    assert.equal(missingReport.roots[0]?.anchorVerified, false)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test("audit-verify holds anchors to the roots file's own checkpoint records (DEWP §5.3)", () => {
  // --roots used to pass only each line's root into the verifier, discarding the chain-verified time
  // and chain hash: a bundle could then re-date its checkpoint (or strip it) and a late witness counted.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-audit-roots-records-test-"))
  try {
    type Case = { name: string; bundle: unknown; options: { trustedCheckpoints?: Record<string, unknown>[] } }
    const vectors = JSON.parse(
      fs.readFileSync(
        path.join(import.meta.dirname, "../vectors/verifier-parity-vectors.json"),
        "utf8",
      ),
    ) as {
      dewpEvidenceHardening: { keys: { id: string; spkiB64: string }[]; evidence: { cases: Case[] } }
    }
    const section = vectors.dewpEvidenceHardening
    const byName = (n: string) => {
      const c = section.evidence.cases.find((x) => x.name === n)
      assert.ok(c, n)
      return c
    }
    const record = byName("trusted-record-fills-stripped-checkpoint").options.trustedCheckpoints?.[0]
    assert.ok(record)
    const rootsPath = path.join(tmp, "roots.jsonl")
    fs.writeFileSync(rootsPath, `${JSON.stringify({ ...record, prevChainHash: "" })}\n`)
    const keyPath = path.join(tmp, "rekor.key")
    fs.writeFileSync(keyPath, section.keys.find((k) => k.id === "h-rekor")?.spkiB64 ?? "")
    const verify = (name: string) => {
      const bundlePath = path.join(tmp, `${name}.json`)
      fs.writeFileSync(bundlePath, JSON.stringify(byName(name).bundle))
      return run([
        "audit-verify",
        bundlePath,
        "--roots",
        rootsPath,
        "--trusted-issuer",
        "https://rekor.sigstore.dev",
        "--rekor-key",
        keyPath,
        "--json",
      ])
    }
    // The bundle strips its checkpoint's time and chain; the roots file supplies them.
    assert.equal(verify("trusted-record-fills-stripped-checkpoint").status, 0)
    // The bundle re-dates its checkpoint with a self-consistent chain; the roots file contradicts it.
    const redated = verify("redated-checkpoint-contradicts-trusted-record")
    assert.equal(redated.status, 1)
    assert.match(redated.stdout, /contradicts your trusted checkpoint record/)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test("audit-verify refuses malformed or unscoped --tsa-trust", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-audit-tsa-config-test-"))
  try {
    const bundlePath = path.join(tmp, "bundle.json")
    const trustPath = path.join(tmp, "tsa.json")
    fs.writeFileSync(bundlePath, JSON.stringify({ proof: {} }))
    fs.writeFileSync(trustPath, "{}")
    const empty = run(["audit-verify", bundlePath, "--trusted-issuer", "issuer", "--tsa-trust", trustPath])
    assert.equal(empty.status, 1)
    assert.match(empty.stderr, /non-empty JSON object/)
    const unscoped = run(["audit-verify", bundlePath, "--tsa-trust", trustPath])
    assert.equal(unscoped.status, 1)
    assert.match(unscoped.stderr, /requires --trusted-issuer/)
    const rekorPath = path.join(tmp, "rekor.pem")
    fs.writeFileSync(rekorPath, "public log key")
    const ambiguousRekor = run([
      "audit-verify",
      bundlePath,
      "--trusted-issuer",
      "rekor.example,tsa.example",
      "--rekor-key",
      rekorPath,
    ])
    assert.equal(ambiguousRekor.status, 1)
    assert.match(ambiguousRekor.stderr, /requires --rekor-issuer/)
    const unknownScope = run([
      "audit-verify",
      bundlePath,
      "--trusted-issuer",
      "rekor.example,tsa.example",
      "--rekor-key",
      rekorPath,
      "--rekor-issuer",
      "other.example",
    ])
    assert.equal(unknownScope.status, 1)
    assert.match(unknownScope.stderr, /must name a --trusted-issuer/)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
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

// ── Transport rules (transport.ts): https-only gateway, redirects never followed ───────────────────

test("commands that talk to the gateway refuse a non-https, non-loopback --gateway", () => {
  for (const args of [
    ["login", "--did", "did:example:1", "--gateway", "http://gw.example"],
    ["verify", "abc", "--gateway", "http://gw.example"],
    ["authorize", "x", "--target", "prod", "--token", "t", "--gateway", "http://gw.example"],
  ]) {
    const r = run(args)
    assert.notEqual(r.status, 0, args.join(" "))
    assert.match(r.stderr, /--gateway \/ INTYGA_GATEWAY_URL must use https:\/\//, args.join(" "))
  }
})

test("offline commands ignore an http INTYGA_GATEWAY_URL", () => {
  const r = spawnSync("node", [cli], {
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, INTYGA_GATEWAY_URL: "http://gw.example" },
  })
  assert.equal(r.status, 0)
})

test("login and trust-bundle export do not follow a 307 to another origin", async () => {
  const http = await import("node:http")
  const reached: string[] = []
  const elsewhere = http.createServer((req, res) => {
    reached.push(`${req.method} ${req.url} ${req.headers.authorization ?? ""}`)
    req.resume()
    res.setHeader("content-type", "application/json")
    res.end(JSON.stringify({ nonce: "n", pollSecret: "p", ok: true }))
  })
  await new Promise<void>((r) => elsewhere.listen(0, "127.0.0.1", r))
  const elsewherePort = (elsewhere.address() as { port: number }).port
  const origin = http.createServer((req, res) => {
    req.resume()
    res.statusCode = 307
    res.setHeader("location", `http://127.0.0.1:${elsewherePort}${req.url}`)
    res.end()
  })
  await new Promise<void>((r) => origin.listen(0, "127.0.0.1", r))
  const gateway = `http://127.0.0.1:${(origin.address() as { port: number }).port}`
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-cli-redirect-"))

  const runAsync = (args: string[], env: Record<string, string> = {}) =>
    new Promise<{ status: number | null; stderr: string }>((resolve, reject) => {
      const child = spawn("node", [cli, ...args], { env: { ...process.env, HOME: home, ...env } })
      let stderr = ""
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString()
      })
      child.on("error", reject)
      child.on("close", (status) => resolve({ status, stderr }))
    })

  try {
    const login = await runAsync(["login", "--did", "did:example:1", "--gateway", gateway])
    assert.notEqual(login.status, 0)
    assert.match(login.stderr, /never follow redirects/)

    const exported = await runAsync(
      ["trust-bundle", "export", "--tenant", "00000000-0000-0000-0000-000000000000", "--gateway", gateway],
      { INTYGA_INTERNAL_TOKEN: "internal-secret" },
    )
    assert.notEqual(exported.status, 0)
    assert.match(exported.stderr, /export failed \(307\).*never follow redirects/)

    assert.deepEqual(reached, [], "a request (and its credential) reached the redirect target")
  } finally {
    for (const s of [origin, elsewhere]) {
      s.closeAllConnections()
      s.close()
    }
    fs.rmSync(home, { recursive: true, force: true })
  }
})
