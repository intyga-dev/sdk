import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

// The GitHub Action relies on the CLI's exit-code contract: 0 when it succeeds/prints help, non-zero
// when the request is malformed or approval fails. These spawn the BUILT binary (run `pnpm build` first).
const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url))

function run(args: string[]) {
  return spawnSync("node", [cli, ...args], { encoding: "utf8" })
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

test("keygen prints org keypair and exits 0", () => {
  const r = run(["keygen"])
  assert.equal(r.status, 0)
  assert.match(r.stdout, /publicKey/)
  assert.match(r.stdout, /privateKey/)
})

test("keygen --out writes key files and exits 0", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-keygen-test-"))
  const prefix = path.join(tmp, "org")
  try {
    const r = run(["keygen", "--out", prefix])
    assert.equal(r.status, 0)
    assert.ok(fs.existsSync(`${prefix}.public.key`))
    assert.ok(fs.existsSync(`${prefix}.private.key`))
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
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
