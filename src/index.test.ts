import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"

// Point HOME at an empty directory BEFORE importing the client: token() falls back to
// ~/.intyga/credentials.json, so a developer who has run `intyga login` would otherwise get a
// different result from CI. node --test gives each file its own process, so this is contained.
const home = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-sdk-test-"))
process.env.HOME = home
process.env.USERPROFILE = home

// The BUILT module (run `pnpm build` first), matching cli.test.ts — see policy.test.ts for why.
const { IntygaClient } = await import("../dist/index.js")
type GatewayRefused = import("./index.ts").GatewayRefused

interface Reply {
  status?: number
  body?: unknown
  text?: string
}

interface Call {
  url: string
  method: string
  headers: Record<string, string>
  body: unknown
}

/** Replace global fetch with a recorder. Returns the calls seen and a restore function. */
function stubFetch(handler: (call: Call) => Reply) {
  const calls: Call[] = []
  const original = globalThis.fetch
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    }
    calls.push(call)
    const reply = handler(call)
    const status = reply.status ?? 200
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => reply.body,
      text: async () => reply.text ?? JSON.stringify(reply.body ?? ""),
    } as Response
  }) as typeof fetch
  function restore() {
    globalThis.fetch = original
  }
  return { calls, restore }
}

const GW = "https://gw.example"

test("an explicit token is used verbatim and costs no network call", async (t) => {
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "tok-abc" })
  assert.equal(await c.token(), "tok-abc")
  assert.equal(f.calls.length, 0)
})

test("without a token or client credentials it refuses rather than calling anonymously", async (t) => {
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW })
  await assert.rejects(() => c.token(), /provide `token`/)
  assert.equal(f.calls.length, 0)
})

test("client credentials are exchanged as HTTP Basic and the result is cached", async (t) => {
  const f = stubFetch(() => ({ body: { access_token: "tok-exchanged" } }))
  t.after(f.restore)
  const c = new IntygaClient({
    gatewayUrl: GW,
    clientId: "id",
    clientSecret: "secret",
  })

  assert.equal(await c.token(), "tok-exchanged")
  assert.equal(f.calls.length, 1)
  assert.equal(f.calls[0]!.url, `${GW}/oauth/token`)
  assert.equal(f.calls[0]!.method, "POST")
  // The secret must travel in the Authorization header, never in a query string or body.
  const expected = Buffer.from("id:secret").toString("base64")
  assert.equal(f.calls[0]!.headers.authorization, `Basic ${expected}`)
  assert.equal(f.calls[0]!.body, undefined)

  // Second call must reuse the cached token rather than re-exchanging.
  assert.equal(await c.token(), "tok-exchanged")
  assert.equal(f.calls.length, 1)
})

test("a failed exchange throws and surfaces the status", async (t) => {
  const f = stubFetch(() => ({ status: 401, text: "bad credentials" }))
  t.after(f.restore)
  const c = new IntygaClient({
    gatewayUrl: GW,
    clientId: "id",
    clientSecret: "nope",
  })
  await assert.rejects(() => c.token(), /token exchange failed: 401 bad credentials/)
})

test("a stored credential from `intyga login` is picked up per gateway", async (t) => {
  fs.mkdirSync(path.join(home, ".intyga"), { recursive: true })
  fs.writeFileSync(
    path.join(home, ".intyga", "credentials.json"),
    JSON.stringify({
      [GW]: "tok-stored",
      "https://other.example": "tok-other",
    }),
  )
  t.after(() => fs.rmSync(path.join(home, ".intyga"), { recursive: true, force: true }))
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)

  assert.equal(await new IntygaClient({ gatewayUrl: GW, allowStoredCredentials: true }).token(), "tok-stored")
  // Without explicit allowStoredCredentials, stored tokens are ignored to prevent server-side identity borrowing.
  await assert.rejects(
    () => new IntygaClient({ gatewayUrl: GW }).token(),
    /provide `token`, or `clientId` \+ `clientSecret`/,
  )
  // A gateway with no stored entry must not silently borrow another gateway's token even when enabled.
  await assert.rejects(() =>
    new IntygaClient({ gatewayUrl: "https://third.example", allowStoredCredentials: true }).token(),
  )
  assert.equal(f.calls.length, 0)
})

test("authorize posts the action and defaults params to an empty object", async (t) => {
  const f = stubFetch(() => ({ body: { nonce: "n-1", status: "PENDING" } }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  const r = await c.authorize("Wire $500 to ACME", { target: "test-rp" })
  assert.deepEqual(r, { nonce: "n-1", status: "PENDING" })
  assert.equal(f.calls[0]!.url, `${GW}/authorize`)
  assert.equal(f.calls[0]!.headers.authorization, "Bearer t")
  assert.deepEqual(f.calls[0]!.body, {
    target: "test-rp",
    actionDescription: "Wire $500 to ACME",
    params: {},
  })
})

// `target` used to default to "global" here — and this was the only one of the four SDKs that did.
// sdk-go, sdk-rust and sdk-python all trim and hard-refuse a missing or blank target, each citing
// DIV §3 Invariant 5 (Target Isolation). A "global" target binds no execution environment into the
// signed intent, so the approval verifies at every other relying party in the tenant that also
// asserts "global" — an approval a human granted for staging is replayable against production. The
// gateway has its own `?? "global"` fallback; the sibling ports exist so nobody relies on it, and
// this SDK was sending the value explicitly instead. Two assertions above previously pinned
// `target: "global"` as expected output, which is how it survived.
test("authorize refuses a missing or blank target rather than defaulting it", async (t) => {
  const f = stubFetch(() => ({ body: { nonce: "n", status: "PENDING" } }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  for (const opts of [undefined, {}, { target: "" }, { target: "   " }]) {
    await assert.rejects(
      // biome-ignore lint/suspicious/noExplicitAny: exercising the untyped-caller path on purpose
      () => c.authorize("Wire $1M", opts as any),
      /target is required/,
      `authorize accepted ${JSON.stringify(opts)}`,
    )
  }
  assert.equal(f.calls.length, 0, "nothing should reach the gateway without a target")
})

test("authorize binds actionType and params into the request", async (t) => {
  const f = stubFetch(() => ({ body: { nonce: "n-2", status: "PENDING" } }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  await c.authorize("Wire", {
    target: "test-rp",
    actionType: "payments.wire",
    params: { amount: 500 },
    timeout: 60,
  })
  assert.deepEqual(f.calls[0]!.body, {
    target: "test-rp",
    actionDescription: "Wire",
    actionType: "payments.wire",
    params: { amount: 500 },
    timeout: 60,
  })
})

test("authorize exposes issuer-completed v1 context for the RP to retain", async (t) => {
  const agentContext = {
    action: { reversibility: "reversible", amount: null },
    agent: { label: "did:intyga:agent:test", configDigest: `sha256:${"1".repeat(64)}`, delegatedBy: null },
    session: { id: `sha256:${"2".repeat(64)}`, seq: "1", prev: null, aggregate: null },
    nbf: "2026-09-20T10:00:00.000Z",
  }
  const f = stubFetch(() => ({ body: { nonce: "n-v1", status: "PENDING", agentContext } }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })
  const opened = await c.authorize("Review", {
    target: "test-rp",
    agentContext: {
      action: { reversibility: "reversible", amount: null },
      configDigest: agentContext.agent.configDigest,
      delegatedBy: null,
      session: agentContext.session,
    },
  })
  assert.deepEqual(opened.agentContext, agentContext)
})

test("authorize throws on a non-2xx rather than returning a falsy nonce", async (t) => {
  const f = stubFetch(() => ({ status: 403, text: "forbidden" }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })
  await assert.rejects(() => c.authorize("x", { target: "test-rp" }), /authorize failed: 403 forbidden/)
})

test("status url-encodes the nonce", async (t) => {
  // A nonce is server-generated, but encoding it defends the path from ever being split by a
  // slash — a lookup that silently hit a different route would be worse than a 404.
  const f = stubFetch(() => ({ body: { status: "APPROVED" } }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  await c.status("a/b c")
  assert.equal(f.calls[0]!.url, `${GW}/authorize/a%2Fb%20c`)
})

test("status throws on a non-2xx", async (t) => {
  const f = stubFetch(() => ({ status: 500 }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })
  await assert.rejects(() => c.status("n"), /status failed: 500/)
})

test("consume re-binds the exact action at execution time", async (t) => {
  const f = stubFetch(() => ({ body: { ok: true } }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  const r = await c.consume("n-1", {
    actionType: "payments.wire",
    params: { amount: 500 },
  })
  assert.deepEqual(r, { ok: true })
  assert.equal(f.calls[0]!.url, `${GW}/authorize/verify`)
  assert.deepEqual(f.calls[0]!.body, {
    nonce: "n-1",
    actionType: "payments.wire",
    params: { amount: 500 },
  })
})

test("consume returns the gateway's refusal instead of throwing", async (t) => {
  // A tampered/replayed consume answers 409 with a reason; callers branch on `ok`, so the body
  // must reach them rather than becoming an exception.
  const f = stubFetch(() => ({
    status: 409,
    body: { ok: false, reason: "already consumed" },
  }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })
  assert.deepEqual(await c.consume("n", { actionType: "a" }), {
    ok: false,
    reason: "already consumed",
  })
})

test("requireApproval polls until the challenge resolves", async (t) => {
  let polls = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/authorize")) return { body: { nonce: "n-9", status: "PENDING" } }
    polls += 1
    return polls < 3
      ? { body: { status: "PENDING" } }
      : { body: { status: "APPROVED", signatureHash: "deadbeef" } }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  const r = await c.requireApproval("Wire", { target: "test-rp", intervalMs: 1, timeoutMs: 5000 })
  assert.equal(r.status, "APPROVED")
  assert.equal(r.signatureHash, "deadbeef")
  assert.equal(polls, 3)
})

test("requireApproval surfaces a denial without waiting for the deadline", async (t) => {
  const f = stubFetch((call) =>
    call.url.endsWith("/authorize")
      ? { body: { nonce: "n-10", status: "PENDING" } }
      : { body: { status: "DENIED" } },
  )
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  // Fails closed and fails fast: a denied action must never look like a timeout.
  const r = await c.requireApproval("Wire", { target: "test-rp", intervalMs: 1, timeoutMs: 60_000 })
  assert.equal(r.status, "DENIED")
})

test("requireApproval gives up as EXPIRED and converts timeoutMs to whole seconds", async (t) => {
  const f = stubFetch((call) =>
    call.url.endsWith("/authorize")
      ? { body: { nonce: "n-11", status: "PENDING" } }
      : { body: { status: "PENDING" } },
  )
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  const r = await c.requireApproval("Wire", { target: "test-rp", intervalMs: 1, timeoutMs: 1500 })
  assert.equal(r.status, "EXPIRED")
  // The backend TTL is sent in seconds, rounded up, so the gateway never expires before the client.
  assert.equal(f.calls[0]!.body ? (f.calls[0]!.body as { timeout: number }).timeout : undefined, 2)
})

// Regression: the local deadline used to ignore opts.timeout and hardcode 120s, so it agreed with the
// backend TTL only by accident. The test timeout is what catches the old behaviour — with `timeout: 1`
// the pre-fix client ignored the 1s window and kept polling for the full two minutes.
test("requireApproval derives its deadline from opts.timeout", { timeout: 20_000 }, async (t) => {
  const f = stubFetch((call) =>
    call.url.endsWith("/authorize")
      ? { body: { nonce: "n-12", status: "PENDING" } }
      : { body: { status: "PENDING" } },
  )
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  const started = Date.now()
  const r = await c.requireApproval("Wire", { target: "test-rp", intervalMs: 10, timeout: 1 })
  assert.equal(r.status, "EXPIRED")
  // Client deadline and backend TTL now come from one value, so neither can outlive the other.
  assert.equal((f.calls[0]!.body as { timeout: number }).timeout, 1)
  assert.ok(Date.now() - started < 5_000, "should give up on its own 1s deadline, not the 120s default")
})

test("requireApproval rides out a transient polling failure", async (t) => {
  let polls = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/authorize")) return { body: { nonce: "n-13", status: "PENDING" } }
    polls += 1
    if (polls === 1) return { status: 502, text: "bad gateway" }
    if (polls === 2) return { body: { status: "PENDING" } }
    return { body: { status: "APPROVED" } }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  // A momentary 502 must not throw away a wait the human may already have acted on.
  const r = await c.requireApproval("Wire", { target: "test-rp", intervalMs: 1, timeoutMs: 5_000 })
  assert.equal(r.status, "APPROVED")
})

test("requireApproval gives up when the gateway is persistently unreachable", async (t) => {
  const f = stubFetch((call) =>
    call.url.endsWith("/authorize") ? { body: { nonce: "n-14", status: "PENDING" } } : { status: 503 },
  )
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

  // Tolerating blips is not the same as hanging forever: sustained failure must surface, not
  // masquerade as EXPIRED, so the caller can tell "no answer" from "the human said no".
  await assert.rejects(
    c.requireApproval("Wire", { target: "test-rp", intervalMs: 1, timeoutMs: 60_000 }),
    /5 consecutive errors/,
  )
})

test("verify url-encodes the document hash and needs no token", async (t) => {
  const f = stubFetch(() => ({
    body: { verified: true, status: "SIGNED", documentHash: "ab/cd" },
  }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW })

  const r = await c.verify("ab/cd")
  assert.equal(r.verified, true)
  assert.equal(f.calls[0]!.url, `${GW}/verify/ab%2Fcd`)
  // Public witness lookup: no Authorization header is required or sent.
  assert.equal(f.calls[0]!.headers.authorization, undefined)
})

// ─── A refusal is not an outage (DIV §5a.1, §3.4) ────────────────────────────
//
// offline.ts states the mechanism's first structural property as "IT ONLY APPLIES WHEN WE COULD NOT
// ASK". That held only for a 200 body carrying DENIED/EXPIRED. authorize() and status() threw a bare
// Error on every non-2xx, so a reachable gateway answering 403 SecurityViolation — or 402 Protected
// Ops exhausted, or 401 on a revoked credential — was indistinguishable from a socket failure, and
// the client went off and collected local signatures instead.

for (const status of [401, 402, 403, 429]) {
  test(`requireApproval does NOT fall back offline when the gateway refuses with ${status}`, async (t) => {
    const f = stubFetch(() => ({ status }))
    t.after(f.restore)
    const c = new IntygaClient({ gatewayUrl: GW, token: "t" })

    let offlineWasAttempted = false
    await assert.rejects(
      c.requireApproval("Wire $1M", {
        target: "prod",
        timeoutMs: 5_000,
        intervalMs: 1,
        offline: {
          get bundleDir() {
            offlineWasAttempted = true
            return "/nonexistent"
          },
        } as never,
      }),
      (err: Error) => {
        assert.equal(err.name, "GatewayRefused", `expected a refusal, got ${err.name}: ${err.message}`)
        assert.equal((err as GatewayRefused).status, status)
        return true
      },
    )
    assert.equal(offlineWasAttempted, false, `a ${status} refusal was answered with an offline approval`)
  })
}

test("a 5xx still counts as unreachable, because that is what §5a is for", async (t) => {
  // The distinction is deliberate: a 502 from a load balancer or a 503 from a restarting instance is
  // infrastructure failing, not the gateway deciding. Only 4xx is a verdict.
  const f = stubFetch((call) =>
    call.url.endsWith("/authorize") ? { body: { nonce: "n-5xx", status: "PENDING" } } : { status: 503 },
  )
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, token: "t" })
  await assert.rejects(
    c.requireApproval("Wire", { target: "test-rp", intervalMs: 1, timeoutMs: 60_000 }),
    /5 consecutive errors/,
  )
})

// ─── Token refresh ───────────────────────────────────────────────────────────
//
// The exchanged token used to be cached for the life of the process with `expires_in` never read,
// so a service object older than the token's TTL got a 401 on every call until restart — and the
// gateway could not shorten its TTLs without making that bite sooner. Now the cache honours
// `expires_in` (re-exchanging `min(60s, expires_in/10)` early) and a 401 on an exchanged token is
// retried exactly once with a fresh exchange. Explicit tokens are the caller's to refresh; a stored
// `intyga login` credential has no secret behind it and can only be re-minted by logging in again.

const BASE_NOW = 1_700_000_000_000

function exchangeStub(expiresIn?: number) {
  let exchanges = 0
  const f = stubFetch(() => ({
    body:
      expiresIn === undefined
        ? { access_token: `tok-${++exchanges}` }
        : { access_token: `tok-${++exchanges}`, expires_in: expiresIn },
  }))
  return { ...f, exchanges: () => exchanges }
}

function paths(calls: Call[]): string[] {
  return calls.map((c) => new URL(c.url).pathname)
}

/** A JWT-shaped string whose payload carries `exp` (seconds). Unsigned: the SDK reads it as a hint only. */
function jwtWithExp(exp: number): string {
  const payload = Buffer.from(JSON.stringify({ sub: "did:intyga:cli", exp })).toString("base64url")
  return `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`
}

test("an exchanged token is re-exchanged shortly before the expires_in the gateway reported", async (t) => {
  const f = exchangeStub(100)
  t.after(f.restore)
  let now = BASE_NOW
  t.mock.method(Date, "now", () => now)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  assert.equal(await c.token(), "tok-1")
  // margin = min(60s, 100s / 10) = 10s, so the cache is good until t+90s and not a moment longer.
  now = BASE_NOW + 89_000
  assert.equal(await c.token(), "tok-1")
  assert.equal(f.exchanges(), 1)
  now = BASE_NOW + 91_000
  assert.equal(await c.token(), "tok-2")
  assert.equal(f.exchanges(), 2)
  assert.deepEqual(paths(f.calls), ["/oauth/token", "/oauth/token"])
})

test("the refresh margin is capped at 60s for long-lived tokens", async (t) => {
  const f = exchangeStub(3600)
  t.after(f.restore)
  let now = BASE_NOW
  t.mock.method(Date, "now", () => now)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  assert.equal(await c.token(), "tok-1")
  now = BASE_NOW + 3_539_000
  assert.equal(await c.token(), "tok-1", "a tenth of an hour is 360s, but the margin stops at 60s")
  now = BASE_NOW + 3_541_000
  assert.equal(await c.token(), "tok-2")
  assert.equal(f.exchanges(), 2)
})

test("a token response without expires_in is cached for the life of the process (back-compat)", async (t) => {
  const f = exchangeStub()
  t.after(f.restore)
  let now = BASE_NOW
  t.mock.method(Date, "now", () => now)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  assert.equal(await c.token(), "tok-1")
  now = BASE_NOW + 10 * 24 * 3_600_000
  assert.equal(await c.token(), "tok-1", "with no expiry known the old gateway contract still holds")
  assert.equal(f.exchanges(), 1)
})

test("a 401 on an exchanged token drops the cache and retries the call exactly once", async (t) => {
  let exchanges = 0
  let authorizes = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/oauth/token"))
      return { body: { access_token: `tok-${++exchanges}`, expires_in: 900 } }
    authorizes += 1
    return authorizes === 1
      ? { status: 401, text: "ERR_JWT_EXPIRED" }
      : { body: { nonce: "n-r", status: "PENDING" } }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  const r = await c.authorize("Wire", { target: "test-rp" })
  assert.equal(r.nonce, "n-r")
  assert.deepEqual(paths(f.calls), ["/oauth/token", "/authorize", "/oauth/token", "/authorize"])
  assert.equal(f.calls[1]!.headers.authorization, "Bearer tok-1")
  assert.equal(f.calls[3]!.headers.authorization, "Bearer tok-2", "the retry must carry the NEW token")
  // The request itself is replayed unchanged.
  assert.deepEqual(f.calls[3]!.body, f.calls[1]!.body)
})

test("the 401 retry re-exchanges with client credentials, never with a stored `intyga login` token", async (t) => {
  // SECURITY REGRESSION: the retry used to go back through resolveToken(), which re-reads
  // ~/.intyga/credentials.json BEFORE the client-credentials branch. A process holding client
  // credentials on a box where someone ran `intyga login` mid-session (dev box, CI runner) would
  // retry an AGENT call as the HUMAN: a different principal, a different ceremony shape, and a
  // different requester on the witness leaf. The retry must be a client-credentials exchange, full stop.
  const credsDir = path.join(home, ".intyga")
  t.after(() => fs.rmSync(credsDir, { recursive: true, force: true }))
  let exchanges = 0
  let authorizes = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/oauth/token"))
      return { body: { access_token: `tok-agent-${++exchanges}`, expires_in: 900 } }
    authorizes += 1
    if (authorizes === 1) {
      // A concurrent `intyga login` lands exactly between the first exchange and its 401.
      fs.mkdirSync(credsDir, { recursive: true })
      fs.writeFileSync(path.join(credsDir, "credentials.json"), JSON.stringify({ [GW]: "tok-human" }))
      return { status: 401, text: "ERR_JWT_EXPIRED" }
    }
    return { body: { nonce: "n-r", status: "PENDING" } }
  })
  t.after(f.restore)
  const c = new IntygaClient({
    gatewayUrl: GW,
    clientId: "id",
    clientSecret: "secret",
    allowStoredCredentials: true,
  })

  const r = await c.authorize("Wire", { target: "test-rp" })
  assert.equal(r.nonce, "n-r")
  assert.deepEqual(paths(f.calls), ["/oauth/token", "/authorize", "/oauth/token", "/authorize"])
  assert.equal(f.calls[1]!.headers.authorization, "Bearer tok-agent-1")
  assert.equal(
    f.calls[3]!.headers.authorization,
    "Bearer tok-agent-2",
    "retry must be the re-exchanged agent token",
  )
  assert.equal(exchanges, 2)
  assert.ok(
    !f.calls.some((x) => x.headers.authorization === "Bearer tok-human"),
    "the stored human token must never be sent",
  )
})

test("a 401 that survives the one retry is surfaced as GatewayRefused, not retried again", async (t) => {
  const f = stubFetch((call) =>
    call.url.endsWith("/oauth/token")
      ? { body: { access_token: "tok", expires_in: 900 } }
      : { status: 401, text: "revoked" },
  )
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  await assert.rejects(
    () => c.status("n"),
    (err: Error) => {
      assert.equal(err.name, "GatewayRefused")
      assert.equal((err as GatewayRefused).status, 401)
      return true
    },
  )
  // One retry, then stop: a revoked key must not turn into an exchange loop.
  assert.deepEqual(paths(f.calls), ["/oauth/token", "/authorize/n", "/oauth/token", "/authorize/n"])
})

test("consume retries a 401 once and still never throws", async (t) => {
  let verifies = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/oauth/token"))
      return { body: { access_token: `tok-${verifies + 1}`, expires_in: 900 } }
    verifies += 1
    return verifies === 1
      ? { status: 401, body: { error: { code: "UNAUTHORIZED", message: "expired" } } }
      : { body: { ok: true } }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  assert.deepEqual(await c.consume("n-1", { target: "test-rp", actionType: "a" }), { ok: true })
  assert.deepEqual(paths(f.calls), ["/oauth/token", "/authorize/verify", "/oauth/token", "/authorize/verify"])
})

test("an explicit token is never re-exchanged on a 401", async (t) => {
  const f = stubFetch(() => ({ status: 401, text: "expired" }))
  t.after(f.restore)
  // Client credentials are present too, and must still not be used: the caller chose the token.
  const c = new IntygaClient({ gatewayUrl: GW, token: "t-explicit", clientId: "id", clientSecret: "secret" })

  await assert.rejects(
    () => c.authorize("Wire", { target: "test-rp" }),
    (err: Error) => {
      assert.equal(err.name, "GatewayRefused")
      assert.equal((err as GatewayRefused).status, 401)
      return true
    },
  )
  assert.deepEqual(paths(f.calls), ["/authorize"], "no exchange may be attempted for an explicit token")
})

test("a stored credential is served until its exp, then refused with the one remedy there is", async (t) => {
  let now = BASE_NOW
  t.mock.method(Date, "now", () => now)
  fs.mkdirSync(path.join(home, ".intyga"), { recursive: true })
  fs.writeFileSync(
    path.join(home, ".intyga", "credentials.json"),
    JSON.stringify({ [GW]: jwtWithExp(Math.floor(BASE_NOW / 1000) + 600) }),
  )
  t.after(() => fs.rmSync(path.join(home, ".intyga"), { recursive: true, force: true }))
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, allowStoredCredentials: true })

  assert.equal(await c.token(), jwtWithExp(Math.floor(BASE_NOW / 1000) + 600))
  now = BASE_NOW + 599_000
  assert.equal(await c.token(), jwtWithExp(Math.floor(BASE_NOW / 1000) + 600))
  now = BASE_NOW + 601_000
  // No client secret exists for a CLI login, so there is nothing to exchange: say so, and say what to do.
  await assert.rejects(
    () => c.token(),
    (err: Error) => {
      assert.equal(err.name, "StoredCredentialExpired")
      assert.equal((err as GatewayRefused).status, 401, "handled exactly like the 401 it stands for")
      assert.match(err.message, /run `intyga login` again/)
      return true
    },
  )
  assert.equal(f.calls.length, 0, "an expired stored credential must not be sent, nor anything exchanged")
})

test("a stored credential expiring mid-wait is a refusal, never an outage to answer offline", async (t) => {
  // The pre-emptive expiry is raised client-side, without the gateway being asked. It must still be
  // classified as the 401 it stands in for: a bare Error here would count as "could not ask" and
  // send a requireApproval wait into the DIV §5a offline path over a credential that merely aged out.
  let now = BASE_NOW
  t.mock.method(Date, "now", () => now)
  fs.mkdirSync(path.join(home, ".intyga"), { recursive: true })
  fs.writeFileSync(
    path.join(home, ".intyga", "credentials.json"),
    JSON.stringify({ [GW]: jwtWithExp(Math.floor(BASE_NOW / 1000) + 600) }),
  )
  t.after(() => fs.rmSync(path.join(home, ".intyga"), { recursive: true, force: true }))
  const f = stubFetch((call) => {
    if (call.url.endsWith("/authorize")) return { body: { nonce: "n-mid", status: "PENDING" } }
    // Every poll is PENDING; the clock, not the gateway, ends this wait.
    now += 200_000
    return { body: { status: "PENDING" } }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, allowStoredCredentials: true })

  let offlineWasAttempted = false
  await assert.rejects(
    c.requireApproval("Wire", {
      target: "test-rp",
      timeoutMs: 10_000_000,
      intervalMs: 1,
      offline: {
        get bundleDir() {
          offlineWasAttempted = true
          return "/nonexistent"
        },
      } as never,
    }),
    (err: Error) => {
      assert.equal(err.name, "StoredCredentialExpired", `got ${err.name}: ${err.message}`)
      assert.match(err.message, /run `intyga login` again/)
      return true
    },
  )
  assert.equal(offlineWasAttempted, false)
  // The token was sent for the three polls inside its exp hint (t+0, t+200s, t+400s) and not once after.
  assert.equal(f.calls.filter((call) => call.url.endsWith("/authorize/n-mid")).length, 3)
})

test("a 401 on a stored credential is not retried and tells the user to log in again", async (t) => {
  fs.mkdirSync(path.join(home, ".intyga"), { recursive: true })
  fs.writeFileSync(
    path.join(home, ".intyga", "credentials.json"),
    JSON.stringify({ [GW]: "tok-stored-opaque" }),
  )
  t.after(() => fs.rmSync(path.join(home, ".intyga"), { recursive: true, force: true }))
  const f = stubFetch(() => ({ status: 401, text: "ERR_JWT_EXPIRED" }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, allowStoredCredentials: true })

  await assert.rejects(
    () => c.authorize("Wire", { target: "test-rp" }),
    (err: Error) => {
      assert.equal(err.name, "StoredCredentialExpired")
      assert.equal((err as GatewayRefused).status, 401)
      assert.match(err.message, /run `intyga login` again/)
      return true
    },
  )
  // An opaque (non-JWT) stored value carries no expiry hint and is simply offered once.
  assert.deepEqual(paths(f.calls), ["/authorize"])
})

test("a key revoked between exchange and retry is a refusal on the retry path too, not an outage", async (t) => {
  // The 401-retry re-exchanges mid-call, so a revoked key now fails at the token endpoint from inside
  // authorize(). That failure is a verdict from a reachable gateway and must be typed as one, or the
  // offline fallback would answer a revocation with locally collected signatures.
  let exchanges = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/oauth/token"))
      return ++exchanges === 1
        ? { body: { access_token: "tok-1", expires_in: 900 } }
        : { status: 401, text: "revoked" }
    return { status: 401, text: "ERR_JWT_EXPIRED" }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  let offlineWasAttempted = false
  await assert.rejects(
    c.requireApproval("Wire", {
      target: "test-rp",
      timeoutMs: 5_000,
      intervalMs: 1,
      offline: {
        get bundleDir() {
          offlineWasAttempted = true
          return "/nonexistent"
        },
      } as never,
    }),
    (err: Error) => {
      assert.equal(err.name, "GatewayRefused", `got ${err.name}: ${err.message}`)
      assert.equal((err as GatewayRefused).status, 401)
      assert.match(err.message, /token exchange failed: 401 revoked/)
      return true
    },
  )
  assert.equal(offlineWasAttempted, false)
  assert.deepEqual(paths(f.calls), ["/oauth/token", "/authorize", "/oauth/token"])
})

test("an expired stored credential does not block client credentials supplied alongside it", async (t) => {
  fs.mkdirSync(path.join(home, ".intyga"), { recursive: true })
  fs.writeFileSync(
    path.join(home, ".intyga", "credentials.json"),
    JSON.stringify({ [GW]: jwtWithExp(Math.floor(Date.now() / 1000) - 60) }),
  )
  t.after(() => fs.rmSync(path.join(home, ".intyga"), { recursive: true, force: true }))
  const f = exchangeStub(900)
  t.after(f.restore)
  const c = new IntygaClient({
    gatewayUrl: GW,
    allowStoredCredentials: true,
    clientId: "id",
    clientSecret: "secret",
  })

  assert.equal(await c.token(), "tok-1")
  assert.deepEqual(paths(f.calls), ["/oauth/token"])
})

test("reconcileOfflineApprovals retries a 401 once per report, clears only acknowledged records, and keeps the rest", async (t) => {
  // The buffer is the only evidence an offline approval happened until the gateway acknowledges it,
  // so a record is dropped on a 2xx and on nothing else — a refusal stays queued, with its reason.
  const bufferDir = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-sdk-pending-"))
  t.after(() => fs.rmSync(bufferDir, { recursive: true, force: true }))
  const pending = (nonce: string) => ({
    nonce,
    target: "test-rp",
    actionType: "deploy",
    display: "Deploy",
    usedAt: "2026-08-23T10:00:00.000Z",
    receipt: { stub: nonce },
  })
  fs.writeFileSync(path.join(bufferDir, "n-ack.json"), JSON.stringify(pending("n-ack")))
  fs.writeFileSync(path.join(bufferDir, "n-refused.json"), JSON.stringify(pending("n-refused")))

  let exchanges = 0
  let reports = 0
  const f = stubFetch((call) => {
    if (call.url.endsWith("/oauth/token"))
      return { body: { access_token: `tok-${++exchanges}`, expires_in: 900 } }
    reports += 1
    const { nonce } = call.body as { nonce: string }
    // The very first report meets an expired token; the retry carries a fresh one and is acknowledged.
    if (reports === 1) return { status: 401, text: "ERR_JWT_EXPIRED" }
    return nonce === "n-ack" ? { body: { ok: true } } : { status: 409, text: "already reconciled" }
  })
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW, clientId: "id", clientSecret: "secret" })

  const r = await c.reconcileOfflineApprovals({ bundleDir: "/unused", bufferDir })
  assert.equal(r.reported, 1)
  assert.equal(r.failed, 1)
  assert.deepEqual(r.reasons, ["n-refused: 409 already reconciled"])
  assert.equal(exchanges, 2, "one up-front exchange plus exactly one re-exchange for the 401")
  // The receipt travels with the report so the gateway can re-verify rather than take our word for it.
  const first = f.calls.find((call) => call.url.endsWith("/offline-approval/reconcile"))!
  assert.deepEqual((first.body as { receipt: unknown }).receipt, {
    stub: (first.body as { nonce: string }).nonce,
  })
  assert.deepEqual(
    fs.readdirSync(bufferDir).sort(),
    ["n-refused.json"],
    "only the acknowledged record is cleared",
  )
})

test("reconcileOfflineApprovals with a misconfigured client throws up front rather than failing every record", async (t) => {
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)
  const c = new IntygaClient({ gatewayUrl: GW })
  await assert.rejects(() => c.reconcileOfflineApprovals({ bundleDir: "/unused" }), /provide `token`/)
  assert.equal(f.calls.length, 0)
})
