import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"

// Point HOME at an empty directory BEFORE importing the client: token() falls back to
// ~/.sakra/credentials.json, so a developer who has run `sakra login` would otherwise get a
// different result from CI. node --test gives each file its own process, so this is contained.
const home = fs.mkdtempSync(path.join(os.tmpdir(), "sakra-sdk-test-"))
process.env.HOME = home
process.env.USERPROFILE = home

// The BUILT module (run `pnpm build` first), matching cli.test.ts — see policy.test.ts for why.
const { SakraClient } = await import("../dist/index.js")

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
  const c = new SakraClient({ gatewayUrl: GW, token: "tok-abc" })
  assert.equal(await c.token(), "tok-abc")
  assert.equal(f.calls.length, 0)
})

test("without a token or client credentials it refuses rather than calling anonymously", async (t) => {
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW })
  await assert.rejects(() => c.token(), /provide `token`/)
  assert.equal(f.calls.length, 0)
})

test("client credentials are exchanged as HTTP Basic and the result is cached", async (t) => {
  const f = stubFetch(() => ({ body: { access_token: "tok-exchanged" } }))
  t.after(f.restore)
  const c = new SakraClient({
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
  const c = new SakraClient({
    gatewayUrl: GW,
    clientId: "id",
    clientSecret: "nope",
  })
  await assert.rejects(() => c.token(), /token exchange failed: 401 bad credentials/)
})

test("a stored credential from `sakra login` is picked up per gateway", async (t) => {
  fs.mkdirSync(path.join(home, ".sakra"), { recursive: true })
  fs.writeFileSync(
    path.join(home, ".sakra", "credentials.json"),
    JSON.stringify({
      [GW]: "tok-stored",
      "https://other.example": "tok-other",
    }),
  )
  t.after(() => fs.rmSync(path.join(home, ".sakra"), { recursive: true, force: true }))
  const f = stubFetch(() => ({ body: {} }))
  t.after(f.restore)

  assert.equal(await new SakraClient({ gatewayUrl: GW }).token(), "tok-stored")
  // A gateway with no stored entry must not silently borrow another gateway's token.
  await assert.rejects(() => new SakraClient({ gatewayUrl: "https://third.example" }).token())
  assert.equal(f.calls.length, 0)
})

test("authorize posts the action and defaults params to an empty object", async (t) => {
  const f = stubFetch(() => ({ body: { nonce: "n-1", status: "PENDING" } }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

  const r = await c.authorize("Wire $500 to ACME")
  assert.deepEqual(r, { nonce: "n-1", status: "PENDING" })
  assert.equal(f.calls[0]!.url, `${GW}/authorize`)
  assert.equal(f.calls[0]!.headers.authorization, "Bearer t")
  assert.deepEqual(f.calls[0]!.body, {
    actionDescription: "Wire $500 to ACME",
    params: {},
  })
})

test("authorize binds actionType and params into the request", async (t) => {
  const f = stubFetch(() => ({ body: { nonce: "n-2", status: "PENDING" } }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

  await c.authorize("Wire", {
    actionType: "payments.wire",
    params: { amount: 500 },
    timeout: 60,
  })
  assert.deepEqual(f.calls[0]!.body, {
    actionDescription: "Wire",
    actionType: "payments.wire",
    params: { amount: 500 },
    timeout: 60,
  })
})

test("authorize throws on a non-2xx rather than returning a falsy nonce", async (t) => {
  const f = stubFetch(() => ({ status: 403, text: "forbidden" }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })
  await assert.rejects(() => c.authorize("x"), /authorize failed: 403 forbidden/)
})

test("status url-encodes the nonce", async (t) => {
  // A nonce is server-generated, but encoding it defends the path from ever being split by a
  // slash — a lookup that silently hit a different route would be worse than a 404.
  const f = stubFetch(() => ({ body: { status: "APPROVED" } }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

  await c.status("a/b c")
  assert.equal(f.calls[0]!.url, `${GW}/authorize/a%2Fb%20c`)
})

test("status throws on a non-2xx", async (t) => {
  const f = stubFetch(() => ({ status: 500 }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })
  await assert.rejects(() => c.status("n"), /status failed: 500/)
})

test("consume re-binds the exact action at execution time", async (t) => {
  const f = stubFetch(() => ({ body: { ok: true } }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

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
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })
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
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

  const r = await c.requireApproval("Wire", { intervalMs: 1, timeoutMs: 5000 })
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
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

  // Fails closed and fails fast: a denied action must never look like a timeout.
  const r = await c.requireApproval("Wire", {
    intervalMs: 1,
    timeoutMs: 60_000,
  })
  assert.equal(r.status, "DENIED")
})

test("requireApproval gives up as EXPIRED and converts timeoutMs to whole seconds", async (t) => {
  const f = stubFetch((call) =>
    call.url.endsWith("/authorize")
      ? { body: { nonce: "n-11", status: "PENDING" } }
      : { body: { status: "PENDING" } },
  )
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW, token: "t" })

  const r = await c.requireApproval("Wire", { intervalMs: 1, timeoutMs: 1500 })
  assert.equal(r.status, "EXPIRED")
  // The backend TTL is sent in seconds, rounded up, so the gateway never expires before the client.
  assert.equal(f.calls[0]!.body ? (f.calls[0]!.body as { timeout: number }).timeout : undefined, 2)
})

test("verify url-encodes the document hash and needs no token", async (t) => {
  const f = stubFetch(() => ({
    body: { verified: true, status: "SIGNED", documentHash: "ab/cd" },
  }))
  t.after(f.restore)
  const c = new SakraClient({ gatewayUrl: GW })

  const r = await c.verify("ab/cd")
  assert.equal(r.verified, true)
  assert.equal(f.calls[0]!.url, `${GW}/verify/ab%2Fcd`)
  // Public witness lookup: no Authorization header is required or sent.
  assert.equal(f.calls[0]!.headers.authorization, undefined)
})
