// Transport rules for every TypeScript gateway client (transport.ts): a non-https gateway URL is
// refused at construction (loopback excepted), and a redirect is never followed — a followed 307
// re-sends the POST body, and on the platform plane that body is the private_key_jwt assertion.
// The redirect tests use two REAL local HTTP servers rather than a fetch stub, because the property
// under test is what undici's fetch does with a 307, not what our code asks it to do.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import http from "node:http"
import type { AddressInfo } from "node:net"
import { test } from "node:test"

// The BUILT modules (run `pnpm build` first), matching index.test.ts.
const { assertGatewayUrl, isLoopbackHost, IntygaClient, IntygaPlatformClient } = await import(
  "../dist/index.js"
)

const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })

test("assertGatewayUrl accepts https and loopback http, and strips trailing slashes", () => {
  assert.equal(assertGatewayUrl("https://gw.example/"), "https://gw.example")
  assert.equal(assertGatewayUrl("https://gw.example:8443/base//"), "https://gw.example:8443/base")
  for (const ok of [
    "http://localhost:8787",
    "http://LOCALHOST",
    "http://127.0.0.1:8787",
    "http://127.200.3.4",
    "http://[::1]:8787",
  ]) {
    assert.equal(assertGatewayUrl(ok), ok)
  }
})

test("assertGatewayUrl refuses plain http to a non-loopback host, other schemes and garbage", () => {
  for (const bad of [
    "http://gw.example",
    "http://10.0.0.5:8787",
    "http://128.0.0.1",
    "http://localhost.evil.example",
    "http://127.0.0.1.nip.io",
    "http://[::2]",
    "ftp://gw.example",
    "ws://localhost",
  ]) {
    assert.throws(() => assertGatewayUrl(bad), /must use https:\/\//, bad)
  }
  assert.throws(() => assertGatewayUrl("gw.example"), /not a valid URL/)
})

test("isLoopbackHost covers localhost, 127.0.0.0/8 and ::1 only", () => {
  assert.equal(isLoopbackHost("localhost"), true)
  assert.equal(isLoopbackHost("127.9.9.9"), true)
  assert.equal(isLoopbackHost("[::1]"), true)
  assert.equal(isLoopbackHost("gw.example"), false)
  assert.equal(isLoopbackHost("0.0.0.0"), false)
})

test("IntygaClient refuses a non-https gateway at construction", () => {
  assert.throws(() => new IntygaClient({ gatewayUrl: "http://gw.example", token: "t" }), /must use https/)
  assert.doesNotThrow(() => new IntygaClient({ gatewayUrl: "http://localhost:8787", token: "t" }))
  assert.doesNotThrow(() => new IntygaClient({ gatewayUrl: "https://gw.example", token: "t" }))
})

test("IntygaPlatformClient refuses a non-https gateway at construction", () => {
  assert.throws(
    () => new IntygaPlatformClient({ gatewayUrl: "http://gw.example", clientId: "c", privateKey }),
    /must use https/,
  )
  assert.doesNotThrow(
    () => new IntygaPlatformClient({ gatewayUrl: "http://127.0.0.1:8787", clientId: "c", privateKey }),
  )
})

interface Recorded {
  method: string
  url: string
  body: string
  authorization?: string
}

/**
 * `origin` answers every request with a 307 to the same path on `elsewhere`; `elsewhere` records
 * whatever reaches it. A client that follows redirects shows up as a recorded request.
 */
async function redirectPair(t: { after: (fn: () => Promise<void>) => void }) {
  const reached: Recorded[] = []
  const listen = async (server: http.Server) => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  }
  const elsewhere = await listen(
    http.createServer((req, res) => {
      let body = ""
      req.on("data", (c: Buffer) => (body += c.toString()))
      req.on("end", () => {
        reached.push({
          method: req.method ?? "",
          url: req.url ?? "",
          body,
          authorization: req.headers.authorization,
        })
        res.setHeader("content-type", "application/json")
        res.end(JSON.stringify({ access_token: "stolen", expires_in: 900, status: "APPROVED" }))
      })
    }),
  )
  const origin = await listen(
    http.createServer((req, res) => {
      req.resume()
      res.statusCode = 307
      res.setHeader("location", `${elsewhere}${req.url}`)
      res.end()
    }),
  )
  return { origin, elsewhere, reached }
}

test("IntygaPlatformClient does not follow a 307: the client assertion never reaches the second origin", async (t) => {
  const { origin, elsewhere, reached } = await redirectPair(t)
  const client = new IntygaPlatformClient({ gatewayUrl: origin, clientId: "c", privateKey })
  await assert.rejects(
    client.token(),
    (err: Error & { status?: number }) =>
      err.status === 307 &&
      /token exchange failed: 307/.test(err.message) &&
      /never follow redirects/.test(err.message) &&
      err.message.includes(elsewhere),
  )
  assert.deepEqual(reached, [])
})

test("IntygaPlatformClient does not follow a 307 on an authenticated request either", async (t) => {
  const { origin, reached } = await redirectPair(t)
  const client = new IntygaPlatformClient({ gatewayUrl: origin, clientId: "c", privateKey })
  // Skip the exchange: seed a token so the first request is the authenticated POST itself.
  ;(client as unknown as { cached: { token: string } }).cached = { token: "tok" }
  await assert.rejects(client.createSubject("user-1"), /createSubject failed: 307 .*never follow redirects/)
  assert.deepEqual(reached, [])
})

test("IntygaClient does not follow a 307 on the exchange or on /authorize", async (t) => {
  const { origin, reached } = await redirectPair(t)
  await assert.rejects(
    new IntygaClient({ gatewayUrl: origin, clientId: "id", clientSecret: "secret" }).token(),
    /token exchange failed: 307 .*never follow redirects/,
  )
  await assert.rejects(
    new IntygaClient({ gatewayUrl: origin, token: "t" }).authorize("x", { target: "prod" }),
    /authorize failed: 307 .*never follow redirects/,
  )
  assert.deepEqual(reached, [])
})
