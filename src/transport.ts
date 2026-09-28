// Transport rules shared by every TypeScript client that talks to an Intyga gateway: IntygaClient,
// IntygaPlatformClient, the `intyga` CLI and (re-exported) the @intyga/mcp-sdk approval client.
//
// Two rules, both about where credentials can end up:
//
// 1. The gateway URL must be https://. Every request carries a bearer token, a Basic client secret
//    or a private_key_jwt client assertion; over plain http any on-path observer takes it. Loopback
//    (localhost, 127.0.0.0/8, ::1) is the one exception, for a gateway on the same machine during
//    development — traffic to it never leaves the host.
// 2. Redirects are never followed (`redirect: "manual"`). fetch re-sends a POST body on a 307/308,
//    so a gateway (or anything impersonating its hostname) answering with a redirect to another
//    origin would receive the client assertion or the approval request. A 3xx is surfaced as an
//    error that names the fix instead.
//
// Mirrored in intent (not code) by sdk-go, sdk-rust, sdk-java and sdk-python — change the rule in
// all five together.

/** Per-request bound, matching the Go, Rust, Java and Python clients. */
export const GATEWAY_TIMEOUT_MS = 30_000

/** True for the hostnames a development gateway on this machine can have. */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase()
  if (host === "localhost" || host === "[::1]" || host === "::1") return true
  // WHATWG URL parsing canonicalizes IPv4 (`127.1` → `127.0.0.1`), so a dotted quad is all we see.
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
}

/**
 * Validate a gateway base URL and return it without trailing slashes. Throws unless it is https://,
 * or http:// to a loopback host. Call at client construction so a misconfiguration fails before any
 * credential is sent.
 */
export function assertGatewayUrl(raw: string, name = "gatewayUrl"): string {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error(`${name} is not a valid URL: ${JSON.stringify(raw)}`)
  }
  if (url.protocol === "https:") return raw.replace(/\/+$/, "")
  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) return raw.replace(/\/+$/, "")
  throw new Error(
    `${name} must use https:// (got ${url.protocol}//${url.host}): Intyga clients send credentials on ` +
      "every request and refuse plain http except to a loopback host (localhost, 127.0.0.0/8, ::1) for " +
      "local development",
  )
}

/**
 * A 3xx answered to a `redirect: "manual"` request. Node returns the 3xx itself; a browser-style
 * runtime returns an `opaqueredirect` with status 0 — both are a redirect we did not follow.
 */
export function isRedirect(res: Response): boolean {
  return res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)
}

/** The explanation appended to a refusal when the gateway answered with a redirect. */
export function redirectHint(res: Response): string {
  const location = res.headers.get("location")
  return (
    `the gateway answered with a redirect${location ? ` to ${location}` : ""}; Intyga clients never ` +
    "follow redirects (the request body can carry credentials) — set the gateway URL to its final https:// address"
  )
}
