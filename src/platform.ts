import crypto from "node:crypto"
import {
  type PlatformReceipt,
  type PlatformReceiptExpectation,
  stableStringify,
  verifyPlatformReceipt,
  type VerifyReceiptOptions,
} from "@intyga/verify"
import { GatewayRefused } from "./index.js"
import { assertGatewayUrl, GATEWAY_TIMEOUT_MS, isRedirect, redirectHint } from "./transport.js"

/**
 * The platform-plane client (DIV §5c): for services that embed Intyga for THEIR end customers.
 * The platform owns the UI and the user relationship; this client covers the whole loop —
 * provision an opaque subject, relay a WebAuthn enrollment run on the platform's own origin,
 * canonicalize-and-hash the platform's payload, drive the hash-only signing ceremony, and verify
 * the receipt offline (`verifyReceipt` delegates to @intyga/verify with no gateway call).
 *
 * Authentication is `private_key_jwt` ONLY (RFC 7523): a platform-scoped API key has no working
 * static secret — the gateway refuses it — so this client takes the key's P-256 PRIVATE key and
 * signs a fresh assertion per token exchange. The private key never leaves the process.
 */
export interface IntygaPlatformClientOptions {
  /** https:// only; http:// is accepted for a loopback host (local development) and nothing else. */
  gatewayUrl: string
  clientId: string
  /** The P-256 private key registered (by public half) on the API key: PEM string or KeyObject. */
  privateKey: string | crypto.KeyObject
}

/** SHA-256 (lowercase hex) over the RFC 8785 canonicalization of `payload` — the §5c digest. */
export function hashPayload(payload: unknown): string {
  return crypto.createHash("sha256").update(stableStringify(payload), "utf8").digest("hex")
}

const b64url = (b: Buffer | string) =>
  (typeof b === "string" ? Buffer.from(b, "utf8") : b).toString("base64url")

export interface PlatformSubjectView {
  externalId: string
  did: string
  claims: unknown
  credentials: Array<{
    credentialId: string | null
    publicKey: string
    aaguid: string | null
    deviceType: string | null
    backedUp: boolean | null
    createdAt: string
    revokedAt: string | null
    revokedReason: string | null
  }>
}

export interface SignatureChallenge {
  nonce: string
  expiresAt: string
  /** PublicKeyCredentialRequestOptionsJSON — hand to the browser on the platform's origin. */
  options: unknown
}

export interface PlatformSignatureResult {
  receipt: PlatformReceipt
  ledger: { receiptSeq: string | null; receiptTenantSeq: string | null }
}

export class IntygaPlatformClient {
  private readonly key: crypto.KeyObject
  private readonly gatewayUrl: string
  private cached?: { token: string; refreshAt?: number }

  constructor(private readonly opts: IntygaPlatformClientOptions) {
    // Before the key is parsed: a plain-http URL must fail construction, never reach a request.
    this.gatewayUrl = assertGatewayUrl(opts.gatewayUrl)
    this.key =
      typeof opts.privateKey === "string" ? crypto.createPrivateKey(opts.privateKey) : opts.privateKey
  }

  /** A fresh RFC 7523 client assertion: ES256, iss=sub=clientId, aud=token endpoint, one-shot jti. */
  private assertion(nowMs: number): string {
    const url = new URL("/oauth/token", this.gatewayUrl)
    const header = b64url(JSON.stringify({ alg: "ES256", typ: "JWT" }))
    const iat = Math.floor(nowMs / 1000)
    const payload = b64url(
      JSON.stringify({
        iss: this.opts.clientId,
        sub: this.opts.clientId,
        aud: `${url.origin}${url.pathname}`,
        iat,
        exp: iat + 300,
        jti: crypto.randomUUID(),
      }),
    )
    // JWS ES256 signatures are raw r||s (IEEE P1363), not DER.
    const signature = crypto
      .sign("sha256", Buffer.from(`${header}.${payload}`, "utf8"), {
        key: this.key,
        dsaEncoding: "ieee-p1363",
      })
      .toString("base64url")
    return `${header}.${payload}.${signature}`
  }

  async token(): Promise<string> {
    const now = Date.now()
    if (this.cached && (this.cached.refreshAt === undefined || now < this.cached.refreshAt)) {
      return this.cached.token
    }
    return (await this.exchange(now)).token
  }

  private async exchange(nowMs: number): Promise<{ token: string }> {
    // `redirect: "manual"`: a followed 307/308 would re-send this body — the client assertion — to
    // whatever origin the Location names. A 3xx is refused below instead (transport.ts).
    const res = await fetch(`${this.gatewayUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
      body: JSON.stringify({
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: this.assertion(nowMs),
      }),
    })
    if (!res.ok)
      throw new GatewayRefused(
        res.status,
        `token exchange failed: ${res.status} ${isRedirect(res) ? redirectHint(res) : await res.text()}`,
      )
    const data = (await res.json()) as { access_token: string; expires_in?: unknown }
    const ttlMs = typeof data.expires_in === "number" ? data.expires_in * 1000 : undefined
    this.cached = {
      token: data.access_token,
      // Re-exchange shortly before expiry, same policy as IntygaClient: min(60s, ttl/10) early.
      refreshAt: ttlMs === undefined ? undefined : nowMs + ttlMs - Math.min(60_000, ttlMs / 10),
    }
    return { token: data.access_token }
  }

  private async authed<T>(
    path: string,
    init: { method?: string; body?: unknown } = {},
    op = path,
  ): Promise<T> {
    const send = async (token: string) =>
      fetch(`${this.gatewayUrl}${path}`, {
        method: init.method ?? (init.body === undefined ? "GET" : "POST"),
        redirect: "manual",
        signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
        headers: {
          authorization: `Bearer ${token}`,
          ...(init.body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
      })
    let res = await send(await this.token())
    if (res.status === 401) {
      // One retry on a fresh exchange — covers TTL skew for a long-lived process.
      this.cached = undefined
      res = await send((await this.exchange(Date.now())).token)
    }
    if (!res.ok)
      throw new GatewayRefused(
        res.status,
        `${op} failed: ${res.status} ${isRedirect(res) ? redirectHint(res) : await res.text()}`,
      )
    return (await res.json()) as T
  }

  // ── Subjects & enrollment relay ────────────────────────────────────────────────────────────────

  async createSubject(
    externalId: string,
    claims?: Record<string, unknown>,
  ): Promise<{ externalId: string; did: string }> {
    const { subject } = await this.authed<{ subject: { externalId: string; did: string } }>(
      "/platform/subjects",
      { body: { externalId, ...(claims ? { claims } : {}) } },
      "createSubject",
    )
    return subject
  }

  async getSubject(externalId: string): Promise<PlatformSubjectView> {
    const { subject } = await this.authed<{ subject: PlatformSubjectView }>(
      `/platform/subjects/${encodeURIComponent(externalId)}`,
      {},
      "getSubject",
    )
    return subject
  }

  /** Registration options frozen to the exact browser origin that will call credentials.create. */
  async beginEnrollment(externalId: string, origin: string, rpId?: string): Promise<unknown> {
    const { options } = await this.authed<{ options: unknown }>(
      "/platform/credentials/register/options",
      { body: { externalId, origin, ...(rpId ? { rpId } : {}) } },
      "beginEnrollment",
    )
    return options
  }

  /** Relay the browser's RegistrationResponseJSON. Returns the bound subject DID + credential. */
  async completeEnrollment(
    externalId: string,
    response: unknown,
  ): Promise<{
    subject: { externalId: string; did: string }
    credential: { credentialId: string; publicKey: string }
  }> {
    return this.authed("/platform/credentials/register/verify", {
      body: { externalId, response },
    })
  }

  async revokeCredential(credentialId: string, reason?: string): Promise<{ revokedAt: string }> {
    return this.authed(
      `/platform/credentials/${encodeURIComponent(credentialId)}/revoke`,
      { body: reason ? { reason } : {} },
      "revokeCredential",
    )
  }

  // ── Hash-only signing (DIV §5c) ────────────────────────────────────────────────────────────────

  /**
   * Open a signing challenge. Pass either the precomputed lowercase-hex `payloadHash`, or `payload`
   * to canonicalize-and-hash here — in that case render your approval UI from the SAME
   * canonicalization (`stableStringify`), sign these options in the browser, and execute from that
   * serialization: displayed, signed and executed bytes must be one artifact (§5c.1).
   */
  async requestSignature(input: {
    externalId: string
    /** Exact browser origin that will call navigator.credentials.get; frozen into the ceremony. */
    origin: string
    payloadHash?: string
    payload?: unknown
    rpId?: string
    expiresInSeconds?: number
  }): Promise<SignatureChallenge> {
    const payloadHash = input.payloadHash ?? hashPayload(input.payload)
    return this.authed(
      "/platform/sign/challenges",
      {
        body: {
          externalId: input.externalId,
          payloadHash,
          origin: input.origin,
          ...(input.rpId ? { rpId: input.rpId } : {}),
          ...(input.expiresInSeconds ? { expiresInSeconds: input.expiresInSeconds } : {}),
        },
      },
      "requestSignature",
    )
  }

  /** Relay the browser's AuthenticationResponseJSON; returns the receipt + its ledger handle. */
  async completeSignature(nonce: string, response: unknown): Promise<PlatformSignatureResult> {
    return this.authed(
      `/platform/sign/challenges/${encodeURIComponent(nonce)}/complete`,
      { body: { response } },
      "completeSignature",
    )
  }

  async getSignature(
    nonce: string,
  ): Promise<{ status: string; receipt?: PlatformReceipt; ledger?: PlatformSignatureResult["ledger"] }> {
    return this.authed(`/platform/sign/challenges/${encodeURIComponent(nonce)}`, {}, "getSignature")
  }

  async rejectSignature(nonce: string): Promise<{ ok: boolean }> {
    return this.authed(
      `/platform/sign/challenges/${encodeURIComponent(nonce)}/reject`,
      { body: {} },
      "rejectSignature",
    )
  }

  /** The receipt's DEWP inclusion proof. 409 until the ledger seals — poll after a commit window. */
  async getReceiptProof(nonce: string): Promise<Record<string, unknown>> {
    return this.authed(`/platform/receipts/${encodeURIComponent(nonce)}/proof`, {}, "getReceiptProof")
  }

  /** Offline verification — no gateway call. Delegates to @intyga/verify's verifyPlatformReceipt. */
  verifyReceipt(
    receipt: PlatformReceipt,
    expected: PlatformReceiptExpectation,
    opts?: VerifyReceiptOptions,
  ): ReturnType<typeof verifyPlatformReceipt> {
    return verifyPlatformReceipt(receipt, expected, opts)
  }
}
