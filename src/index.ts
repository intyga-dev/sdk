// @intyga/sdk — one client for every Intyga use case. The primitive is uniform: request a challenge →
// a human approves with a passkey or security key → poll until resolved. Works for AI agents, humans,
// and any backend service; the only difference is which API key/token you hold.

// Receipt verification + canonical helpers now live in the standalone, zero-dependency @intyga/verify
// package (open-source, inspect-it-yourself). Re-exported here so existing SDK consumers are unchanged.
export {
  agentConfigDigest,
  agentReceiptDigest,
  verifyAgentSessionChain,
  verifyAgentDelegationChain,
  type AgentIntentContext,
  type ApprovalReceipt,
  type ApproverTrustAnchor,
  canonicalIntentPayload,
  SELF_CERTIFYING_DID_PREFIX,
  selfCertifyingDid,
  verificationCode,
  verifyApprovalReceipt,
  verifyEcdsaP256,
} from "@intyga/verify"
export {
  parseTrustAnchorFile,
  TRUST_ANCHOR_FILE_TYPE,
  type TrustAnchorFile,
  trustAnchorApprovers,
} from "./trust-anchor.js"
export * as policy from "./policy.js"
export {
  assembleOfflineReceipt,
  CHALLENGE_ENVELOPE_PREFIX,
  clearPendingApproval,
  createOfflineChallenge,
  decodeChallengeEnvelope,
  decodeSignatureEnvelope,
  DEFAULT_OFFLINE_WINDOW_MINUTES,
  encodeSignatureEnvelope,
  FileRedemptionStore,
  type OfflineApprovalOptions,
  type OfflineApprovalResult,
  type OfflineChallenge,
  type PendingApproval,
  pendingApprovals,
  type RedemptionStore,
  SIGNATURE_ENVELOPE_PREFIX,
  useOfflineApproval,
} from "./offline.js"
export {
  approverAnchor,
  type BundleApprover,
  type BundlePolicy,
  DIV_TRUST_BUNDLE_TYPE,
  loadTrustBundle,
  MAX_TRUST_BUNDLE_AGE_DAYS,
  requirementFor,
  saveTrustBundle,
  type TrustBundle,
  type TrustBundleFiles,
  verifyTrustBundle,
} from "./trust-bundle.js"
// The platform-plane client (DIV §5c): for services embedding Intyga for their own end customers —
// opaque subjects, relayed WebAuthn on the platform's origin, hash-only receipts. Its offline
// verifier (verifyPlatformReceipt) is re-exported from @intyga/verify alongside it.
export {
  hashPayload,
  IntygaPlatformClient,
  type IntygaPlatformClientOptions,
  type PlatformSignatureResult,
  type PlatformSubjectView,
  type SignatureChallenge,
} from "./platform.js"
export {
  type PlatformReceipt,
  type PlatformReceiptExpectation,
  verifyPlatformReceipt,
} from "@intyga/verify"
export { type AgentSessionState, type LiveAgentConfig, verifyAgentForExecution } from "./agent-execution.js"

import type { AgentIntentContext, ApprovalReceipt } from "@intyga/verify"
import {
  clearPendingApproval,
  type OfflineApprovalOptions,
  pendingApprovals,
  useOfflineApproval,
} from "./offline.js"

export interface IntygaClientOptions {
  gatewayUrl: string
  /** A pre-minted token (agent or human), OR provide clientId/clientSecret to auto-exchange. */
  token?: string
  clientId?: string
  clientSecret?: string
  /** Allow loading stored bearer token from ~/.intyga/credentials.json (intended for CLI tools). */
  allowStoredCredentials?: boolean
}

/**
 * CONSUMED means the approval was real but has ALREADY BEEN REDEEMED — single-use is enforced by the
 * gateway, and this is how you observe it without calling /authorize/verify. Treat it as not
 * authorized: only APPROVED permits execution.
 */
export type ApprovalStatus =
  | "APPROVED"
  | "CONSUMED"
  | "DENIED"
  | "EXPIRED"
  | "PENDING"
  /**
   * An OFFLINE APPROVAL authorized this — real human signatures, collected out of band at incident
   * time because the gateway could not be reached (docs/DIV.md §5a).
   *
   * Deliberately NOT "APPROVED". The usual caller guard is `if (r.status !== "APPROVED") throw`, so a
   * distinct status means adding offline approval to an existing service cannot silently start
   * permitting things — handling it has to be a conscious code change at the call site.
   */
  | "OFFLINE_APPROVED"

export interface ApprovalResult {
  status: ApprovalStatus
  /** Issuer-completed v1 context retained from challenge creation, never copied from the receipt. */
  agentContext?: AgentIntentContext
  signatureHash?: string
  receipt?: ApprovalReceipt
  /**
   * The challenge nonce this result belongs to. Set by `requireApproval`, which owns the nonce
   * internally — without it, callers of the one-shot helper have no way to pass `expected.nonce` to
   * `verifyApprovalReceipt`, and no way to record the nonce as redeemed for their own single-use check.
   */
  nonce?: string
}

/** Options for a structured, WYSIWYS-bound approval request. */
export interface AuthorizeOptions {
  /**
   * The intended execution target — a machine-readable identifier of the Relying Party / execution
   * environment that will run the action (e.g. "prod-db-cluster-01"). Bound into the signed payload so
   * the approval cannot be replayed against a different target (DIV Target Isolation). Required.
   */
  target: string
  /** Action identifier, e.g. "wire_transfer". Bound into the signed payload. */
  actionType?: string
  /** The exact structured variables that will execute — displayed to the approver AND signed. */
  params?: Record<string, unknown>
  /** Custom Time-To-Live (TTL) for the approval challenge in seconds. */
  timeout?: number
  /** RP-asserted continuity claim for AI_AGENT keys. The PEP must recompute configDigest before
   * execution and compare the signed session state against its own durable budget. */
  agentContext?: {
    action: {
      reversibility: "reversible" | "irreversible"
      amount: { amount: string; currency: string } | null
    }
    configDigest: string
    delegatedBy: string | null
    session: {
      id: string
      seq: string
      prev: string | null
      aggregate: { amount: string; currency: string } | null
    }
  }
}

export interface VerifyResult {
  verified: boolean
  status: string
  documentHash: string
  signerDid?: string | null
  signedAt?: string | null
  signatureHash?: string | null
}

import fs from "node:fs"
import os from "node:os"
import path from "node:path"

/** Where `intyga login` caches bearer tokens. Shared with the CLI writer so reader and writer can't desync. */
export const INTYGA_DIR = path.join(os.homedir(), ".intyga")
export const CREDENTIALS_FILE = path.join(INTYGA_DIR, "credentials.json")

/** How many back-to-back polling failures before `requireApproval` declares the gateway unreachable. */
const MAX_POLL_ERRORS = 5

/**
 * The gateway answered, and the answer was no.
 *
 * Distinct from a transport failure on purpose. Both used to surface as a bare `Error`, so
 * `requireApproval` could not tell "the gateway is gone" from "the gateway refused" — and routed
 * both into the DIV §5a offline-approval path. A reachable gateway returning 403 (SecurityViolation,
 * which `RequirementUnavailable` extends), 401 or 429 is a verdict, not an outage, and a verdict
 * must not be answered by collecting signatures out of band. (402 no longer fires for usage —
 * approvals have no plan allowance — but any 4xx that does arrive is handled the same way.)
 */
export class GatewayRefused extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = "GatewayRefused"
    this.status = status
  }
}

function loadStoredToken(gatewayUrl: string): string | undefined {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) {
      const data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8")) as Record<string, string>
      return data[gatewayUrl]
    }
  } catch {}
  return undefined
}

/**
 * Where the bearer token came from. Only an `exchange` can be repeated: an `explicit` token is the
 * caller's to refresh, and a `stored` one (`intyga login`) is bound to a single passkey ceremony
 * with no client secret behind it, so when it expires the only remedy is logging in again.
 */
type TokenSource = "explicit" | "exchange" | "stored"

interface CachedToken {
  token: string
  source: Exclude<TokenSource, "explicit">
  /** Epoch ms at which the token stops being served from the cache; `undefined` = no expiry known. */
  refreshAt?: number
}

/** The furthest ahead of expiry a token is re-exchanged; shorter tokens use a tenth of their TTL. */
const REFRESH_MARGIN_MS = 60_000

/**
 * When to stop serving a token with `expires_in` seconds of life. Absent or malformed means "no
 * expiry known", which keeps the pre-refresh behaviour (cache until the gateway says 401).
 */
function refreshAtFor(expiresIn: unknown, now: number): number | undefined {
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) return undefined
  const ttlMs = expiresIn * 1000
  return now + ttlMs - Math.min(REFRESH_MARGIN_MS, ttlMs / 10)
}

/**
 * Read `exp` out of a JWT WITHOUT verifying it. This is a hint for when a stored credential should
 * stop being offered, never a trust decision — the gateway verifies the signature and is the only
 * authority on whether the token is good. Anything that does not parse simply yields no hint.
 */
function jwtExpiryHint(token: string): number | undefined {
  const parts = token.split(".")
  if (parts.length !== 3 || !parts[1]) return undefined
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { exp?: unknown }
    return typeof payload.exp === "number" && Number.isFinite(payload.exp) ? payload.exp * 1000 : undefined
  } catch {
    return undefined
  }
}

const STORED_CREDENTIAL_EXPIRED =
  "the credential saved by `intyga login` has expired and cannot be refreshed — run `intyga login` again"

/**
 * The credential saved by `intyga login` is no longer good — the gateway said 401 to it, or its own
 * `exp` has passed and it was not sent at all. A `GatewayRefused` with status 401 on purpose: there
 * is no client secret behind a CLI login, so the only refresh path is logging in again, and an
 * expired credential must be handled as the refusal it stands for — never as an outage that
 * `requireApproval` may answer by collecting signatures offline.
 */
export class StoredCredentialExpired extends GatewayRefused {
  constructor(message: string) {
    super(401, message)
    this.name = "StoredCredentialExpired"
  }
}

export class IntygaClient {
  private cached?: CachedToken
  constructor(private readonly opts: IntygaClientOptions) {}

  /**
   * Resolve a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange.
   *
   * An exchanged token is cached only until shortly before the `expires_in` the gateway reported —
   * `min(60s, expires_in / 10)` ahead of expiry — and re-exchanged after that, so a long-lived service
   * object (or a `requireApproval` wait longer than the token's life) keeps working without the caller
   * managing tokens. A response with no `expires_in` is cached for the life of the process, as before.
   */
  async token(): Promise<string> {
    return (await this.resolveToken()).token
  }

  private async resolveToken(): Promise<{ token: string; source: TokenSource }> {
    if (this.opts.token) return { token: this.opts.token, source: "explicit" }
    const now = Date.now()
    if (this.cached && (this.cached.refreshAt === undefined || now < this.cached.refreshAt)) {
      return { token: this.cached.token, source: this.cached.source }
    }
    if (this.opts.allowStoredCredentials) {
      // Re-read the file on every miss: a fresh `intyga login` in another terminal should be picked
      // up by a wait that is still running, instead of that wait dying on the token it started with.
      const stored = loadStoredToken(this.opts.gatewayUrl)
      if (stored) {
        const exp = jwtExpiryHint(stored)
        if (exp === undefined || now < exp) {
          this.cached = { token: stored, source: "stored", refreshAt: exp }
          return { token: stored, source: "stored" }
        }
        // Expired on disk, and there is nothing here to re-exchange it with — unless the caller ALSO
        // supplied client credentials, which are still good and should not be blocked by a stale file.
        if (!this.opts.clientId || !this.opts.clientSecret)
          throw new StoredCredentialExpired(STORED_CREDENTIAL_EXPIRED)
      }
    }
    return this.exchange(now)
  }

  /**
   * The client-credentials exchange itself, bypassing the stored-credential lookup. The 401 retry in
   * `authed()` calls this directly: going back through `resolveToken()` would consult
   * `~/.intyga/credentials.json` first, so a process configured with BOTH a stored `intyga login`
   * token and client credentials could retry an agent call as the human — a different principal, a
   * different ceremony shape, and a different requester on the witness leaf.
   */
  private async exchange(now: number): Promise<{ token: string; source: "exchange" }> {
    if (!this.opts.clientId || !this.opts.clientSecret) {
      throw new Error(
        this.opts.allowStoredCredentials
          ? "provide `token`, or `clientId` + `clientSecret`, or run `intyga login` first"
          : "provide `token`, or `clientId` + `clientSecret`",
      )
    }
    const basic = Buffer.from(`${this.opts.clientId}:${this.opts.clientSecret}`).toString("base64")
    const res = await fetch(`${this.opts.gatewayUrl}/oauth/token`, {
      method: "POST",
      headers: { authorization: `Basic ${basic}` },
    })
    // A refused exchange is a verdict from a reachable gateway, like any other 4xx — and since the
    // 401-retry in `authed()` re-exchanges, a revoked key now gets here mid-call, where a bare Error
    // would read as an outage and could route a `requireApproval` wait offline.
    if (!res.ok)
      throw new GatewayRefused(res.status, `token exchange failed: ${res.status} ${await res.text()}`)
    const data = (await res.json()) as { access_token: string; expires_in?: unknown }
    this.cached = {
      token: data.access_token,
      source: "exchange",
      refreshAt: refreshAtFor(data.expires_in, now),
    }
    return { token: data.access_token, source: "exchange" }
  }

  /**
   * One authenticated request. On a 401 carrying a token WE exchanged, the cache is dropped and the
   * call retried exactly once with a fresh client-credentials exchange (never a stored credential —
   * see `exchange()`) — that covers clock skew against the gateway and a
   * gateway-side TTL change, both of which would otherwise leave a long-running process refusing every
   * call until restart. An explicit token is never retried (there is nothing to re-exchange it with),
   * and a stored credential is not either: see `refusal()` for what it gets instead.
   */
  private async authed(
    path: string,
    init: { method?: string; headers?: Record<string, string>; body?: string } = {},
  ): Promise<{ res: Response; source: TokenSource }> {
    const send = (token: string) =>
      fetch(`${this.opts.gatewayUrl}${path}`, {
        ...init,
        headers: { ...init.headers, authorization: `Bearer ${token}` },
      })
    const first = await this.resolveToken()
    const res = await send(first.token)
    if (res.status !== 401 || first.source !== "exchange") return { res, source: first.source }
    this.cached = undefined
    const retry = await this.exchange(Date.now())
    return { res: await send(retry.token), source: retry.source }
  }

  /** A refusal on a stored credential names the one remedy there is, instead of a bare 401. */
  private refusal(op: string, res: Response, source: TokenSource, text: string): GatewayRefused {
    const message = `${op} failed: ${res.status}${text ? ` ${text}` : ""}`
    if (res.status !== 401 || source !== "stored") return new GatewayRefused(res.status, message)
    // Drop it so the next call re-reads the file rather than re-sending a token the gateway refused.
    this.cached = undefined
    return new StoredCredentialExpired(`${message} — ${STORED_CREDENTIAL_EXPIRED}`)
  }

  /**
   * `target` is REQUIRED — DIV §3 Invariant 5 (Target Isolation).
   *
   * This used to default to `"global"`, and it was the only one of the four SDKs that did:
   * `sdk-go`, `sdk-rust` and `sdk-python` all trim and hard-refuse a missing or blank target, each
   * citing this invariant. A `"global"` target binds no execution environment into the signed
   * intent, so the resulting approval verifies at every other relying party in the tenant that also
   * asserts `"global"` — an approval a human granted for staging is replayable against production.
   * The gateway has its own `?? "global"` fallback; the sibling ports exist precisely so nobody
   * relies on it, and this one was sending the value explicitly instead.
   */
  async authorize(
    actionDescription: string,
    opts: AuthorizeOptions,
  ): Promise<{ nonce: string; status: ApprovalStatus; agentContext?: AgentIntentContext }> {
    const target = opts?.target?.trim()
    if (!target) {
      throw new Error(
        "target is required (DIV Target Isolation): name the relying party / execution environment " +
          "this approval is bound to",
      )
    }
    const { res, source } = await this.authed("/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        target,
        actionDescription,
        actionType: opts?.actionType,
        params: opts?.params ?? {},
        timeout: opts?.timeout,
        agentContext: opts?.agentContext,
      }),
    })
    if (!res.ok) throw this.refusal("authorize", res, source, await res.text())
    return (await res.json()) as { nonce: string; status: ApprovalStatus; agentContext?: AgentIntentContext }
  }

  /**
   * Execution-time re-binding: after APPROVED, call this immediately before running the action so the
   * gateway confirms the approved signature matches the exact instruction and marks it single-use.
   */
  async consume(
    nonce: string,
    what: { target: string; actionType: string; params?: Record<string, unknown> },
  ): Promise<{ ok: boolean; reason?: string }> {
    // Non-throwing by contract: callers branch on `ok`, so even a refusal status reaches them as a body.
    const { res } = await this.authed("/authorize/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce,
        target: what.target,
        actionType: what.actionType,
        params: what.params ?? {},
      }),
    })
    return (await res.json()) as { ok: boolean; reason?: string }
  }

  /** Poll a challenge's current status (non-blocking). */
  async status(nonce: string): Promise<ApprovalResult> {
    const { res, source } = await this.authed(`/authorize/${encodeURIComponent(nonce)}`)
    if (!res.ok) throw this.refusal("status", res, source, "")
    return (await res.json()) as ApprovalResult
  }

  /**
   * The core zero-trust gate: `await` this immediately before a high-risk action. It creates the
   * challenge and blocks until the human approves/denies with their passkey (or it times out).
   *
   *   const action = {
   *     target: "payments-prod",                    // required — DIV Target Isolation
   *     actionType: "wire_transfer",
   *     params: { to: "Acme Corp", amount: 5000, currency: "USD" },
   *   };
   *   const r = await intyga.requireApproval("Wire $5,000 to Acme Corp", action);
   *   if (r.status !== "APPROVED") throw new Error("not authorized");
   *   // Hard binding before executing. `nonce` and `approvers` are REQUIRED by
   *   // verifyApprovalReceipt and have no default: a receipt checked against the key inside
   *   // itself proves nothing (DIV Invariant 3). Resolve approvers from your own key policy.
   *   // For passkey receipts (the normal flow) `expectedOrigin`/`expectedRpId` are REQUIRED too —
   *   // the verifier fails closed without them, or an assertion from any site would verify.
   *   const check = verifyApprovalReceipt(r.receipt!, {
   *     ...action,
   *     nonce: r.nonce!,
   *     approvers: { publicKeys: trustedApproverKeys },
   *   }, {
   *     expectedOrigin: process.env.INTYGA_WEBAUTHN_ORIGIN,  // your approval console's origin
   *     expectedRpId: process.env.INTYGA_WEBAUTHN_RP_ID,     // and its RP ID
   *   });
   *   if (!check.ok) throw new Error(check.reason);
   *
   * Note this always sends an explicit TTL, derived from `timeoutMs`/`timeout` or the 120s default, so
   * the challenge cannot outlive the wait. A deployment that has raised AUTH_CHALLENGE_TIMEOUT_MS above
   * 120s will not see that default apply here — pass `timeout` to match it. Plain `authorize()` still
   * defers to the server's configured TTL.
   */
  async requireApproval(
    actionDescription: string,
    opts: AuthorizeOptions & {
      timeoutMs?: number
      intervalMs?: number
      /**
       * Opt in to the OFFLINE APPROVAL fallback for THIS call (docs/DIV.md §5a).
       *
       * Omitted means no fallback, ever. Pass it only at the specific call sites permitted to run
       * under an offline approval — a process-wide default would make every gated action in the
       * service accept an out-of-band approval, which is the difference between an emergency
       * mechanism and a hole.
       */
      offline?: OfflineApprovalOptions
    },
  ): Promise<ApprovalResult> {
    // One source of truth for the wait window: the local deadline and the backend TTL must agree, or we
    // either abandon a still-live challenge (returning a false EXPIRED after the human already approved)
    // or keep polling a nonce the gateway has already dropped. `!= null` so `timeout: 0` isn't swallowed.
    const timeoutMs = opts.timeoutMs ?? (opts.timeout != null ? opts.timeout * 1000 : 120_000)

    // The fallback is reachable ONLY from a transport failure. Every other outcome below returns
    // normally: a DENIED or EXPIRED result means a human was reached and did not approve, and letting
    // an out-of-band approval override that would be worse than having no gate at all.
    const tryOffline = async (cause: string, err?: unknown): Promise<ApprovalResult> => {
      // DIV §5a exists for the case where we could not ASK. A 4xx means the gateway was reached and
      // refused — 403 in particular is its own fail-closed "I cannot resolve the approval
      // requirement" (RequirementUnavailable extends SecurityViolation), and 401/402/429 are equally
      // deliberate. Treating a refusal as unreachability turns a policy denial into a different
      // approval route, which is worse than having no gate at all (DIV §3.4).
      //
      // 5xx is deliberately NOT included: a 502 from a load balancer or a 503 from a restarting
      // instance is infrastructure failing, which is exactly the "could not ask" §5a is written for.
      if (err instanceof GatewayRefused && err.status < 500) throw err
      if (opts.agentContext)
        throw new Error("agent continuity requests cannot fall back to an unchained offline proof")
      if (!opts.offline) throw new Error(cause)
      const offline = await useOfflineApproval(
        {
          target: opts.target,
          actionType: opts.actionType ?? "",
          display: actionDescription,
          params: opts.params ?? {},
        },
        opts.offline,
      )
      if (!offline.ok)
        throw new Error(`${cause} — and the offline approval did not complete: ${offline.reason}`)
      return { status: "OFFLINE_APPROVED", receipt: offline.receipt, nonce: offline.nonce }
    }

    let nonce: string
    let agentContext: AgentIntentContext | undefined
    try {
      ;({ nonce, agentContext } = await this.authorize(actionDescription, {
        target: opts.target,
        actionType: opts.actionType,
        params: opts.params,
        timeout: Math.ceil(timeoutMs / 1000),
        agentContext: opts.agentContext,
      }))
    } catch (err) {
      // Could not even raise the challenge — the clearest "gateway is unreachable" signal there is,
      // unless the gateway in fact answered, which tryOffline rethrows rather than routing offline.
      return tryOffline(`could not reach Intyga to request approval: ${(err as Error).message}`, err)
    }
    const deadline = Date.now() + timeoutMs
    const interval = opts.intervalMs ?? 2_000
    let consecutiveErrors = 0
    for (;;) {
      // A human approval can outlast a transient 502 or socket hangup — don't discard the whole wait
      // over one bad poll. Only give up once the gateway looks genuinely unreachable.
      try {
        const r = await this.status(nonce)
        consecutiveErrors = 0
        if (r.status !== "PENDING") return { ...r, nonce, ...(agentContext ? { agentContext } : {}) }
      } catch (err: unknown) {
        if (++consecutiveErrors >= MAX_POLL_ERRORS) {
          const msg = err instanceof Error ? err.message : String(err)
          // The gateway went away mid-wait. Same situation as failing to raise the challenge, so the
          // same fallback applies — and, as there, only because we could not ASK, not because we were
          // told no.
          return tryOffline(`polling failed after ${MAX_POLL_ERRORS} consecutive errors: ${msg}`, err)
        }
      }
      if (Date.now() > deadline)
        return { status: "EXPIRED", nonce, ...(agentContext ? { agentContext } : {}) }
      await new Promise((resolve) => setTimeout(resolve, interval))
    }
  }

  /**
   * Report offline approvals that happened while the gateway was unreachable (DIV §5a.7).
   *
   * Call this on reconnect — a scheduled retry, a health-check hook, or service start. Until an
   * approval is reported it exists only on the relying party's disk, and an unreported approval is
   * indistinguishable from an unauthorized action.
   *
   * A buffered record is cleared ONLY on a definite acknowledgement. A network failure leaves it
   * queued for the next attempt rather than silently discarding the evidence.
   */
  async reconcileOfflineApprovals(
    opts: Pick<OfflineApprovalOptions, "bundleDir" | "bufferDir">,
  ): Promise<{ reported: number; failed: number; reasons: string[] }> {
    // Resolve credentials up front so a misconfigured client throws here, as it always did, instead of
    // being counted as one "failed" report per buffered approval.
    await this.token()
    const reasons: string[] = []
    let reported = 0
    let failed = 0

    for (const use of pendingApprovals(opts)) {
      try {
        const { res } = await this.authed("/offline-approval/reconcile", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            nonce: use.nonce,
            usedAt: use.usedAt,
            target: use.target,
            actionType: use.actionType,
            display: use.display,
            // The full receipt travels with the report so the gateway can RE-VERIFY the approval
            // rather than take the reporter's word for it — we are reporting on ourselves.
            receipt: use.receipt,
            delegationNonce: use.delegationNonce,
          }),
        })
        if (res.ok) {
          clearPendingApproval(use.nonce, opts)
          reported++
        } else {
          failed++
          reasons.push(`${use.nonce}: ${res.status} ${await res.text()}`)
        }
      } catch (err) {
        failed++
        reasons.push(`${use.nonce}: ${(err as Error).message}`)
      }
    }
    return { reported, failed, reasons }
  }

  /** Public witness lookup: has this document hash been signed, by whom, and when? */
  async verify(documentHash: string): Promise<VerifyResult> {
    const res = await fetch(`${this.opts.gatewayUrl}/verify/${encodeURIComponent(documentHash)}`)
    return (await res.json()) as VerifyResult
  }
}
