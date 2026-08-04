// @intyga/sdk — one client for every Intyga use case. The primitive is uniform: request a challenge →
// a human approves with a passkey or security key → poll until resolved. Works for AI agents, humans,
// and any backend service; the only difference is which API key/token you hold.

// Receipt verification + canonical helpers now live in the standalone, zero-dependency @intyga/verify
// package (open-source, inspect-it-yourself). Re-exported here so existing SDK consumers are unchanged.
export {
  type ApprovalReceipt,
  canonicalIntentPayload,
  verificationCode,
  verifyApprovalReceipt,
  verifyEcdsaP256,
} from "@intyga/verify"
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

import type { ApprovalReceipt } from "@intyga/verify"
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
 * which `RequirementUnavailable` extends), 402 (Protected Ops exhausted), 401 or 429 is a verdict,
 * not an outage, and a verdict must not be answered by collecting signatures out of band.
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

export class IntygaClient {
  private cachedToken?: string
  constructor(private readonly opts: IntygaClientOptions) {}

  /** Resolve a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange. */
  async token(): Promise<string> {
    if (this.opts.token) return this.opts.token
    if (this.cachedToken) return this.cachedToken
    if (this.opts.allowStoredCredentials) {
      const stored = loadStoredToken(this.opts.gatewayUrl)
      if (stored) {
        this.cachedToken = stored
        return stored
      }
    }
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
    if (!res.ok) throw new Error(`token exchange failed: ${res.status} ${await res.text()}`)
    const data = (await res.json()) as { access_token: string }
    this.cachedToken = data.access_token
    return data.access_token
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
  ): Promise<{ nonce: string; status: ApprovalStatus }> {
    const target = opts?.target?.trim()
    if (!target) {
      throw new Error(
        "target is required (DIV Target Isolation): name the relying party / execution environment " +
          "this approval is bound to",
      )
    }
    const token = await this.token()
    const res = await fetch(`${this.opts.gatewayUrl}/authorize`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        target,
        actionDescription,
        actionType: opts?.actionType,
        params: opts?.params ?? {},
        timeout: opts?.timeout,
      }),
    })
    if (!res.ok) throw new GatewayRefused(res.status, `authorize failed: ${res.status} ${await res.text()}`)
    return (await res.json()) as { nonce: string; status: ApprovalStatus }
  }

  /**
   * Execution-time re-binding: after APPROVED, call this immediately before running the action so the
   * gateway confirms the approved signature matches the exact instruction and marks it single-use.
   */
  async consume(
    nonce: string,
    what: { target: string; actionType: string; params?: Record<string, unknown> },
  ): Promise<{ ok: boolean; reason?: string }> {
    const token = await this.token()
    const res = await fetch(`${this.opts.gatewayUrl}/authorize/verify`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
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
    const token = await this.token()
    const res = await fetch(`${this.opts.gatewayUrl}/authorize/${encodeURIComponent(nonce)}`, {
      headers: { authorization: `Bearer ${token}` },
    })
    if (!res.ok) throw new GatewayRefused(res.status, `status failed: ${res.status}`)
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
   *   const check = verifyApprovalReceipt(r.receipt!, {
   *     ...action,
   *     nonce: r.nonce!,
   *     approvers: { publicKeys: trustedApproverKeys },
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
    try {
      ;({ nonce } = await this.authorize(actionDescription, {
        target: opts.target,
        actionType: opts.actionType,
        params: opts.params,
        timeout: Math.ceil(timeoutMs / 1000),
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
        if (r.status !== "PENDING") return { ...r, nonce }
      } catch (err: unknown) {
        if (++consecutiveErrors >= MAX_POLL_ERRORS) {
          const msg = err instanceof Error ? err.message : String(err)
          // The gateway went away mid-wait. Same situation as failing to raise the challenge, so the
          // same fallback applies — and, as there, only because we could not ASK, not because we were
          // told no.
          return tryOffline(`polling failed after ${MAX_POLL_ERRORS} consecutive errors: ${msg}`, err)
        }
      }
      if (Date.now() > deadline) return { status: "EXPIRED", nonce }
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
    const token = await this.token()
    const reasons: string[] = []
    let reported = 0
    let failed = 0

    for (const use of pendingApprovals(opts)) {
      try {
        const res = await fetch(`${this.opts.gatewayUrl}/offline-approval/reconcile`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
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
