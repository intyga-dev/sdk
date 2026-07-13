// @sakra/sdk — one client for every SÄKRA use case. The primitive is uniform: request a challenge →
// a human approves on their wallet → poll until resolved. Works for AI agents, humans, and any
// backend service; the only difference is which API key/token you hold.

export * as policy from "./policy.js";

// Receipt verification + canonical helpers now live in the standalone, zero-dependency @sakra/verify
// package (open-source, inspect-it-yourself). Re-exported here so existing SDK consumers are unchanged.
export {
  verifyApprovalReceipt,
  canonicalAuthorizationPayload,
  verificationCode,
  verifyEcdsaP256,
  type ApprovalReceipt,
} from "@sakra/verify";
import type { ApprovalReceipt } from "@sakra/verify";

export interface SakraClientOptions {
  gatewayUrl: string;
  /** A pre-minted token (agent or human), OR provide clientId/clientSecret to auto-exchange. */
  token?: string;
  clientId?: string;
  clientSecret?: string;
}

export type ApprovalStatus = "APPROVED" | "DENIED" | "EXPIRED" | "PENDING";

export interface ApprovalResult {
  status: ApprovalStatus;
  signatureHash?: string;
  receipt?: ApprovalReceipt;
}

/** Options for a structured, WYSIWYS-bound approval request. */
export interface AuthorizeOptions {
  /** Action identifier, e.g. "wire_transfer". Bound into the signed payload. */
  actionType?: string;
  /** The exact structured variables that will execute — displayed in the wallet AND signed. */
  params?: Record<string, unknown>;
  /** Custom Time-To-Live (TTL) for the approval challenge in seconds. */
  timeout?: number;
}

export interface VerifyResult {
  verified: boolean;
  status: string;
  documentHash: string;
  signerDid?: string | null;
  signedAt?: string | null;
  signatureHash?: string | null;
}

import os from "node:os";
import path from "node:path";
import fs from "node:fs";

function loadStoredToken(gatewayUrl: string): string | undefined {
  try {
    const credsPath = path.join(os.homedir(), ".sakra", "credentials.json");
    if (fs.existsSync(credsPath)) {
      const data = JSON.parse(fs.readFileSync(credsPath, "utf-8")) as Record<string, string>;
      return data[gatewayUrl];
    }
  } catch {}
  return undefined;
}

export class SakraClient {
  private cachedToken?: string;
  constructor(private readonly opts: SakraClientOptions) {}

  /** Resolve a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange. */
  async token(): Promise<string> {
    if (this.opts.token) return this.opts.token;
    if (this.cachedToken) return this.cachedToken;
    const stored = loadStoredToken(this.opts.gatewayUrl);
    if (stored) {
      this.cachedToken = stored;
      return stored;
    }
    if (!this.opts.clientId || !this.opts.clientSecret) {
      throw new Error("provide `token`, or `clientId` + `clientSecret`, or run `sakra login` first");
    }
    const basic = Buffer.from(`${this.opts.clientId}:${this.opts.clientSecret}`).toString("base64");
    const res = await fetch(`${this.opts.gatewayUrl}/oauth/token`, {
      method: "POST",
      headers: { authorization: `Basic ${basic}` },
    });
    if (!res.ok) throw new Error(`token exchange failed: ${res.status} ${await res.text()}`);
    const data = (await res.json()) as { access_token: string };
    this.cachedToken = data.access_token;
    return data.access_token;
  }

  async authorize(
    actionDescription: string,
    opts: AuthorizeOptions = {},
  ): Promise<{ nonce: string; status: ApprovalStatus }> {
    const token = await this.token();
    const res = await fetch(`${this.opts.gatewayUrl}/authorize`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        actionDescription,
        actionType: opts.actionType,
        params: opts.params ?? {},
        timeout: opts.timeout,
      }),
    });
    if (!res.ok) throw new Error(`authorize failed: ${res.status} ${await res.text()}`);
    return (await res.json()) as { nonce: string; status: ApprovalStatus };
  }

  /**
   * Execution-time re-binding: after APPROVED, call this immediately before running the action so the
   * gateway confirms the approved signature matches the exact instruction and marks it single-use.
   */
  async consume(
    nonce: string,
    what: { actionType: string; params?: Record<string, unknown> },
  ): Promise<{ ok: boolean; reason?: string }> {
    const token = await this.token();
    const res = await fetch(`${this.opts.gatewayUrl}/authorize/verify`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ nonce, actionType: what.actionType, params: what.params ?? {} }),
    });
    return (await res.json()) as { ok: boolean; reason?: string };
  }

  /** Poll a challenge's current status (non-blocking). */
  async status(nonce: string): Promise<ApprovalResult> {
    const token = await this.token();
    const res = await fetch(`${this.opts.gatewayUrl}/authorize/${encodeURIComponent(nonce)}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`status failed: ${res.status}`);
    return (await res.json()) as ApprovalResult;
  }

  /**
   * The core zero-trust gate: `await` this immediately before a high-risk action. It creates the
   * challenge and blocks until the human approves/denies on their wallet (or it times out).
   *
   *   const r = await sakra.requireApproval("Wire $5,000 to Acme Corp", {
   *     actionType: "wire_transfer",
   *     params: { to: "Acme Corp", amount: 5000, currency: "USD" },
   *   });
   *   if (r.status !== "APPROVED") throw new Error("not authorized");
   *   // Optional hard binding before executing:
   *   const ok = verifyApprovalReceipt(r.receipt!, { actionType: "wire_transfer", params: {...} });
   */
  async requireApproval(
    actionDescription: string,
    opts: AuthorizeOptions & { timeoutMs?: number; intervalMs?: number } = {},
  ): Promise<ApprovalResult> {
    const backendTimeoutSec = opts.timeoutMs ? Math.ceil(opts.timeoutMs / 1000) : opts.timeout;
    const { nonce } = await this.authorize(actionDescription, {
      actionType: opts.actionType,
      params: opts.params,
      timeout: backendTimeoutSec,
    });
    const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
    const interval = opts.intervalMs ?? 2_000;
    for (;;) {
      const r = await this.status(nonce);
      if (r.status !== "PENDING") return r;
      if (Date.now() > deadline) return { status: "EXPIRED" };
      await new Promise((resolve) => setTimeout(resolve, interval));
    }
  }

  /** Public witness lookup: has this document hash been signed, by whom, and when? */
  async verify(documentHash: string): Promise<VerifyResult> {
    const res = await fetch(`${this.opts.gatewayUrl}/verify/${encodeURIComponent(documentHash)}`);
    return (await res.json()) as VerifyResult;
  }
}
