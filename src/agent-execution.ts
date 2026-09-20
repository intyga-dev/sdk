import {
  agentConfigDigest,
  agentReceiptDigest,
  type ApprovalReceipt,
  type ReceiptExpectation,
  type VerifyReceiptOptions,
  verifyApprovalReceipt,
} from "@intyga/verify"

export type LiveAgentConfig = Parameters<typeof agentConfigDigest>[0]
export type AgentSessionState = {
  head: string | null
  seq: string
  aggregate: { amount: string; currency: string } | null
}

// Same decimal grammar as the DIV v1 agent context validator in @intyga/verify. Validate the
// RP-owned prior aggregate too: it is read from storage, not parsed by the receipt verifier.
const AGENT_DECIMAL = /^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,9})?$/

/** Run at the RP's PEP immediately before execution. This compares the actual runtime config to
 * the independently retained request context, verifies the human proof, and returns a head for the
 * caller's durable compare-and-swap. The caller MUST atomically reserve the budget across sessions,
 * consume the nonce and persist that head before performing the action. */
export function verifyAgentForExecution(
  receipt: ApprovalReceipt,
  expected: ReceiptExpectation & { agentContext: NonNullable<ReceiptExpectation["agentContext"]> },
  liveConfig: LiveAgentConfig,
  trustedState: AgentSessionState,
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; nextHead?: string } {
  let actualDigest: string
  try {
    actualDigest = agentConfigDigest(liveConfig)
  } catch {
    return { ok: false, reason: "current agent configuration cannot be canonicalized" }
  }
  if (actualDigest !== expected.agentContext.agent.configDigest)
    return { ok: false, reason: "agent configuration drifted after approval" }
  const { session, action } = expected.agentContext
  if (session.prev !== trustedState.head)
    return { ok: false, reason: "agent session predecessor differs from the RP's durable head" }
  try {
    if (
      !/^(?:0|[1-9][0-9]{0,17})$/.test(trustedState.seq) ||
      BigInt(session.seq) !== BigInt(trustedState.seq) + 1n
    )
      return { ok: false, reason: "agent session sequence differs from the RP's durable sequence" }
    const money = action.amount
    if (money) {
      if (trustedState.aggregate && trustedState.aggregate.currency !== money.currency)
        return { ok: false, reason: "agent session changes currency" }
      if (
        !session.aggregate ||
        session.aggregate.currency !== money.currency ||
        units(session.aggregate.amount) !== units(trustedState.aggregate?.amount ?? "0") + units(money.amount)
      )
        return { ok: false, reason: "agent aggregate differs from the RP's recomputed total" }
    } else if (session.aggregate || trustedState.aggregate) {
      return { ok: false, reason: "agent session mixes monetary and non-monetary actions" }
    }
  } catch {
    return { ok: false, reason: "invalid agent session amount or sequence" }
  }
  const proof = verifyApprovalReceipt(receipt, expected, { ...opts, allowAutoApproved: false })
  if (!proof.ok) return { ok: false, reason: proof.reason }
  return { ok: true, nextHead: agentReceiptDigest(receipt) }
}

function units(value: string): bigint {
  if (!AGENT_DECIMAL.test(value)) throw new Error("invalid decimal amount")
  const [integer, fraction = ""] = value.split(".")
  if (integer === undefined) throw new Error("invalid decimal amount")
  return BigInt(integer) * 1_000_000_000n + BigInt(fraction.padEnd(9, "0") || "0")
}
