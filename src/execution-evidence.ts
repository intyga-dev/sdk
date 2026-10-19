/**
 * DEWP §4.7 execution evidence — the evidence source's side. An evidence source (a protection relay,
 * a meter, a measured-boot attester) is a party independent of the service that executed an approved
 * action. It observes the effect and signs a statement; your service relays it with
 * `IntygaClient.submitEvidence`. The service never signs one itself: it does not hold the source's key.
 */
import crypto from "node:crypto"
import {
  canonicalExecutionEvidenceStatement,
  type ExecutionVerdict,
  executionPayloadSha256,
} from "@intyga/verify"

/**
 * The canonical statement bytes for one observation (DEWP §4.7.2). `approvalPayload` is the approved
 * DIV Intent Payload (`receipt.canonicalPayload`); its SHA-256 binds the statement to exactly those
 * bytes. Throws on input a verifier would refuse (non-portable numbers, more than 64 levels, …).
 *
 * `sequence` is the source's own gapless counter of statements it has signed for this log — one
 * counter per log, incremented by exactly one per statement, never reused (rule 12). It is what lets
 * a verifier see a statement that was withheld. Keep it durable: a source that restarts from 1 signs
 * a divergence.
 */
export function buildExecutionEvidence(input: {
  approvalPayload: string
  nonce: string
  source: string
  verdict: ExecutionVerdict
  observation: Record<string, unknown>
  /** The source's per-log statement counter (DEWP §4.7.2 rule 12). */
  sequence: number
  /** When the measurement was taken (rule 11). Defaults to `observedAt`, in the DEWP §4.3 form. */
  sampledAt?: string
  /** When the source produced the statement. Defaults to now, in the DEWP §4.3 form. */
  observedAt?: string
}): string {
  const observedAt = input.observedAt ?? new Date().toISOString()
  return canonicalExecutionEvidenceStatement({
    nonce: input.nonce,
    payloadSha256: executionPayloadSha256(input.approvalPayload),
    source: input.source,
    verdict: input.verdict,
    observedAt,
    sampledAt: input.sampledAt ?? observedAt,
    sequence: input.sequence,
    observation: input.observation,
  })
}

/** ES256 (P-256, IEEE P1363) signature over statement bytes, base64 — what `submitEvidence` relays. */
export function signExecutionEvidence(statement: string, privateKey: crypto.KeyObject | string): string {
  const key = typeof privateKey === "string" ? crypto.createPrivateKey(privateKey) : privateKey
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1")
    throw new Error("evidence statements are signed with an EC P-256 (prime256v1) key")
  return crypto
    .sign("sha256", Buffer.from(statement, "utf8"), { key, dsaEncoding: "ieee-p1363" })
    .toString("base64")
}
