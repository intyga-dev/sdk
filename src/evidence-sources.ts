/**
 * The relying party's evidence-source trust file for DEWP §4.7 execution evidence.
 *
 * Deliberately a separate file from the approver trust anchor (`trust-anchor.ts`): an approver is not
 * an independent observer of the action they approved, and a source key accepted as an approver key
 * would let a sensor approve (DEWP §4.7.5). Like the trust anchor, it carries no signature — adopting
 * it into your configuration is the act of trust.
 */
import type { ExecutionEvidencePolicy, TrustedSourceKey } from "@intyga/verify"

export const EVIDENCE_SOURCES_FILE_TYPE = "intyga-evidence-sources"

/**
 * One key of a source: a bare base64 SPKI P-256 key, or the key with a validity interval (DEWP
 * §4.7.5). A bounded key establishes trust only when the Evidence Record's anchored time lies inside
 * `[notBefore, notAfter]` — write the source's registration time from the console's Evidence Sources
 * page as `notBefore`, and as `notAfter` the earliest witness time of the first checkpoint anchored
 * after its revocation (not the revocation instant, which would refuse every statement anchored
 * later), so a statement accepted before the revocation keeps its trust and one after does not.
 */
export type EvidenceSourceKey = string | { key: string; notBefore?: string; notAfter?: string }

export interface EvidenceSourcesFile {
  type: typeof EVIDENCE_SOURCES_FILE_TYPE
  v: 1
  /** Each source's identifier (its statements' `source`) and the keys that speak for it. */
  sources: Array<{ did: string; publicKeys: EvidenceSourceKey[]; label?: string }>
}

const fail = (detail: string): never => {
  throw new Error(`invalid evidence-sources file: ${detail}`)
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/
const DEWP_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

/**
 * A DEWP §4.3 timestamp naming a real instant, as the verifier reads it: `Date.parse` alone rolls
 * 30 February into March, so the value must also round-trip. A bound the loader accepted but the
 * verifier refused would load cleanly and then silently trust nothing.
 */
function checkTimestamp(did: string, field: string, value: unknown): void {
  if (value === undefined) return
  const ms = typeof value === "string" && DEWP_TIMESTAMP.test(value) ? Date.parse(value) : Number.NaN
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value)
    fail(`source ${did}: ${field} must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp`)
}

/** Parse and validate an evidence-sources file, failing loudly on the first problem. */
export function parseEvidenceSourcesFile(jsonText: string): EvidenceSourcesFile {
  let raw: unknown
  try {
    raw = JSON.parse(jsonText)
  } catch (err) {
    return fail(`not valid JSON (${err instanceof Error ? err.message : String(err)})`)
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return fail("root must be an object")
  const obj = raw as Record<string, unknown>
  if (obj.type !== EVIDENCE_SOURCES_FILE_TYPE)
    return fail(
      `type must be "${EVIDENCE_SOURCES_FILE_TYPE}" — approver trust (intyga-trust-anchor) is a separate file`,
    )
  if (obj.v !== 1) return fail(`unsupported version ${JSON.stringify(obj.v)} (expected 1)`)
  if (!Array.isArray(obj.sources) || obj.sources.length === 0)
    return fail("sources must be a non-empty array — an empty file would trust nobody")
  const seen = new Set<string>()
  for (const entry of obj.sources) {
    if (typeof entry !== "object" || entry === null) return fail("every sources[] entry must be an object")
    const { did, publicKeys, label } = entry as Record<string, unknown>
    if (typeof did !== "string" || did.length === 0) return fail("every source needs a non-empty did")
    if (seen.has(did)) return fail(`duplicate source ${did}`)
    seen.add(did)
    if (!Array.isArray(publicKeys) || publicKeys.length === 0)
      return fail(`source ${did}: publicKeys must be a non-empty array`)
    for (const key of publicKeys) {
      if (typeof key === "string") {
        if (!BASE64.test(key))
          return fail(`source ${did}: every publicKeys[] entry must be a base64 SPKI key`)
        continue
      }
      if (typeof key !== "object" || key === null || Array.isArray(key))
        return fail(
          `source ${did}: every publicKeys[] entry must be a base64 SPKI key or { key, notBefore?, notAfter? }`,
        )
      const k = key as Record<string, unknown>
      if (typeof k.key !== "string" || !BASE64.test(k.key))
        return fail(`source ${did}: every publicKeys[] entry must carry a base64 SPKI key`)
      // Exactly these members: a misspelt bound (`notafter`, `revokedAt`) must not read as "no bound".
      for (const member of Object.keys(k))
        if (member !== "key" && member !== "notBefore" && member !== "notAfter")
          return fail(
            `source ${did}: unexpected member "${member}" in a publicKeys[] entry (only key, notBefore, notAfter)`,
          )
      checkTimestamp(did, "notBefore", k.notBefore)
      checkTimestamp(did, "notAfter", k.notAfter)
      if (
        typeof k.notBefore === "string" &&
        typeof k.notAfter === "string" &&
        Date.parse(k.notBefore) > Date.parse(k.notAfter)
      )
        return fail(`source ${did}: notBefore is later than notAfter`)
    }
    if (label !== undefined && typeof label !== "string") return fail(`source ${did}: label must be a string`)
  }
  return obj as unknown as EvidenceSourcesFile
}

/** The verifier's evidence-source trust from a parsed file. */
export function evidencePolicyFromFile(file: EvidenceSourcesFile): ExecutionEvidencePolicy {
  const trustedSources: Record<string, TrustedSourceKey[]> = Object.create(null)
  for (const s of file.sources) trustedSources[s.did] = s.publicKeys
  return { trustedSources }
}
