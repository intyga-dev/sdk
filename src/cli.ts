#!/usr/bin/env node
import crypto from "node:crypto"
import fs from "node:fs"
// Paths come from the SDK so this writer and the `token()` reader can never drift apart.
import { type ApprovalResult, CREDENTIALS_FILE, INTYGA_DIR, IntygaClient } from "./index.js"
import {
  decodeChallengeEnvelope,
  encodeSignatureEnvelope,
  loadTrustBundle,
  saveTrustBundle,
} from "./index.js"
import { blobHash, encryptPolicy, generateOrgKeypair } from "./policy.js"
import { ensurePrivateDir, writePrivateFile } from "./secure-files.js"

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 ? process.argv[i + 1] : undefined
}

/**
 * The approver keys THIS caller trusts, from --approver-key (repeatable) or INTYGA_APPROVER_KEYS
 * (comma-separated). Base64 SPKI for a raw P-256 approver, base64 COSE for a passkey.
 *
 * There is deliberately no default and no fallback to the key inside the receipt. Verifying a receipt
 * against its own embedded key proves only that the receipt is self-consistent: anyone who can hand
 * you one could have generated that keypair, signed the exact payload your command is about to run,
 * and called themselves anything. Resolving the key yourself is the entire security property
 * (DIV §3 Invariant 3), so the CLI refuses rather than verify something weaker.
 */
function approverKeys(): string[] {
  const flags: string[] = []
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === "--approver-key" && process.argv[i + 1]) {
      flags.push(process.argv[i + 1] as string)
    }
  }
  const fromEnv = (process.env.INTYGA_APPROVER_KEYS ?? "")
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean)
  return [...flags, ...fromEnv]
}

function die(msg: string): never {
  console.error(`error: ${msg}`)
  process.exit(1)
}

/**
 * Render a requester-controlled field for a human who is about to sign it.
 *
 * `display`, `actionType`, `target` and `requester.did` all come from whoever built the challenge.
 * Interpolated raw into a terminal, a newline lets them print convincing extra lines above the real
 * ones, and an ANSI cursor/erase sequence (`\x1b[A`, `\x1b[2K`) removes the real ones outright — so
 * the approver reads one action and signs a different one. The signature still covers the true
 * bytes, so the approval verifies perfectly at the relying party.
 *
 * That is precisely the outcome DIV §5a.8 says a compromised requester must not be able to reach:
 * "it cannot obtain a signature over an action the Approvers decline". Stripping C0/C1 controls and
 * capping length keeps this pane a faithful view of the signed payload.
 */
function approverSafe(value: string, max = 300): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
  const stripped = value.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
  return stripped.length > max ? `${stripped.slice(0, max)}… (truncated, ${stripped.length} chars)` : stripped
}

function parseTimeout(val: string | undefined): { timeoutSec?: number; timeoutMs: number } {
  if (!val) return { timeoutMs: 120_000 }
  const num = Number(val)
  if (!Number.isFinite(num) || num <= 0) {
    die(`Invalid --timeout value: "${val}". Must be a positive number of seconds.`)
  }
  return { timeoutSec: num, timeoutMs: Math.round(num * 1000) }
}

/** Read a privileged internal token without leaking it into shell history/process listings. */
function internalToken(): string {
  if (arg("token"))
    die(
      "--token is not accepted for internal credentials; use INTYGA_INTERNAL_TOKEN, --token-file, or --token-stdin",
    )
  const file = arg("token-file")
  const stdin = process.argv.includes("--token-stdin")
  const env = process.env.INTYGA_INTERNAL_TOKEN
  const sources = Number(Boolean(file)) + Number(stdin) + Number(Boolean(env))
  if (sources !== 1) {
    die("provide exactly one of INTYGA_INTERNAL_TOKEN, --token-file <0600 file>, or --token-stdin")
  }
  if (env) return env.trim()
  if (stdin) return fs.readFileSync(0, "utf8").trim()
  const stat = fs.lstatSync(file as string)
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    die("--token-file must be a regular owner-only (0600) file")
  }
  return fs.readFileSync(file as string, "utf8").trim()
}

function saveStoredToken(gatewayUrl: string, token: string) {
  ensurePrivateDir(INTYGA_DIR)
  let data: Record<string, string> = {}
  if (fs.existsSync(CREDENTIALS_FILE)) {
    try {
      data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8")) as Record<string, string>
    } catch {}
  }
  data[gatewayUrl] = token
  // This file holds a live bearer token — never leave it at the default umask (0644) on a shared host.
  writePrivateFile(CREDENTIALS_FILE, JSON.stringify(data, null, 2))
}

function _signPayload(privateKeyB64: string, payload: string): string {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  })
  const sign = crypto.createSign("sha256")
  sign.update(payload)
  return sign.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64")
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/**
 * Build the DEWP §5.3 anchor-policy options for `verifyBundle` from CLI flags.
 *
 * Anchor signatures are only meaningful against keys the AUDITOR trusts. `--anchor-keys` supplies a
 * JSON map of `{ "issuer#keyId": "<base64 SPKI>" }` (the shape `/.well-known/dewp-anchors.json`
 * publishes), and `--trusted-issuer` (repeatable, comma-separated) names which issuers count toward
 * quorum. Supplying neither is not an error, but it is not an anchor check either: DEWP §3
 * Invariant 7 makes `anchorVerified` an if-and-only-if on the quorum, so with no policy it stays
 * false and the report says why. A root supplied via `--root` is provenance, not verification.
 *
 * A REKOR anchor is verified differently: it carries no DEWP signature, so instead of a key from
 * `--anchor-keys` it needs Sigstore's LOG key (`--rekor-key`), against which its Signed Entry
 * Timestamp is checked. Without that key a Rekor anchor cannot be verified and therefore does NOT
 * count toward quorum — deliberately, because counting an unverifiable anchor is how "independently
 * anchored" becomes a claim rather than a fact. Get the key from Sigstore's TUF root, not from the
 * bundle you are checking.
 */
async function buildAnchorOptions(
  trustedIssuers: string | undefined,
  anchorKeysFile: string | undefined,
  requireAnchors: string | undefined,
  rekorKeyFile?: string,
): Promise<Record<string, unknown>> {
  if (!trustedIssuers) return {}
  const issuers = trustedIssuers
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
  if (issuers.length === 0) return {}

  const nodeCrypto = await import("node:crypto")
  let keyMap: Record<string, string> = {}
  if (anchorKeysFile) {
    try {
      keyMap = JSON.parse(fs.readFileSync(anchorKeysFile, "utf8")) as Record<string, string>
    } catch (err) {
      die(`cannot read --anchor-keys: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  // A required count larger than the keys we can actually resolve would fail confusingly; default to
  // "every named issuer must agree", which is the conservative reading of §5.3.
  const required = requireAnchors ? Number(requireAnchors) : issuers.length
  if (!Number.isFinite(required) || required < 1) die("--require-anchors must be a positive integer")

  let rekorKey: string | undefined
  if (rekorKeyFile) {
    try {
      rekorKey = fs.readFileSync(rekorKeyFile, "utf8").trim()
    } catch (err) {
      die(`cannot read --rekor-key: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  return {
    ...(rekorKey ? { externalKeys: { rekor: rekorKey } } : {}),
    anchorPolicy: {
      requiredAnchors: required,
      trustedIssuers: issuers,
      quorum: required >= issuers.length ? "ALL_MUST_AGREE" : "N_OF_M",
    },
    resolveAnchorKey: (anchor: { issuer: string; keyId: string }) => {
      const spki = keyMap[`${anchor.issuer}#${anchor.keyId}`] ?? keyMap[anchor.issuer]
      if (!spki) return null
      try {
        return nodeCrypto.createPublicKey({
          key: Buffer.from(spki, "base64"),
          format: "der",
          type: "spki",
        })
      } catch {
        return null // an unparseable key resolves to "unknown", never to "trusted"
      }
    },
  }
}

/** One line of a published roots.jsonl. v2 lines carry the §5.4 chain; hand-built minimal lists may not. */
interface RootsFileEntry {
  seqStart?: string
  seqEnd?: string
  entryCount?: number
  root: string
  anchorRef?: string
  anchoredAt?: string
  prevChainHash?: string
  chainHash?: string
}

function rootsDecimal(value: unknown, label: string): bigint {
  const rendered = JSON.stringify(value) ?? String(value)
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    die(`${label} ${rendered} is not an unsigned decimal integer`)
  }
  return BigInt(value)
}

/** Read and parse a JSONL roots file (e.g. a checkout of intyga-dev/ledger's roots/roots.jsonl).
 *  A malformed line is fatal — silently skipping one would lose a published root without saying so. */
function parseRootsEntries(rootsPath: string): RootsFileEntry[] {
  let raw: string
  try {
    raw = fs.readFileSync(rootsPath, "utf8")
  } catch (err) {
    die(`cannot read roots file: ${err instanceof Error ? err.message : String(err)}`)
  }
  return raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i): RootsFileEntry => {
      let parsed: unknown
      try {
        parsed = JSON.parse(l) as unknown
      } catch {
        return die(`roots file line ${i + 1} is not valid JSON`)
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return die(`roots file line ${i + 1} is not an object`)
      }
      return parsed as RootsFileEntry
    })
}

/** Pick the published daily root that covers this proof's seq (or matches its anchorRef).
 *  Undefined if no match. */
function pickRoot(
  entries: RootsFileEntry[],
  bundle: { proof: { seq: string; anchorRef: string | null } },
): string | undefined {
  const seq = rootsDecimal(bundle.proof.seq, "bundle proof.seq")
  const byAnchor = bundle.proof.anchorRef
    ? entries.find((e) => e.anchorRef && e.anchorRef === bundle.proof.anchorRef)
    : undefined
  const bySeq = entries.find((e) => {
    if (e.seqStart == null || e.seqEnd == null) return false
    const seqStart = rootsDecimal(e.seqStart, "roots file entry seqStart")
    const seqEnd = rootsDecimal(e.seqEnd, "roots file entry seqEnd")
    return seqStart <= seq && seq <= seqEnd
  })
  return (byAnchor ?? bySeq)?.root
}

function parseParamsArg(): Record<string, unknown> {
  const raw = arg("params")
  if (!raw) return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err: unknown) {
    die(`Invalid JSON in --params: ${err instanceof Error ? err.message : String(err)}`)
  }
  // Must be a plain object: `null`, arrays and primitives would otherwise sail through the cast and
  // desync WYSIWYS — `params ?? {}` signs `{}` while the later verify call rebinds against the raw value.
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    die(`--params must be a JSON object (e.g. '{"amount":5000}')`)
  }
  // Strip potential prototype poisoning keys (__proto__, constructor, prototype)
  const cleanObj = JSON.parse(
    JSON.stringify(parsed, (key, value) => {
      if (key === "__proto__" || key === "constructor" || key === "prototype") return undefined
      return value
    }),
  )
  return cleanObj as Record<string, unknown>
}

/** Emit GitHub Actions step outputs when running in a workflow (so later steps can read nonce/url). */
function ghOutput(kv: Record<string, string>) {
  const file = process.env.GITHUB_OUTPUT
  if (!file) return
  try {
    fs.appendFileSync(
      file,
      `${Object.entries(kv)
        .map(([k, v]) => `${k}=${v}`)
        .join("\n")}\n`,
    )
  } catch {}
}

/** Poll a pending challenge to resolution, verify the receipt offline, optionally single-use consume. */
async function pollVerifyConsume(
  client: IntygaClient,
  nonce: string,
  target: string,
  actionType: string,
  params: Record<string, unknown>,
  timeoutMs: number,
  consume: boolean,
  onPending?: () => void,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  // Peek once before blocking: if policy already resolved it (Discovery Mode / pre-approval window)
  // there is nothing for a human to do — skip opening the browser and the "waiting" spinner entirely.
  let result: ApprovalResult | null = await client.status(nonce)
  if (result.status === "PENDING") {
    onPending?.() // e.g. open the approval page — only when a human actually needs to sign
    process.stdout.write("Waiting for human approval… ")
    while (result.status === "PENDING" && Date.now() < deadline) {
      process.stdout.write(".")
      await sleep(2000)
      result = await client.status(nonce)
    }
    console.log("")
  }
  if (result?.status !== "APPROVED")
    die(`Authorization failed with status: ${result ? result.status : "TIMEOUT"}`)
  if (!result.receipt) die("Gateway returned APPROVED but no signature receipt.")

  const { verifyApprovalReceipt, verificationCode } = await import("./index.js")
  const approvers = approverKeys()
  if (approvers.length === 0) {
    die(
      "no trusted approver key configured — pass --approver-key <base64> (repeatable) or set " +
        "INTYGA_APPROVER_KEYS. Verification must use a key YOU resolved; a receipt cannot vouch " +
        "for its own signer, so there is no safe default.",
    )
  }
  // Accepting a receipt that carries no human signature is an explicit, per-invocation decision.
  // `sigAlg: "AUTO_APPROVED"` is a plain receipt field, not part of the signed bytes, and the
  // verifier deliberately returns `ok: false` for it so that `if (!ok) die` blocks unsigned
  // approvals by default. Reading the `autoApproved` marker as permission to continue — which is
  // what this did — let anything that can answer the status poll authorize any action, with no
  // approver key ever consulted.
  const allowAutoApproved = process.argv.includes("--allow-auto-approved")

  // The nonce is asserted too: it binds the receipt to the challenge this call issued, so a receipt
  // for some other (equally valid) approval cannot be substituted.
  const v = verifyApprovalReceipt(
    result.receipt,
    {
      target,
      actionType,
      params,
      nonce,
      approvers: { publicKeys: approvers },
    },
    { allowAutoApproved },
  )
  // `ok` alone, always. The payload is checked before the signature, so a tampered action fails here
  // regardless of mode; and an offline approval that claims to be auto-approved stays `ok: false`
  // even under --allow-auto-approved, because that combination is a contradiction the flag must not
  // rescue.
  if (!v.ok) {
    if (v.autoApproved && !allowAutoApproved) {
      die(
        "this authorization carries NO human signature — it was auto-approved by policy " +
          "(Discovery Mode or a pre-approval window). Refusing by default. If your deployment " +
          "intends observe-only runs, re-run with --allow-auto-approved.",
      )
    }
    die(`Offline verification FAILED: ${v.reason}`)
  }
  if (v.autoApproved) {
    // Opted in above. The action is recorded and governed, but was NOT signed by a human — say so
    // loudly so it never reads as a real approval.
    console.log(
      "\x1b[33m%s\x1b[0m",
      `⚠ Policy-approved without a human signature — Discovery Mode or a pre-approval window.`,
    )
    console.log(
      "\x1b[33m%s\x1b[0m",
      `  The action was recorded and is visible in Governance, but no human signed it. Proceeding.`,
    )
  } else {
    // Derived from the canonical bytes, not read from the receipt's echoed field: this is the value
    // the operator reads back to the approver, and an echoed one is not something either side computed.
    console.log(
      "\x1b[32m%s\x1b[0m",
      `✓ Offline verification SUCCESSFUL (Code: ${verificationCode(result.receipt.canonicalPayload)})`,
    )
  }

  if (consume) {
    const c = await client.consume(nonce, { target, actionType, params })
    if (!c.ok) die(`Failed to consume authorization: ${c.reason}`)
    console.log("✓ Authorization CONSUMED.")
  }
}

/**
 * Post an interactive Slack / Teams message with the approval context and an "Approve" button that
 * deep-links to the /approve page. Run from the CALLER's CI to the CALLER's own webhook — so the rich
 * context stays in the customer's trust boundary (Intyga's own gateway webhook remains opaque).
 * Notification failures are non-fatal: the `await` step is the actual gate, not the ping.
 */
async function postNotifications(input: {
  approvalUrl: string
  context: string
  code?: string
  slack?: string
  teams?: string
}): Promise<void> {
  const codeLine = input.code ? `Verification code: \`${input.code}\`` : "Sign with your wallet or passkey."
  if (input.slack) {
    try {
      await fetch(input.slack, {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(5000),
        body: JSON.stringify({
          text: `🔒 Intyga approval required: ${input.context}`,
          blocks: [
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: `*🔒 Approval required*\n${input.context}`,
              },
            },
            {
              type: "actions",
              elements: [
                {
                  type: "button",
                  style: "primary",
                  text: { type: "plain_text", text: "Approve" },
                  url: input.approvalUrl,
                },
              ],
            },
            { type: "context", elements: [{ type: "mrkdwn", text: codeLine }] },
          ],
        }),
      })
    } catch (err) {
      console.error(`[notify:slack] ${(err as Error).message}`)
    }
  }
  if (input.teams) {
    try {
      await fetch(input.teams, {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(5000),
        body: JSON.stringify({
          "@type": "MessageCard",
          "@context": "http://schema.org/extensions",
          themeColor: "4f46e5",
          summary: "Intyga approval required",
          sections: [
            {
              activityTitle: "🔒 Intyga approval required",
              activitySubtitle: input.context,
              text: codeLine,
              markdown: true,
            },
          ],
          potentialAction: [
            {
              "@type": "OpenUri",
              name: "Approve",
              targets: [{ os: "default", uri: input.approvalUrl }],
            },
          ],
        }),
      })
    } catch (err) {
      console.error(`[notify:teams] ${(err as Error).message}`)
    }
  }
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2)
  const gatewayUrl = (arg("gateway") ?? process.env.INTYGA_GATEWAY_URL ?? "http://localhost:8787").replace(
    /\/+$/,
    "",
  )

  switch (cmd) {
    case "keygen": {
      const out = arg("out")
      if (!out) die("usage: intyga keygen --out <private-key-prefix> (private keys are never printed)")
      const kp = generateOrgKeypair()
      writePrivateFile(`${out}.public.key`, kp.publicKey)
      writePrivateFile(`${out}.private.key`, kp.privateKey)
      console.log(`wrote ${out}.public.key and ${out}.private.key`)
      console.log(
        "Upload the PUBLIC key to Intyga. Keep the PRIVATE key off Intyga — it decrypts your policies.",
      )
      return
    }
    case "policy-encrypt": {
      const manifestPath = rest.find((a) => !a.startsWith("--"))
      const pubkeyPath = arg("pubkey")
      if (!manifestPath || !pubkeyPath)
        die("usage: intyga policy-encrypt <manifest.json> --pubkey <public.key>")
      const plaintext = fs.readFileSync(manifestPath, "utf8")
      JSON.parse(plaintext) // fail fast on invalid JSON
      const pub = fs.readFileSync(pubkeyPath, "utf8").trim()
      const blob = encryptPolicy(pub, plaintext)
      const out = arg("out")
      const result = { encryptedBlob: blob, blobHash: blobHash(blob) }
      if (out) {
        fs.writeFileSync(out, JSON.stringify(result, null, 2))
        console.log(
          `wrote ${out} (encryptedBlob + blobHash) — publish these; Intyga never sees the plaintext`,
        )
      } else {
        console.log(JSON.stringify(result, null, 2))
      }
      return
    }
    case "login": {
      const did = arg("did")
      if (!did) die("usage: intyga login --did <did> [--gateway <url>]")

      console.log(`Initiating passwordless OIDC login challenge for ${did}...`)
      const reqRes = await fetch(`${gatewayUrl}/cli/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did }),
      })

      if (!reqRes.ok) {
        die(`Failed to request login challenge: ${reqRes.status} - ${await reqRes.text()}`)
      }

      // `pollSecret` is what authorises collecting the token; the gateway returns it exactly once,
      // here, and stores only its hash. Never print it — the nonce below is a correlation id and is
      // safe on screen, but this value is a bearer credential for the next two minutes.
      const { nonce, pollSecret } = (await reqRes.json()) as { nonce: string; pollSecret?: string }
      if (!pollSecret) {
        die(
          "This gateway did not issue a poll secret. It is running a build from before CLI login was " +
            "bound to the initiating process; upgrade the gateway, or upgrade this CLI to match it.",
        )
      }
      console.log(`\n------------------------------------------------------------`)
      console.log(`Challenge: ${nonce.slice(0, 8)}…`)
      console.log(`PLEASE APPROVE this login in your Intyga Wallet or Console.`)
      console.log(`------------------------------------------------------------\n`)

      console.log("Polling for biometric wallet signature...")
      const pollIntervalMs = 2000
      const maxAttempts = 60
      let attempts = 0

      while (attempts < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs))
        attempts++

        // Bearer header, not a query parameter: the gateway's access log redacts the authorization
        // header, and a secret in a URL is a secret in every log and proxy along the path.
        const checkRes = await fetch(`${gatewayUrl}/cli/login/${nonce}`, {
          headers: { authorization: `Bearer ${pollSecret}` },
        })
        if (checkRes.ok) {
          const checkData = (await checkRes.json()) as {
            status: string
            token?: string
          }
          if (checkData.status === "APPROVED" && checkData.token) {
            saveStoredToken(gatewayUrl, checkData.token)
            console.log("🎉 Successfully authenticated! Token saved to ~/.intyga/credentials.json.")
            return
          } else if (checkData.status === "DENIED" || checkData.status === "EXPIRED") {
            die(`Login request was ${checkData.status.toLowerCase()}.`)
          }
        }
      }
      die("Login timed out awaiting wallet signature.")
      return
    }
    case "authorize": {
      const actionDescription = rest.find((a) => !a.startsWith("--"))
      if (!actionDescription)
        die(
          'usage: intyga authorize "<action>" --gateway <url> --target <target> [--type <actionType>] [--params <json>] [--token <t> | --client-id <> --client-secret <>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume] [--allow-auto-approved]',
        )
      const { timeoutSec, timeoutMs } = parseTimeout(arg("timeout"))
      const params = parseParamsArg()
      const target = arg("target") ?? ""
      if (!target) die("--target is required (DIV Target Isolation): identify the executing RP / environment")

      const client = new IntygaClient({
        gatewayUrl,
        token: arg("token") ?? process.env.INTYGA_TOKEN,
        clientId: arg("client-id") ?? process.env.INTYGA_CLIENT_ID,
        clientSecret: arg("client-secret") ?? process.env.INTYGA_CLIENT_SECRET,
        allowStoredCredentials: true,
      })

      const actionType = arg("type") ?? ""

      const { nonce } = await client.authorize(actionDescription, {
        target,
        actionType,
        params,
        timeout: timeoutSec,
      })

      const webUrl = arg("web") || process.env.INTYGA_APP_URL || "http://localhost:3999"
      const approvalUrl = `${webUrl.replace(/\/+$/, "")}/approve?nonce=${nonce}`

      // Machine-readable so a CI runner can grab the deep-link and notify the approver's chat tool.
      ghOutput({ nonce, approval_url: approvalUrl })

      const printApprovalBanner = () => {
        console.log(`\n============================================================`)
        console.log(`Approval nonce: ${nonce}`)
        console.log(`Approve at:`)
        console.log(`\x1b[36m%s\x1b[0m`, approvalUrl)
        console.log(`============================================================\n`)
      }

      // --no-wait: create the challenge and hand back the deep-link immediately (don't block). The caller
      // sends the interactive notification, then blocks separately with `intyga await <nonce>`.
      if (process.argv.indexOf("--no-wait") >= 0) {
        printApprovalBanner()
        console.log(JSON.stringify({ nonce, approvalUrl }))
        process.exit(0)
      }

      // Show the approval banner + open the browser ONLY when a human actually needs to sign. In Discovery
      // Mode (and pre-approval windows) the request is already resolved, so we skip both —
      // pollVerifyConsume invokes this callback only when the challenge is still PENDING.
      const onPending = () => {
        printApprovalBanner()
        if (process.argv.indexOf("--no-open") >= 0) return
        // Open the approval URL via execFile with an argument array — never a shell command string.
        // approvalUrl embeds a server-provided nonce, and string interpolation into `exec` would let a
        // malicious/compromised gateway inject shell (e.g. `$(...)`/backticks) and run code locally.
        try {
          void import("node:child_process").then(({ execFile }) => {
            if (process.platform === "darwin") execFile("open", [approvalUrl])
            else if (process.platform === "win32") execFile("cmd", ["/c", "start", "", approvalUrl])
            else execFile("xdg-open", [approvalUrl])
          })
        } catch {}
      }

      await pollVerifyConsume(
        client,
        nonce,
        target,
        actionType,
        params,
        timeoutMs,
        process.argv.indexOf("--consume") >= 0,
        onPending,
      )
      process.exit(0)
      return
    }
    case "await": {
      const nonce = rest.find((a) => !a.startsWith("--"))
      if (!nonce)
        die(
          "usage: intyga await <nonce> --gateway <url> --target <target> [--type <t>] [--params <json>] [--timeout <s>] [--consume] [--allow-auto-approved]",
        )
      const { timeoutMs } = parseTimeout(arg("timeout"))
      const target = arg("target") ?? ""
      if (!target) die("--target is required (DIV Target Isolation): identify the executing RP / environment")
      const client = new IntygaClient({
        gatewayUrl,
        token: arg("token") ?? process.env.INTYGA_TOKEN,
        clientId: arg("client-id") ?? process.env.INTYGA_CLIENT_ID,
        clientSecret: arg("client-secret") ?? process.env.INTYGA_CLIENT_SECRET,
        allowStoredCredentials: true,
      })
      await pollVerifyConsume(
        client,
        nonce,
        target,
        arg("type") ?? "",
        parseParamsArg(),
        timeoutMs,
        process.argv.indexOf("--consume") >= 0,
      )
      process.exit(0)
      return
    }
    case "notify": {
      const approvalUrl = arg("url")
      if (!approvalUrl)
        die(
          'usage: intyga notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]',
        )
      await postNotifications({
        approvalUrl,
        context: arg("context") ?? "A high-risk action requires human approval.",
        code: arg("code"),
        slack: arg("slack") ?? process.env.INTYGA_SLACK_WEBHOOK,
        teams: arg("teams") ?? process.env.INTYGA_TEAMS_WEBHOOK,
      })
      console.log("notification sent (best-effort).")
      return
    }
    case "verify": {
      const hash = rest.find((a) => !a.startsWith("--"))
      if (!hash) die("usage: intyga verify <documentHash> --gateway <url>")
      const client = new IntygaClient({ gatewayUrl })
      console.log(JSON.stringify(await client.verify(hash), null, 2))
      return
    }
    // biome-ignore lint/suspicious/noFallthroughSwitchClause: every exit from this case is a process.exit() (type `never`), so control never reaches `default:`; Biome does not type-analyze.
    case "audit-verify": {
      // Offline, no-secret verification of an audit inclusion proof exported from the dashboard.
      // For a trustworthy verdict, supply the daily root from an independent source: --root <hex>
      // (pasted from the external anchor) or --roots <file> (the published end-of-day root list, e.g.
      // a checkout of the intyga-dev/ledger repo). Without one, the bundle is only checked against its
      // own asserted root. Exit code 0 = verified, 1 = not.
      const { verifyBundle, verifyEvidenceBundle, verifyRootsChain, EVIDENCE_BUNDLE_KIND } = await import(
        "@intyga/verify"
      )
      const bundlePath = rest.find((a) => !a.startsWith("--"))
      if (!bundlePath)
        die(
          "usage: intyga audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>] " +
            "[--trusted-issuer <a,b>] [--anchor-keys <keys.json>] [--require-anchors <n>] " +
            "[--rekor-key <pem>] [--json]\n" +
            "  Works for both single inclusion proofs and multi-entry evidence bundles.",
        )

      let bundle: import("@intyga/verify").ProofBundle
      try {
        bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8")) as import("@intyga/verify").ProofBundle
      } catch (err) {
        die(`cannot read bundle: ${err instanceof Error ? err.message : String(err)}`)
      }

      // A supplied roots file is the ROOT SOURCE for everything below, so its own integrity comes
      // first: verify the §5.4 continuity chain over the whole file before trusting any line in it.
      // A broken chain is tamper-shaped (an edited or truncated file poisons every later verdict) and
      // is fatal; a file with no chain fields at all is a legitimate hand-built minimal list, so it
      // only warns — the published file is always chained.
      const rootsPath = arg("roots")
      const rootsEntries = rootsPath ? parseRootsEntries(rootsPath) : undefined
      /** Carried into the --json output for BOTH bundle kinds: the stderr warning is invisible to a
       *  JSON consumer and to the exit code, so without this a CI pipeline cannot distinguish
       *  "chain verified over N entries" from "the file carried no chain at all". */
      let rootsChain: { ok: boolean; unchained: boolean; verifiedEntries: number } | undefined
      if (rootsEntries && rootsEntries.length > 0) {
        const chain = verifyRootsChain(rootsEntries as import("@intyga/verify").RootsChainEntry[])
        rootsChain = { ok: chain.ok, unchained: chain.unchained, verifiedEntries: chain.verifiedCount }
        if (chain.unchained) {
          console.error(
            "warning: roots file carries no §5.4 chain hashes — continuity NOT checked. (A hand-built " +
              "minimal root list is fine for a one-off lookup; the published file is always chained.)",
          )
        } else if (!chain.ok) {
          die(
            `roots file FAILED §5.4 chain verification: ${chain.reason}\n` +
              "The file may have been edited, truncated or spliced — refusing to trust any root in it. " +
              "Re-fetch it from the published source and compare copies.",
          )
        } else {
          console.error(`roots chain verified (${chain.verifiedCount} entries)`)
        }
      }

      // DEWP §5.3 anchor quorum flags apply to BOTH bundle kinds. Without --trusted-issuer the
      // verifier has no key to check an anchor signature against, so no quorum is evaluated and
      // `anchorVerified` stays false for both kinds — which the report labels honestly rather than
      // letting an out-of-band `--root` read as anchored.
      const anchorOpts = await buildAnchorOptions(
        arg("trusted-issuer"),
        arg("anchor-keys"),
        arg("require-anchors"),
        arg("rekor-key"),
      )

      // Multi-entry evidence bundle (date-range export): its own verifier + report shape.
      const bundleKind = (bundle as { kind?: string }).kind
      if (bundleKind === EVIDENCE_BUNDLE_KIND) {
        const evidence = bundle as unknown as import("@intyga/verify").EvidenceBundle
        // An evidence bundle can legitimately span several daily roots, so EVERY published root is a
        // trusted candidate — each entry still has to chain to one of them to verify.
        const root = arg("root")
        const fromFile = rootsEntries?.map((e) => e.root) ?? []
        const trustedRoots = [...new Set([...(root ? [root] : []), ...fromFile])]
        const result = verifyEvidenceBundle(evidence, {
          trustedRoots: trustedRoots.length > 0 ? trustedRoots : undefined,
          ...anchorOpts,
        })
        if (process.argv.indexOf("--json") >= 0) {
          console.log(JSON.stringify(rootsChain ? { rootsChain, ...result } : result, null, 2))
          process.exit(result.ok ? 0 : 1)
        }
        console.log(
          `Intyga evidence bundle — ${result.total} entries (${evidence.range.from} → ${evidence.range.to})`,
        )
        console.log(`  content-verified  ${result.contentVerified}`)
        console.log(
          `  commitment-only   ${result.commitmentOnly} (redacted by retention — digest verified, content removed)`,
        )
        console.log(`  failed            ${result.failed.length}`)
        for (const f of result.failed.slice(0, 20)) console.log(`    seq ${f.seq}: ${f.reason}`)
        // DEWP §9.2 Extended Profile: offline DIV signature verification, per entry. Only ES256 is
        // checkable from a leaf — see the `signatures` docs on EvidenceVerification.
        console.log(
          `  signatures        ${result.signatures.verified} verified, ${result.signatures.invalid.length} invalid, ` +
            `${result.signatures.notCheckable} not offline-checkable`,
        )
        for (const s of result.signatures.invalid.slice(0, 20)) {
          console.log(`    seq ${s.seq}: committed ES256 proof material does not verify`)
        }
        for (const r of result.roots) {
          const quorum =
            r.anchorVerified === null
              ? "unchecked"
              : r.anchorVerified
                ? `VERIFIED (${r.verifiedIssuers.join(", ")})`
                : "NOT MET"
          console.log(`  root ${r.root.slice(0, 16)}… anchor: ${r.anchorRef ?? "(none)"}  quorum: ${quorum}`)
        }
        for (const n of result.notes) console.log(`  note: ${n}`)
        console.log("")
        console.log(result.ok ? "\x1b[32mVERIFIED ✓\x1b[0m" : "\x1b[31mNOT VERIFIED ✗\x1b[0m")
        process.exit(result.ok ? 0 : 1)
      }

      const trustedRoot = arg("root") ?? (rootsEntries ? pickRoot(rootsEntries, bundle) : undefined)
      if (rootsEntries && !trustedRoot)
        console.error("warning: no matching root in the roots file for this event.")

      const result = verifyBundle(bundle, { trustedRoot, ...anchorOpts })

      if (process.argv.indexOf("--json") >= 0) {
        console.log(JSON.stringify(rootsChain ? { rootsChain, ...result } : result, null, 2))
        process.exit(result.ok ? 0 : 1)
      }
      const c = result.checks
      const m = (x: { pass: boolean | null }) =>
        x.pass === true ? "PASS" : x.pass === false ? "FAIL" : "n/a "
      console.log(`Intyga inclusion proof — seq ${bundle.proof.seq} (${bundle.event.type})`)
      console.log(`  root source     ${result.rootSource}`)
      console.log(`  [${m(c.inclusion)}] inclusion       ${c.inclusion.detail}`)
      console.log(`  [${m(c.rootConsistency)}] root match      ${c.rootConsistency.detail}`)
      console.log(`  [${m(c.leafBinding)}] leaf binding    ${c.leafBinding.detail}`)
      // A producer CLAIM, not this verifier's finding — the real check is `anchor` in the DEWP
      // property line below. Printing it as "[PASS] anchored" for self-signed-only roots was the bug.
      console.log(`  [${m(c.anchored)}] anchor claim    ${c.anchored.detail}`)
      // DEWP §7.1 property model + summary level.
      const p = result.properties
      const yn = (b: boolean) => (b ? "yes" : "no ")
      console.log(
        `  DEWP level: ${result.verificationLevel}  ` +
          `(commitment:${yn(p.commitmentVerified)} content:${yn(p.contentVerified)} ` +
          `signature:${yn(p.signatureVerified)} anchor:${yn(p.anchorVerified)})`,
      )
      for (const n of result.notes) console.log(`  note: ${n}`)
      console.log("")
      console.log(result.ok ? "\x1b[32mVERIFIED ✓\x1b[0m" : "\x1b[31mNOT VERIFIED ✗\x1b[0m")
      process.exit(result.ok ? 0 : 1)
    }
    // biome-ignore lint/suspicious/noFallthroughSwitchClause: every exit from this case is a process.exit()/die() (type `never`), so control never reaches `default:`; Biome does not type-analyze.
    case "sign": {
      // OFFLINE APPROVER TOOL (docs/DIV.md §5a). Runs with no network, by design: this is what an
      // approver uses while the gateway is unreachable.
      //
      // It refuses anything that is not a `div-offline-intent` challenge. That matters: signing an
      // ORDINARY intent payload here would mint a live approval outside the gateway's single-use
      // accounting, and signing a delegation would hand over approval authority. Both are things an
      // approver could be tricked into if this tool signed whatever it was handed.
      const envelope = rest.find((a) => !a.startsWith("--")) ?? process.env.INTYGA_CHALLENGE
      const keyPath = arg("key")
      const did = arg("did")
      if (!envelope || !keyPath || !did)
        die(
          "usage: intyga sign <DIV1:...> --key <private.pem|private.der> --did <your-did> [--yes]\n" +
            "  Reads the challenge, shows you the action, and prints a SIG1: envelope to send back.\n" +
            "  Works entirely offline — no gateway, no network.",
        )

      const decoded = decodeChallengeEnvelope(envelope)
      if (!decoded.ok || !decoded.challenge) die(decoded.reason ?? "unreadable challenge")
      const c = decoded.challenge

      // Show the human what they are authorizing, in full. An approver who signs an opaque blob has
      // not approved anything (DIV §5a.8), so this output is a security control, not decoration —
      // which is exactly why every requester-controlled field goes through `approverSafe`.
      const expiryMs = Date.parse(c.expiresAt)
      // A timestamp we cannot read is not a timestamp we can say is still valid. `NaN <= 0` is false,
      // so an unparseable expiresAt used to sail past the guard below and get signed (DIV §6.2).
      if (!Number.isFinite(expiryMs)) die("expiresAt is not a valid RFC3339 timestamp — refusing to sign")
      const expiresIn = Math.round((expiryMs - Date.now()) / 1000)
      console.log("")
      console.log("\x1b[1mOFFLINE APPROVAL REQUEST\x1b[0m")
      console.log("")
      console.log(`  Action     ${approverSafe(c.display)}`)
      console.log(`  Type       ${approverSafe(c.actionType)}`)
      console.log(`  Target     ${approverSafe(c.target)}`)
      console.log(`  Params     ${approverSafe(JSON.stringify(c.params))}`)
      console.log(`  Requested  ${approverSafe(c.requester?.did ?? "(unknown)")}`)
      console.log(`  Quorum     ${c.requirement?.requiredApprovals ?? "?"} approver(s) required`)
      console.log(`  Expires    ${approverSafe(c.expiresAt)}  (${expiresIn}s from now)`)
      console.log("")
      console.log(`  \x1b[1mVerification code: ${approverSafe(c.verificationCode)}\x1b[0m`)
      console.log("  Read this back to the operator. If it does not match their screen, STOP.")
      console.log("")
      if (expiresIn <= 0) die("this challenge has already expired — ask for a fresh one")

      if (arg("yes") === undefined && !process.argv.includes("--yes")) {
        // Interactive confirmation on purpose. The whole value of this mechanism is that a human looks
        // at the actual incident, so the default path makes them type something.
        const answer = await new Promise<string>((resolve) => {
          process.stdout.write("Sign this approval? [y/N] ")
          process.stdin.setEncoding("utf8")
          process.stdin.once("data", (d) => resolve(String(d).trim().toLowerCase()))
        })
        if (answer !== "y" && answer !== "yes") {
          console.log("Not signed.")
          process.exit(1)
        }
      }

      const raw = fs.readFileSync(keyPath)
      let privateKey: crypto.KeyObject
      try {
        // Accept a PEM or a raw DER PKCS#8 — an approver's key comes from wherever they keep it.
        privateKey = raw.includes("-----BEGIN")
          ? crypto.createPrivateKey(raw.toString("utf8"))
          : crypto.createPrivateKey({ key: raw, format: "der", type: "pkcs8" })
      } catch (err) {
        die(`could not read the private key: ${(err as Error).message}`)
      }
      const signature = crypto
        .sign("sha256", Buffer.from(c.canonicalPayload, "utf8"), {
          key: privateKey,
          dsaEncoding: "ieee-p1363",
        })
        .toString("base64")
      // Derived via PEM rather than by passing the private KeyObject straight in: createPublicKey
      // accepts one at runtime, but @types/node does not declare that overload.
      const publicKey = crypto
        .createPublicKey(privateKey.export({ format: "pem", type: "pkcs8" }) as string)
        .export({ format: "der", type: "spki" })
        .toString("base64")

      console.log("")
      console.log("Send this back to the operator:")
      console.log("")
      console.log(
        encodeSignatureEnvelope({
          signerDid: did,
          signerPublicKey: publicKey,
          signature,
          sigAlg: "ES256",
        }),
      )
      console.log("")
      process.exit(0)
    }
    // biome-ignore lint/suspicious/noFallthroughSwitchClause: every exit from this case is a process.exit()/die() (type `never`), so control never reaches `default:`; Biome does not type-analyze.
    case "trust-bundle": {
      // Export (online) or inspect (offline) the trust bundle that makes offline approval possible.
      const sub = rest.find((a) => !a.startsWith("--"))
      const dir = arg("dir") ?? ".intyga-offline"
      if (sub === "export") {
        const tenantId = arg("tenant")
        if (!tenantId)
          die(
            "usage: intyga trust-bundle export --tenant <uuid> (INTYGA_INTERNAL_TOKEN | --token-file <0600-file> | --token-stdin) [--dir <dir>] [--gateway <url>]",
          )
        const token = internalToken()
        const res = await fetch(`${gatewayUrl}/trust-bundle/export`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: JSON.stringify({ tenantId }),
        })
        const out = (await res.json()) as {
          ok?: boolean
          reason?: string
          jws?: string
          gatewayJwk?: JsonWebKey
        }
        if (!res.ok || !out.ok || !out.jws || !out.gatewayJwk)
          die(out.reason ?? `export failed (${res.status})`)
        saveTrustBundle(dir, { jws: out.jws, gatewayJwk: out.gatewayJwk })
        console.log(`wrote ${dir}/trust-bundle.jws and ${dir}/gateway-key.jwk.json`)
        console.log(
          "Keep these where your service can read them BEFORE an outage — it cannot fetch them during one.",
        )
        process.exit(0)
      }
      if (sub === "show") {
        const loaded = loadTrustBundle(dir)
        if (!loaded.ok || !loaded.bundle) die(loaded.reason ?? "could not load the bundle")
        console.log(JSON.stringify(loaded.bundle, null, 2))
        process.exit(0)
      }
      die("usage: intyga trust-bundle <export|show> [--dir <dir>]")
    }
    default:
      console.log(
        [
          "Intyga CLI",
          "",
          "Commands:",
          "  intyga keygen --out <prefix>",
          "  intyga policy-encrypt <manifest.json> --pubkey <public.key> [--out <blob.json>]",
          "  intyga login --did <did> [--gateway <url>]",
          '  intyga authorize "<action>" --gateway <url> (--token <t> | --client-id <> --client-secret <>) [--type <actionType>] [--params <json>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume] [--allow-auto-approved]',
          "  intyga await <nonce> --gateway <url> [--type <t>] [--params <json>] [--timeout <s>] [--consume] [--allow-auto-approved]",
          "",
          "  `authorize` and `await` verify the approval receipt offline and REQUIRE the approver keys",
          "  you trust — the receipt's own key is never used, or it would vouch for its own signer:",
          "    --approver-key <base64>   repeatable; base64 SPKI (raw P-256) or base64 COSE (passkey)",
          "    INTYGA_APPROVER_KEYS      comma-separated, same values",
          '  intyga notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]',
          "  intyga verify <documentHash> --gateway <url>",
          "",
          "  Offline approval (docs/DIV.md §5a) — for when the gateway is unreachable:",
          "  intyga trust-bundle export --tenant <uuid> (INTYGA_INTERNAL_TOKEN | --token-file <0600-file> | --token-stdin) [--dir <dir>] [--gateway <url>]",
          "  intyga trust-bundle show [--dir <dir>]",
          "  intyga sign <DIV1:...> --key <private.pem> --did <your-did> [--yes]",
          "",
          "  `trust-bundle export` is run BEFORE an outage: it stores your approvers' public keys and",
          "  the approval policy, signed, so a service can verify offline. `sign` is run DURING one, by",
          "  an approver, with no network at all — it shows the action and a verification code you must",
          "  read back to the operator before signing.",
          "  intyga audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>]",
          "                     [--trusted-issuer <a,b>] [--anchor-keys <keys.json>] [--require-anchors <n>]",
          "                     [--rekor-key <sigstore-log-key.pem>] [--json]",
          "",
          "  A Rekor anchor is checked against Sigstore's LOG key (--rekor-key), not --anchor-keys:",
          "  it carries no DEWP signature, only its Signed Entry Timestamp. Without that key it",
          "  cannot be verified and does NOT count toward quorum. Take the key from Sigstore's TUF",
          "  root — never from the bundle you are checking.",
        ].join("\n"),
      )
      process.exit(cmd ? 1 : 0)
  }
}

main().catch((err) => die((err as Error).message))
