#!/usr/bin/env node
import crypto from "node:crypto"
import fs from "node:fs"
// Paths come from the SDK so this writer and the `token()` reader can never drift apart.
import { type ApprovalResult, CREDENTIALS_FILE, SAKRA_DIR, SakraClient } from "./index.js"
import { blobHash, encryptPolicy, generateOrgKeypair } from "./policy.js"

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 ? process.argv[i + 1] : undefined
}

function die(msg: string): never {
  console.error(`error: ${msg}`)
  process.exit(1)
}

function parseTimeout(val: string | undefined): { timeoutSec?: number; timeoutMs: number } {
  if (!val) return { timeoutMs: 120_000 }
  const num = Number(val)
  if (!Number.isFinite(num) || num <= 0) {
    die(`Invalid --timeout value: "${val}". Must be a positive number of seconds.`)
  }
  return { timeoutSec: num, timeoutMs: Math.round(num * 1000) }
}

/** Best-effort permission tightening — `chmod` throws on Windows/exotic filesystems and must never
 *  break `sakra login`. The `mode` options on mkdir/writeFile are no-ops when the target already
 *  exists, so these calls are also what repairs a 0644 credentials file from an earlier install. */
function restrictPermissions(target: string, mode: number) {
  try {
    fs.chmodSync(target, mode)
  } catch {}
}

function saveStoredToken(gatewayUrl: string, token: string) {
  if (!fs.existsSync(SAKRA_DIR)) {
    fs.mkdirSync(SAKRA_DIR, { recursive: true, mode: 0o700 })
  }
  restrictPermissions(SAKRA_DIR, 0o700)
  let data: Record<string, string> = {}
  if (fs.existsSync(CREDENTIALS_FILE)) {
    try {
      data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8")) as Record<string, string>
    } catch {}
  }
  data[gatewayUrl] = token
  // This file holds a live bearer token — never leave it at the default umask (0644) on a shared host.
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(data, null, 2), { encoding: "utf-8", mode: 0o600 })
  restrictPermissions(CREDENTIALS_FILE, 0o600)
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
 * quorum. Supplying neither is not an error: the verifier then reports `anchorVerified` on the weaker
 * "independent root supplied" basis, and says so, rather than pretending a quorum was evaluated.
 */
async function buildAnchorOptions(
  trustedIssuers: string | undefined,
  anchorKeysFile: string | undefined,
  requireAnchors: string | undefined,
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

  return {
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

/** Pick the published daily root that covers this proof's seq (or matches its anchorRef), from a JSONL
 *  roots file (e.g. a checkout of sakra-trust/ledger's roots/roots.jsonl). Undefined if no file/match. */
function resolveRootFromFile(
  rootsPath: string | undefined,
  bundle: { proof: { seq: string; anchorRef: string | null } },
): string | undefined {
  if (!rootsPath) return undefined
  let raw: string
  try {
    raw = fs.readFileSync(rootsPath, "utf8")
  } catch (err) {
    die(`cannot read roots file: ${err instanceof Error ? err.message : String(err)}`)
  }
  const entries = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map(
      (l) =>
        JSON.parse(l) as {
          seqStart?: string
          seqEnd?: string
          root: string
          anchorRef?: string
        },
    )
  const seq = BigInt(bundle.proof.seq)
  const byAnchor = bundle.proof.anchorRef
    ? entries.find((e) => e.anchorRef && e.anchorRef === bundle.proof.anchorRef)
    : undefined
  const bySeq = entries.find(
    (e) => e.seqStart != null && e.seqEnd != null && BigInt(e.seqStart) <= seq && seq <= BigInt(e.seqEnd),
  )
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
  client: SakraClient,
  nonce: string,
  target: string,
  actionType: string,
  params: Record<string, unknown>,
  timeoutMs: number,
  consume: boolean,
  onPending?: () => void,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  // Peek once before blocking: if policy already resolved it (Discovery Mode / break-glass / pre-approval)
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

  const { verifyApprovalReceipt } = await import("./index.js")
  // The nonce is asserted too: it binds the receipt to the challenge this call issued, so a receipt
  // for some other (equally valid) approval cannot be substituted.
  const v = verifyApprovalReceipt(result.receipt, { target, actionType, params, nonce })
  // The payload is always checked first, so a tampered action still fails here regardless of mode.
  if (!v.ok && !v.autoApproved) die(`Offline verification FAILED: ${v.reason}`)
  if (v.autoApproved) {
    // Policy let this through with NO human signature — Discovery Mode (observe-only) or a break-glass /
    // pre-approval window. The action is recorded and governed, but was NOT signed by a human. We proceed
    // (that is the point of observe-mode) but say so loudly so it never reads as a real approval.
    console.log(
      "\x1b[33m%s\x1b[0m",
      `⚠ Policy-approved without a human signature — Discovery Mode or a break-glass window.`,
    )
    console.log(
      "\x1b[33m%s\x1b[0m",
      `  The action was recorded and is visible in Governance, but no human signed it. Proceeding.`,
    )
  } else {
    console.log(
      "\x1b[32m%s\x1b[0m",
      `✓ Offline verification SUCCESSFUL (Code: ${result.receipt.verificationCode})`,
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
 * context stays in the customer's trust boundary (SÄKRA's own gateway webhook remains opaque).
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
          text: `🔒 SÄKRA approval required: ${input.context}`,
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
          summary: "SÄKRA approval required",
          sections: [
            {
              activityTitle: "🔒 SÄKRA approval required",
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
  const gatewayUrl = (arg("gateway") ?? process.env.SAKRA_GATEWAY_URL ?? "http://localhost:8787").replace(
    /\/+$/,
    "",
  )

  switch (cmd) {
    case "keygen": {
      const kp = generateOrgKeypair()
      const out = arg("out")
      if (out) {
        fs.writeFileSync(`${out}.public.key`, kp.publicKey)
        fs.writeFileSync(`${out}.private.key`, kp.privateKey)
        console.log(`wrote ${out}.public.key and ${out}.private.key`)
        console.log(
          "Upload the PUBLIC key to SÄKRA. Keep the PRIVATE key off SÄKRA — it decrypts your policies.",
        )
      } else {
        console.log(JSON.stringify(kp, null, 2))
        console.error("\nKeep the private key secret — SÄKRA must never receive it.")
      }
      return
    }
    case "policy-encrypt": {
      const manifestPath = rest.find((a) => !a.startsWith("--"))
      const pubkeyPath = arg("pubkey")
      if (!manifestPath || !pubkeyPath)
        die("usage: sakra policy-encrypt <manifest.json> --pubkey <public.key>")
      const plaintext = fs.readFileSync(manifestPath, "utf8")
      JSON.parse(plaintext) // fail fast on invalid JSON
      const pub = fs.readFileSync(pubkeyPath, "utf8").trim()
      const blob = encryptPolicy(pub, plaintext)
      const out = arg("out")
      const result = { encryptedBlob: blob, blobHash: blobHash(blob) }
      if (out) {
        fs.writeFileSync(out, JSON.stringify(result, null, 2))
        console.log(`wrote ${out} (encryptedBlob + blobHash) — publish these; SÄKRA never sees the plaintext`)
      } else {
        console.log(JSON.stringify(result, null, 2))
      }
      return
    }
    case "login": {
      const did = arg("did")
      if (!did) die("usage: sakra login --did <did> [--gateway <url>]")

      console.log(`Initiating passwordless OIDC login challenge for ${did}...`)
      const reqRes = await fetch(`${gatewayUrl}/cli/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did }),
      })

      if (!reqRes.ok) {
        die(`Failed to request login challenge: ${reqRes.status} - ${await reqRes.text()}`)
      }

      const { nonce } = (await reqRes.json()) as { nonce: string }
      console.log(`\n------------------------------------------------------------`)
      console.log(`Challenge Nonce: ${nonce}`)
      console.log(`PLEASE APPROVE this login in your SÄKRA Wallet or Console.`)
      console.log(`------------------------------------------------------------\n`)

      console.log("Polling for biometric wallet signature...")
      const pollIntervalMs = 2000
      const maxAttempts = 60
      let attempts = 0

      while (attempts < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs))
        attempts++

        const checkRes = await fetch(`${gatewayUrl}/cli/login/${nonce}`)
        if (checkRes.ok) {
          const checkData = (await checkRes.json()) as {
            status: string
            token?: string
          }
          if (checkData.status === "APPROVED" && checkData.token) {
            saveStoredToken(gatewayUrl, checkData.token)
            console.log("🎉 Successfully authenticated! Token saved to ~/.sakra/credentials.json.")
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
          'usage: sakra authorize "<action>" --gateway <url> --target <target> [--type <actionType>] [--params <json>] [--token <t> | --client-id <> --client-secret <>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume]',
        )
      const { timeoutSec, timeoutMs } = parseTimeout(arg("timeout"))
      const params = parseParamsArg()
      const target = arg("target") ?? ""
      if (!target) die("--target is required (DIV Target Isolation): identify the executing RP / environment")

      const client = new SakraClient({
        gatewayUrl,
        token: arg("token") ?? process.env.SAKRA_TOKEN,
        clientId: arg("client-id") ?? process.env.SAKRA_CLIENT_ID,
        clientSecret: arg("client-secret") ?? process.env.SAKRA_CLIENT_SECRET,
        allowStoredCredentials: true,
      })

      const actionType = arg("type") ?? ""

      const { nonce } = await client.authorize(actionDescription, {
        target,
        actionType,
        params,
        timeout: timeoutSec,
      })

      const webUrl = arg("web") || process.env.SAKRA_APP_URL || "http://localhost:3999"
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
      // sends the interactive notification, then blocks separately with `sakra await <nonce>`.
      if (process.argv.indexOf("--no-wait") >= 0) {
        printApprovalBanner()
        console.log(JSON.stringify({ nonce, approvalUrl }))
        process.exit(0)
      }

      // Show the approval banner + open the browser ONLY when a human actually needs to sign. In Discovery
      // Mode (and break-glass / pre-approval windows) the request is already resolved, so we skip both —
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
          "usage: sakra await <nonce> --gateway <url> --target <target> [--type <t>] [--params <json>] [--timeout <s>] [--consume]",
        )
      const { timeoutMs } = parseTimeout(arg("timeout"))
      const target = arg("target") ?? ""
      if (!target) die("--target is required (DIV Target Isolation): identify the executing RP / environment")
      const client = new SakraClient({
        gatewayUrl,
        token: arg("token") ?? process.env.SAKRA_TOKEN,
        clientId: arg("client-id") ?? process.env.SAKRA_CLIENT_ID,
        clientSecret: arg("client-secret") ?? process.env.SAKRA_CLIENT_SECRET,
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
          'usage: sakra notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]',
        )
      await postNotifications({
        approvalUrl,
        context: arg("context") ?? "A high-risk action requires human approval.",
        code: arg("code"),
        slack: arg("slack") ?? process.env.SAKRA_SLACK_WEBHOOK,
        teams: arg("teams") ?? process.env.SAKRA_TEAMS_WEBHOOK,
      })
      console.log("notification sent (best-effort).")
      return
    }
    case "verify": {
      const hash = rest.find((a) => !a.startsWith("--"))
      if (!hash) die("usage: sakra verify <documentHash> --gateway <url>")
      const client = new SakraClient({ gatewayUrl })
      console.log(JSON.stringify(await client.verify(hash), null, 2))
      return
    }
    // biome-ignore lint/suspicious/noFallthroughSwitchClause: every exit from this case is a process.exit() (type `never`), so control never reaches `default:`; Biome does not type-analyze.
    case "audit-verify": {
      // Offline, no-secret verification of an audit inclusion proof exported from the dashboard.
      // For a trustworthy verdict, supply the daily root from an independent source: --root <hex>
      // (pasted from the external anchor) or --roots <file> (the published end-of-day root list, e.g.
      // a checkout of the sakra-trust/ledger repo). Without one, the bundle is only checked against its
      // own asserted root. Exit code 0 = verified, 1 = not.
      const { verifyBundle, verifyEvidenceBundle, EVIDENCE_BUNDLE_KIND, EVIDENCE_BUNDLE_KIND_ALIASES } =
        await import("@sakra-trust/verify")
      const bundlePath = rest.find((a) => !a.startsWith("--"))
      if (!bundlePath)
        die(
          "usage: sakra audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>] " +
            "[--trusted-issuer <a,b>] [--anchor-keys <keys.json>] [--require-anchors <n>] [--json]",
        )

      let bundle: import("@sakra-trust/verify").ProofBundle
      try {
        bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8")) as import("@sakra-trust/verify").ProofBundle
      } catch (err) {
        die(`cannot read bundle: ${err instanceof Error ? err.message : String(err)}`)
      }

      // Multi-entry evidence bundle (date-range export): its own verifier + report shape. Accept the
      // canonical dewp.* kind and its legacy sakra.* alias (DEWP §6.5).
      const bundleKind = (bundle as { kind?: string }).kind
      if (bundleKind === EVIDENCE_BUNDLE_KIND || EVIDENCE_BUNDLE_KIND_ALIASES.includes(bundleKind as never)) {
        const evidence = bundle as unknown as import("@sakra-trust/verify").EvidenceBundle
        const root = arg("root")
        const rootArgs = root ? [root] : undefined
        const result = verifyEvidenceBundle(evidence, {
          trustedRoots: rootArgs,
        })
        if (process.argv.indexOf("--json") >= 0) {
          console.log(JSON.stringify(result, null, 2))
          process.exit(result.ok ? 0 : 1)
        }
        console.log(
          `SÄKRA evidence bundle — ${result.total} entries (${evidence.range.from} → ${evidence.range.to})`,
        )
        console.log(`  content-verified  ${result.contentVerified}`)
        console.log(
          `  commitment-only   ${result.commitmentOnly} (redacted by retention — digest verified, content removed)`,
        )
        console.log(`  failed            ${result.failed.length}`)
        for (const f of result.failed.slice(0, 20)) console.log(`    seq ${f.seq}: ${f.reason}`)
        for (const r of result.roots)
          console.log(`  root ${r.root.slice(0, 16)}… anchor: ${r.anchorRef ?? "(none)"}`)
        for (const n of result.notes) console.log(`  note: ${n}`)
        console.log("")
        console.log(result.ok ? "\x1b[32mVERIFIED ✓\x1b[0m" : "\x1b[31mNOT VERIFIED ✗\x1b[0m")
        process.exit(result.ok ? 0 : 1)
      }

      const trustedRoot = arg("root") ?? resolveRootFromFile(arg("roots"), bundle)
      if (arg("roots") && !trustedRoot)
        console.error("warning: no matching root in the roots file for this event.")

      // DEWP §5.3 anchor quorum. Without --trusted-issuer the verifier has no key to check an anchor
      // signature against, so `anchorVerified` falls back to the weaker "an independent root was
      // handed to me" signal — which the report labels honestly rather than calling it anchored.
      const anchorOpts = await buildAnchorOptions(
        arg("trusted-issuer"),
        arg("anchor-keys"),
        arg("require-anchors"),
      )
      const result = verifyBundle(bundle, { trustedRoot, ...anchorOpts })

      if (process.argv.indexOf("--json") >= 0) {
        console.log(JSON.stringify(result, null, 2))
        process.exit(result.ok ? 0 : 1)
      }
      const c = result.checks
      const m = (x: { pass: boolean | null }) =>
        x.pass === true ? "PASS" : x.pass === false ? "FAIL" : "n/a "
      console.log(`SÄKRA inclusion proof — seq ${bundle.proof.seq} (${bundle.event.type})`)
      console.log(`  root source     ${result.rootSource}`)
      console.log(`  [${m(c.inclusion)}] inclusion       ${c.inclusion.detail}`)
      console.log(`  [${m(c.rootConsistency)}] root match      ${c.rootConsistency.detail}`)
      console.log(`  [${m(c.leafBinding)}] leaf binding    ${c.leafBinding.detail}`)
      console.log(`  [${m(c.anchored)}] anchored        ${c.anchored.detail}`)
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
    default:
      console.log(
        [
          "SÄKRA CLI",
          "",
          "Commands:",
          "  sakra keygen [--out <prefix>]",
          "  sakra policy-encrypt <manifest.json> --pubkey <public.key> [--out <blob.json>]",
          "  sakra login --did <did> [--gateway <url>]",
          '  sakra authorize "<action>" --gateway <url> (--token <t> | --client-id <> --client-secret <>) [--type <actionType>] [--params <json>] [--timeout <s>] [--web <appUrl>] [--no-wait] [--no-open] [--consume]',
          "  sakra await <nonce> --gateway <url> [--type <t>] [--params <json>] [--timeout <s>] [--consume]",
          '  sakra notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]',
          "  sakra verify <documentHash> --gateway <url>",
          "  sakra audit-verify <bundle.json> [--root <hex> | --roots <roots.jsonl>]",
          "                     [--trusted-issuer <a,b>] [--anchor-keys <keys.json>] [--require-anchors <n>] [--json]",
        ].join("\n"),
      )
      process.exit(cmd ? 1 : 0)
  }
}

main().catch((err) => die((err as Error).message))
