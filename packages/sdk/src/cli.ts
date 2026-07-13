#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { SakraClient, type ApprovalResult } from "./index.js";
import { generateOrgKeypair, encryptPolicy, blobHash } from "./policy.js";

const SAKRA_DIR = path.join(os.homedir(), ".sakra");
const CREDENTIALS_FILE = path.join(SAKRA_DIR, "credentials.json");

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function die(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function saveStoredToken(gatewayUrl: string, token: string) {
  if (!fs.existsSync(SAKRA_DIR)) {
    fs.mkdirSync(SAKRA_DIR, { recursive: true });
  }
  let data: Record<string, string> = {};
  if (fs.existsSync(CREDENTIALS_FILE)) {
    try {
      data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8")) as Record<string, string>;
    } catch {}
  }
  data[gatewayUrl] = token;
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(data, null, 2), "utf-8");
}

function signPayload(privateKeyB64: string, payload: string): string {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const sign = crypto.createSign("sha256");
  sign.update(payload);
  return sign.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function parseParamsArg(): Record<string, unknown> {
  const raw = arg("params");
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch (err: unknown) {
    die(`Invalid JSON in --params: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Emit GitHub Actions step outputs when running in a workflow (so later steps can read nonce/url). */
function ghOutput(kv: Record<string, string>) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  try {
    fs.appendFileSync(file, Object.entries(kv).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
  } catch {}
}

/** Poll a pending challenge to resolution, verify the receipt offline, optionally single-use consume. */
async function pollVerifyConsume(
  client: SakraClient,
  nonce: string,
  actionType: string,
  params: Record<string, unknown>,
  timeoutMs: number,
  consume: boolean,
  onPending?: () => void,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  // Peek once before blocking: if policy already resolved it (Discovery Mode / break-glass / pre-approval)
  // there is nothing for a human to do — skip opening the browser and the "waiting" spinner entirely.
  let result: ApprovalResult | null = await client.status(nonce);
  if (result.status === "PENDING") {
    onPending?.(); // e.g. open the approval page — only when a human actually needs to sign
    process.stdout.write("Waiting for human approval… ");
    while (result.status === "PENDING" && Date.now() < deadline) {
      process.stdout.write(".");
      await sleep(2000);
      result = await client.status(nonce);
    }
    console.log("");
  }
  if (!result || result.status !== "APPROVED") die(`Authorization failed with status: ${result ? result.status : "TIMEOUT"}`);
  if (!result.receipt) die("Gateway returned APPROVED but no signature receipt.");

  const { verifyApprovalReceipt } = await import("./index.js");
  const v = verifyApprovalReceipt(result.receipt, { actionType, params });
  // The payload is always checked first, so a tampered action still fails here regardless of mode.
  if (!v.ok && !v.autoApproved) die(`Offline verification FAILED: ${v.reason}`);
  if (v.autoApproved) {
    // Policy let this through with NO human signature — Discovery Mode (observe-only) or a break-glass /
    // pre-approval window. The action is recorded and governed, but was NOT signed by a human. We proceed
    // (that is the point of observe-mode) but say so loudly so it never reads as a real approval.
    console.log("\x1b[33m%s\x1b[0m", `⚠ Policy-approved without a human signature — Discovery Mode or a break-glass window.`);
    console.log("\x1b[33m%s\x1b[0m", `  The action was recorded and is visible in Governance, but no human signed it. Proceeding.`);
  } else {
    console.log("\x1b[32m%s\x1b[0m", `✓ Offline verification SUCCESSFUL (Code: ${result.receipt.verificationCode})`);
  }

  if (consume) {
    const c = await client.consume(nonce, { actionType, params });
    if (!c.ok) die(`Failed to consume authorization: ${c.reason}`);
    console.log("✓ Authorization CONSUMED.");
  }
}

/**
 * Post an interactive Slack / Teams message with the approval context and an "Approve" button that
 * deep-links to the /approve page. Run from the CALLER's CI to the CALLER's own webhook — so the rich
 * context stays in the customer's trust boundary (SÄKRA's own gateway webhook remains opaque).
 * Notification failures are non-fatal: the `await` step is the actual gate, not the ping.
 */
async function postNotifications(input: {
  approvalUrl: string;
  context: string;
  code?: string;
  slack?: string;
  teams?: string;
}): Promise<void> {
  const codeLine = input.code ? `Verification code: \`${input.code}\`` : "Sign with your wallet or passkey.";
  if (input.slack) {
    try {
      await fetch(input.slack, {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(5000),
        body: JSON.stringify({
          text: `🔒 SÄKRA approval required: ${input.context}`,
          blocks: [
            { type: "section", text: { type: "mrkdwn", text: `*🔒 Approval required*\n${input.context}` } },
            { type: "actions", elements: [{ type: "button", style: "primary", text: { type: "plain_text", text: "Approve" }, url: input.approvalUrl }] },
            { type: "context", elements: [{ type: "mrkdwn", text: codeLine }] },
          ],
        }),
      });
    } catch (err) {
      console.error(`[notify:slack] ${(err as Error).message}`);
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
          sections: [{ activityTitle: "🔒 SÄKRA approval required", activitySubtitle: input.context, text: codeLine, markdown: true }],
          potentialAction: [{ "@type": "OpenUri", name: "Approve", targets: [{ os: "default", uri: input.approvalUrl }] }],
        }),
      });
    } catch (err) {
      console.error(`[notify:teams] ${(err as Error).message}`);
    }
  }
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const gatewayUrl = (arg("gateway") ?? process.env.SAKRA_GATEWAY_URL ?? "http://localhost:8787").replace(/\/+$/, "");

  switch (cmd) {
    case "keygen": {
      const kp = generateOrgKeypair();
      const out = arg("out");
      if (out) {
        fs.writeFileSync(`${out}.public.key`, kp.publicKey);
        fs.writeFileSync(`${out}.private.key`, kp.privateKey);
        console.log(`wrote ${out}.public.key and ${out}.private.key`);
        console.log("Upload the PUBLIC key to SÄKRA. Keep the PRIVATE key off SÄKRA — it decrypts your policies.");
      } else {
        console.log(JSON.stringify(kp, null, 2));
        console.error("\nKeep the private key secret — SÄKRA must never receive it.");
      }
      return;
    }
    case "policy-encrypt": {
      const manifestPath = rest.find((a) => !a.startsWith("--"));
      const pubkeyPath = arg("pubkey");
      if (!manifestPath || !pubkeyPath) die("usage: sakra policy-encrypt <manifest.json> --pubkey <public.key>");
      const plaintext = fs.readFileSync(manifestPath, "utf8");
      JSON.parse(plaintext); // fail fast on invalid JSON
      const pub = fs.readFileSync(pubkeyPath, "utf8").trim();
      const blob = encryptPolicy(pub, plaintext);
      const out = arg("out");
      const result = { encryptedBlob: blob, blobHash: blobHash(blob) };
      if (out) {
        fs.writeFileSync(out, JSON.stringify(result, null, 2));
        console.log(`wrote ${out} (encryptedBlob + blobHash) — publish these; SÄKRA never sees the plaintext`);
      } else {
        console.log(JSON.stringify(result, null, 2));
      }
      return;
    }
    case "login": {
      const did = arg("did");
      if (!did) die("usage: sakra login --did <did> [--gateway <url>]");

      console.log(`Initiating passwordless OIDC login challenge for ${did}...`);
      const reqRes = await fetch(`${gatewayUrl}/cli/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did }),
      });

      if (!reqRes.ok) {
        die(`Failed to request login challenge: ${reqRes.status} - ${await reqRes.text()}`);
      }

      const { nonce } = await reqRes.json() as { nonce: string };
      console.log(`\n------------------------------------------------------------`);
      console.log(`Challenge Nonce: ${nonce}`);
      console.log(`PLEASE APPROVE this login in your SÄKRA Wallet or Console.`);
      console.log(`------------------------------------------------------------\n`);

      console.log("Polling for biometric wallet signature...");
      const pollIntervalMs = 2000;
      const maxAttempts = 60;
      let attempts = 0;

      while (attempts < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
        attempts++;

        const checkRes = await fetch(`${gatewayUrl}/cli/login/${nonce}`);
        if (checkRes.ok) {
          const checkData = await checkRes.json() as { status: string; token?: string };
          if (checkData.status === "APPROVED" && checkData.token) {
            saveStoredToken(gatewayUrl, checkData.token);
            console.log("🎉 Successfully authenticated! Token saved to ~/.sakra/credentials.json.");
            return;
          } else if (checkData.status === "DENIED" || checkData.status === "EXPIRED") {
            die(`Login request was ${checkData.status.toLowerCase()}.`);
          }
        }
      }
      die("Login timed out awaiting wallet signature.");
      return;
    }
    case "authorize": {
      const actionDescription = rest.find((a) => !a.startsWith("--"));
      if (!actionDescription) die('usage: sakra authorize "<action>" --gateway <url> [--type <actionType>] [--params <json>] [--token <t> | --client-id <> --client-secret <>] [--web <appUrl>] [--consume]');
      
      const client = new SakraClient({
        gatewayUrl,
        // Prefer env for credentials so secrets never sit on the command line (visible in process
        // listings / CI logs). Flags remain for local convenience.
        token: arg("token") ?? process.env.SAKRA_TOKEN,
        clientId: arg("client-id") ?? process.env.SAKRA_CLIENT_ID,
        clientSecret: arg("client-secret") ?? process.env.SAKRA_CLIENT_SECRET,
      });

      const actionType = arg("type") ?? "";
      const params = parseParamsArg();
      const timeoutVal = arg("timeout");
      const timeoutMs = timeoutVal ? Number(timeoutVal) * 1000 : 120_000;

      const { nonce } = await client.authorize(actionDescription, { actionType, params, timeout: timeoutVal ? Number(timeoutVal) : undefined });

      const webUrl = arg("web") || process.env.SAKRA_APP_URL || "http://localhost:3999";
      const approvalUrl = `${webUrl.replace(/\/+$/, "")}/approve?nonce=${nonce}`;

      // Machine-readable so a CI runner can grab the deep-link and notify the approver's chat tool.
      ghOutput({ nonce, approval_url: approvalUrl });

      const printApprovalBanner = () => {
        console.log(`\n============================================================`);
        console.log(`Approval nonce: ${nonce}`);
        console.log(`Approve at:`);
        console.log(`\x1b[36m%s\x1b[0m`, approvalUrl);
        console.log(`============================================================\n`);
      };

      // --no-wait: create the challenge and hand back the deep-link immediately (don't block). The caller
      // sends the interactive notification, then blocks separately with `sakra await <nonce>`.
      if (process.argv.indexOf("--no-wait") >= 0) {
        printApprovalBanner();
        console.log(JSON.stringify({ nonce, approvalUrl }));
        process.exit(0);
      }

      // Show the approval banner + open the browser ONLY when a human actually needs to sign. In Discovery
      // Mode (and break-glass / pre-approval windows) the request is already resolved, so we skip both —
      // pollVerifyConsume invokes this callback only when the challenge is still PENDING.
      const onPending = () => {
        printApprovalBanner();
        if (process.argv.indexOf("--no-open") >= 0) return;
        const openCmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
        try {
          void import("node:child_process").then(({ exec }) => exec(`${openCmd} "${approvalUrl}"`));
        } catch {}
      };

      await pollVerifyConsume(client, nonce, actionType, params, timeoutMs, process.argv.indexOf("--consume") >= 0, onPending);
      process.exit(0);
      return;
    }
    case "await": {
      const nonce = rest.find((a) => !a.startsWith("--"));
      if (!nonce) die('usage: sakra await <nonce> --gateway <url> [--type <t>] [--params <json>] [--timeout <s>] [--consume]');
      const client = new SakraClient({
        gatewayUrl,
        token: arg("token") ?? process.env.SAKRA_TOKEN,
        clientId: arg("client-id") ?? process.env.SAKRA_CLIENT_ID,
        clientSecret: arg("client-secret") ?? process.env.SAKRA_CLIENT_SECRET,
      });
      const timeoutVal = arg("timeout");
      await pollVerifyConsume(
        client,
        nonce,
        arg("type") ?? "",
        parseParamsArg(),
        timeoutVal ? Number(timeoutVal) * 1000 : 120_000,
        process.argv.indexOf("--consume") >= 0,
      );
      process.exit(0);
      return;
    }
    case "notify": {
      const approvalUrl = arg("url");
      if (!approvalUrl) die('usage: sakra notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]');
      await postNotifications({
        approvalUrl,
        context: arg("context") ?? "A high-risk action requires human approval.",
        code: arg("code"),
        slack: arg("slack") ?? process.env.SAKRA_SLACK_WEBHOOK,
        teams: arg("teams") ?? process.env.SAKRA_TEAMS_WEBHOOK,
      });
      console.log("notification sent (best-effort).");
      return;
    }
    case "verify": {
      const hash = rest.find((a) => !a.startsWith("--"));
      if (!hash) die("usage: sakra verify <documentHash> --gateway <url>");
      const client = new SakraClient({ gatewayUrl });
      console.log(JSON.stringify(await client.verify(hash), null, 2));
      return;
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
          '  sakra authorize "<action>" --gateway <url> (--token <t> | --client-id <> --client-secret <>) [--no-wait] [--no-open] [--consume]',
          "  sakra await <nonce> --gateway <url> [--type <t>] [--params <json>] [--timeout <s>] [--consume]",
          '  sakra notify --url <approvalUrl> --context "<text>" [--slack <webhook>] [--teams <webhook>] [--code <code>]',
          "  sakra verify <documentHash> --gateway <url>",
        ].join("\n"),
      );
      process.exit(cmd ? 1 : 0);
  }
}

main().catch((err) => die((err as Error).message));
