# SÄKRA — Cryptographic Governance for Critical Infrastructure

This repository contains the public-facing client SDKs, offline verification libraries, and Model Context Protocol (MCP) plugins for the SÄKRA action-governance protocol.

SÄKRA is a general **action-governance and witness primitive**: no high-risk operation (database mutations, treasury commands, deployments, or AI agent tool calls) runs without a cryptographically-signed human approval and a tamper-evident record.

**MFA verifies who you are. SÄKRA verifies what you are doing.**

---

## Packages in this Repository

| Package | Purpose | Version |
| :--- | :--- | :--- |
| [`@sakra/sdk`](#sakra-sdk) | The main client SDK for Node.js / TypeScript. | `0.1.0` |
| [`@sakra/verify`](#sakra-verify) | Zero-dependency offline cryptographic receipt verifier. | `0.1.0` |
| [`@sakra/mcp-sdk`](#sakra-mcp) | SDK helper utilities and Zod schemas for Model Context Protocol. | `1.0.0` |
| `@sakra/mcp-proxy` | Standard I/O to SSE bridge proxy for MCP servers. | `1.0.0` |

---

## 1. Quickstart: Gating a Blast-Radius Operation

Add `@sakra/sdk` to your backend service to prevent fat-fingered scripts, prompt-injected AI models, or compromised API keys from executing critical operations without human sign-off.

### Install
```bash
npm install @sakra/sdk
```

### Integration Example
Wrap any irreversible call in your backend with `requireApproval` and verify the cryptographic signature receipt offline:

```typescript
import { SakraClient, verifyApprovalReceipt } from "@sakra/sdk";

const sakra = new SakraClient({
  gatewayUrl: process.env.SAKRA_GATEWAY_URL!,      // Your SÄKRA gateway or cloud endpoint
  clientId: process.env.SAKRA_CLIENT_ID!,          // Service or human API key
  clientSecret: process.env.SAKRA_CLIENT_SECRET!,
});

async function wipeDatabase(targetDatabase: string) {
  const action = { 
    actionType: "wipe_production", 
    params: { target: targetDatabase } 
  };

  // 1. Block and request human verification.
  // Pushes a biometric/FIDO2 challenge to the owner's mobile wallet or browser.
  const approval = await sakra.requireApproval(
    `Wipe production database: ${targetDatabase}`, 
    action
  );
  
  if (approval.status !== "APPROVED") {
    throw new Error(`Unauthorized operation status: ${approval.status}`);
  }

  // 2. Offline Verification (Defense-in-depth)
  // Prove in your own codebase that the human signed off on THIS exact payload.
  // This step requires NO connection to the SÄKRA gateway and uses no secrets.
  const check = verifyApprovalReceipt(approval.receipt!, action);
  if (!check.ok) {
    throw new Error(`Receipt verification failed: ${check.reason}`);
  }

  // 3. Safe to proceed
  await executeWipeCommand(targetDatabase);
}
```

---

## 2. Independent Cryptographic Verification (`@sakra/verify`)

If you are running in highly secure environments (like enclave execution or regulated services), you can use `@sakra/verify` with **zero runtime dependencies** (relying only on Node's native `crypto` module).

You check SÄKRA's math yourself:

```typescript
import { verifyApprovalReceipt } from "@sakra/verify";

// Verify a receipt returned from the SÄKRA gateway offline
const result = verifyApprovalReceipt(receipt, {
  actionType: "wipe_production",
  params: { target: "prod-db-1" }
});

if (!result.ok) {
  throw new Error(`Security Violation: human signature verification failed (${result.reason})`);
}
// Signature is valid and bound strictly to the provided parameters.
```

### Policy Auto-Approvals
If a policy was evaluated and auto-approved during a break-glass window, the receipt will have `sigAlg: "AUTO_APPROVED"`. Because no human signature exists to check, `@sakra/verify` **refuses this by default**. To explicitly opt in to policy auto-approvals, pass the allowance option:

```typescript
verifyApprovalReceipt(receipt, expectedAction, { allowAutoApproved: true });
```

---

## 3. Zero-Knowledge Policies (Off-Platform Encryption)

Ensure your security policies remain entirely confidential. Under SÄKRA's ZK policy design, you author policies locally, encrypt them using an organization public key, and publish the encrypted blob. The SÄKRA gateway only stores the ciphertext and enforces policy version hash freshness—it never decrypts or views the rules.

### Using the CLI
The `@sakra/sdk` publishes a standalone CLI utility `sakra`:

```bash
# 1. Generate local key pair
npx sakra keygen --out org

# 2. Encrypt a policy manifest JSON
npx sakra policy-encrypt policy.json --pubkey org.public.key --out encrypted_policy.json

# 3. Verify a document receipt
npx sakra verify <documentHash> --gateway https://api.sakra.com
```

---

## 4. Connecting to SÄKRA as an MCP Server

SÄKRA implements the **Model Context Protocol (MCP)**. This allows AI coding agents (such as Claude Code, Cursor, or custom LLM loops) to interface directly with SÄKRA to request human-in-the-loop validation for tool calls.

### Client Configuration (`mcp.json`)
Add the SÄKRA Server configuration to your LLM agent client configuration:

```json
{
  "mcpServers": {
    "sakra": {
      "type": "sse",
      "url": "https://api.sakra.com/mcp/sse",
      "headers": { 
        "Authorization": "Bearer <your_agent_jwt_token>" 
      }
    }
  }
}
```

### Provided Tools

* **`verify_human_authorization`**: Initiates a challenge request. Returns a `nonce` UUID and immediately responds with `PENDING` while pushing a request to the user's mobile wallet.
* **`check_human_authorization`**: Polls the status of the request by `nonce`. Returns `PENDING`, `APPROVED` (with cryptographic signature receipt), `DENIED`, or `EXPIRED`.

---

## License

This repository is licensed under the MIT License.
