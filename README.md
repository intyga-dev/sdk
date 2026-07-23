# SÄKRA — Cryptographic Governance for Critical Infrastructure

This repository contains the public-facing client SDKs and offline verification libraries for the SÄKRA action-governance protocol. The Model Context Protocol (MCP) tooling for AI agents lives in its own repository: [`SAKRA-trust/mcp`](https://github.com/SAKRA-trust/mcp).

SÄKRA is a general **action-governance and witness primitive**: no high-risk operation (database mutations, treasury commands, deployments, or AI agent tool calls) runs without a cryptographically-signed human approval and a tamper-evident record.

**MFA verifies who you are. SÄKRA verifies what you are doing.**

---

## Packages in this Repository

| Package | Purpose | Version |
| :--- | :--- | :--- |
| [`@sakra-trust/sdk`](#sakra-sdk) | The main client SDK for Node.js / TypeScript. | `0.1.0` |
| [`sakra-sdk` (Python)](#sakra-sdk-python) | SÄKRA client SDK for Python applications & pipelines. | `0.1.0` |
| [`@sakra-trust/verify`](#sakra-verify) | Zero-dependency offline cryptographic receipt verifier. | `0.1.0` |

---

## 1. Quickstart: Gating a Blast-Radius Operation

Add `@sakra-trust/sdk` to your backend service to prevent fat-fingered scripts, prompt-injected AI models, or compromised API keys from executing critical operations without human sign-off.

### Install
```bash
npm install @sakra-trust/sdk
```

### Integration Example
Wrap any irreversible call in your backend with `requireApproval` and verify the cryptographic signature receipt offline:

```typescript
import { SakraClient, verifyApprovalReceipt } from "@sakra-trust/sdk";

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
  // Raises a FIDO2/WebAuthn challenge the approver signs in their browser
  // (Touch ID, Windows Hello, YubiKey). Nothing to install.
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

### Python Quickstart

Install the Python SDK:
```bash
pip install sakra-sdk
```

Wrap critical operations and verify the signature receipt:
```python
import asyncio
from sakra_sdk import SakraClient, verify_approval_receipt

sakra = SakraClient(
    gateway_url="https://api.sakra.com",
    client_id="your-client-id",
    client_secret="your-client-secret"
)

async def wipe_database(target_database: str):
    action = {
        "actionType": "wipe_production",
        "params": { "target": target_database }
    }

    # 1. Block and request human verification
    approval = await sakra.require_approval(
        f"Wipe production database: {target_database}",
        action_type=action["actionType"],
        params=action["params"]
    )
    if approval["status"] != "APPROVED":
        raise Exception(f"Unauthorized: {approval['status']}")

    # 2. Offline cryptographic verification (no connection or secret required)
    check = verify_approval_receipt(approval["receipt"], action)
    if not check["ok"]:
        raise Exception(f"Verification failed: {check['reason']}")

    # 3. Safe to proceed
    await execute_wipe_command(target_database)
```

---

## 2. Independent Cryptographic Verification (`@sakra-trust/verify`)

If you are running in highly secure environments (like enclave execution or regulated services), you can use `@sakra-trust/verify` with **zero runtime dependencies** (relying only on Node's native `crypto` module).

You check SÄKRA's math yourself:

```typescript
import { verifyApprovalReceipt } from "@sakra-trust/verify";

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
If a policy was evaluated and auto-approved during a break-glass window, the receipt will have `sigAlg: "AUTO_APPROVED"`. Because no human signature exists to check, `@sakra-trust/verify` **refuses this by default**. To explicitly opt in to policy auto-approvals, pass the allowance option:

```typescript
verifyApprovalReceipt(receipt, expectedAction, { allowAutoApproved: true });
```

---

## 3. Zero-Knowledge Policies (Off-Platform Encryption)

Ensure your security policies remain entirely confidential. Under SÄKRA's ZK policy design, you author policies locally, encrypt them using an organization public key, and publish the encrypted blob. The SÄKRA gateway only stores the ciphertext and enforces policy version hash freshness—it never decrypts or views the rules.

### Using the CLI
The `@sakra-trust/sdk` publishes a standalone CLI utility `sakra`:

```bash
# 1. Generate local key pair
npx sakra keygen --out org

# 2. Encrypt a policy manifest JSON
npx sakra policy-encrypt policy.json --pubkey org.public.key --out encrypted_policy.json

# 3. Verify a document receipt
npx sakra verify <documentHash> --gateway https://api.sakra.com
```

---

## 4. Governing AI Agent Tool Calls (MCP)

For gating an AI agent's Model Context Protocol tool calls behind human approval — either by
connecting to SÄKRA's hosted MCP endpoint or by wrapping your own MCP server — see the dedicated
repository and packages: **[`SAKRA-trust/mcp`](https://github.com/SAKRA-trust/mcp)**
(`@sakra-trust/mcp-sdk`, `@sakra-trust/mcp-proxy`).

---

## License

Apache-2.0. See each package's `LICENSE`.
