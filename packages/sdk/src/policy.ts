import crypto from "node:crypto";

// Off-platform zero-knowledge policy crypto. Run this on YOUR machine (CLI/CI) so SÄKRA never sees
// the plaintext or the private key — the strongest ZK posture (no trust in SÄKRA-served code).
// Blob format is byte-compatible with the browser console: `v1.<rsaWrappedAesKey>.<iv>.<ct+gcmTag>`
// (standard base64), RSA-OAEP(SHA-256) + AES-256-GCM.

const b64 = (b: Buffer) => b.toString("base64");
const unb64 = (s: string) => Buffer.from(s, "base64");

/** Generate an org keypair. Keep the private key OFF SÄKRA; upload only the public key. */
export function generateOrgKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    publicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
  };
}

/** Encrypt a plaintext manifest with the org public key (base64 SPKI). Returns an opaque blob. */
export function encryptPolicy(publicKeySpkiB64: string, plaintext: string): string {
  const pub = crypto.createPublicKey({ key: unb64(publicKeySpkiB64), format: "der", type: "spki" });
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ct = Buffer.concat([enc, tag]); // append tag (matches Web Crypto AES-GCM output)
  const wrapped = crypto.publicEncrypt(
    { key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    aesKey,
  );
  return `v1.${b64(wrapped)}.${b64(iv)}.${b64(ct)}`;
}

/** Decrypt an opaque blob with the org private key (base64 PKCS8). */
export function decryptPolicy(privateKeyPkcs8B64: string, blob: string): string {
  const [v, wrapped, iv, ct] = blob.split(".");
  if (v !== "v1" || !wrapped || !iv || !ct) throw new Error("malformed policy blob");
  const priv = crypto.createPrivateKey({ key: unb64(privateKeyPkcs8B64), format: "der", type: "pkcs8" });
  const aesKey = crypto.privateDecrypt(
    { key: priv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    unb64(wrapped),
  );
  const ctBuf = unb64(ct);
  const tag = ctBuf.subarray(ctBuf.length - 16);
  const enc = ctBuf.subarray(0, ctBuf.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, unb64(iv));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

/** Canonical blobHash: SHA-256 hex of the blob string (matches the gateway + browser). */
export function blobHash(blob: string): string {
  return crypto.createHash("sha256").update(blob).digest("hex");
}


