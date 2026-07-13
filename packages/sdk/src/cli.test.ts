import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// The GitHub Action relies on the CLI's exit-code contract: 0 when it succeeds/prints help, non-zero
// when the request is malformed or approval fails. These spawn the BUILT binary (run `pnpm build` first).
const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function run(args: string[]) {
  return spawnSync("node", [cli, ...args], { encoding: "utf8" });
}

test("no command prints help and exits 0", () => {
  const r = run([]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /SÄKRA CLI/);
});

test("authorize without an action description exits non-zero", () => {
  const r = run(["authorize"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /usage: sakra authorize/);
});

test("authorize with invalid --params JSON exits non-zero", () => {
  const r = run(["authorize", "do a thing", "--params", "{not-json}", "--token", "t", "--gateway", "http://127.0.0.1:9"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /Invalid JSON in --params/);
});

test("await without a nonce exits non-zero", () => {
  const r = run(["await"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /usage: sakra await/);
});

test("notify without --url exits non-zero", () => {
  const r = run(["notify", "--context", "x"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /usage: sakra notify/);
});
