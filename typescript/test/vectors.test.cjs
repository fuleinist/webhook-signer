"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const ws = require("../dist/index.js");

const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "..", "vectors", "vectors.json"), "utf8")
);

function payloadBytes(v) {
  if (v.payload_encoding === "hex") return Buffer.from(v.payload_hex, "hex");
  return v.payload;
}

function secretBytes(v) {
  if (v.key_hex) return Buffer.from(v.key_hex, "hex");
  return v.key;
}

test("HMAC-SHA256 vectors: sign matches", () => {
  for (const v of vectors.hmac_sha256) {
    assert.strictEqual(ws.signHmac(secretBytes(v), payloadBytes(v)), v.signature_hex, v.name);
  }
});

test("HMAC-SHA256 vectors: verify accepts valid", () => {
  for (const v of vectors.hmac_sha256) {
    assert.strictEqual(ws.verifyHmac(secretBytes(v), payloadBytes(v), v.signature_hex), true, v.name);
  }
});

test("HMAC-SHA256 vectors: verify rejects wrong secret", () => {
  for (const v of vectors.hmac_sha256) {
    assert.strictEqual(ws.verifyHmac("not-the-right-secret-key-value", payloadBytes(v), v.signature_hex), false, v.name);
  }
});

test("Ed25519 vectors: verify accepts valid", () => {
  for (const v of vectors.ed25519) {
    assert.strictEqual(ws.verifyEd25519(v.public_key_hex, payloadBytes(v), v.signature_hex), true, v.name);
  }
});

test("Ed25519 vectors: sign reproduces signature", () => {
  for (const v of vectors.ed25519) {
    assert.strictEqual(ws.signEd25519(v.secret_key_hex, payloadBytes(v)), v.signature_hex, v.name);
  }
});

test("Ed25519: tampered payload rejected", () => {
  const v = vectors.ed25519[2];
  assert.strictEqual(ws.verifyEd25519(v.public_key_hex, v.payload + "x", v.signature_hex), false);
});

test("Ed25519: bad key lengths rejected without throwing", () => {
  assert.strictEqual(ws.verifyEd25519("abcd", "payload", "ef01"), false);
  assert.strictEqual(ws.verifyEd25519(vectors.ed25519[0].public_key_hex, "x", "not-hex-zz"), false);
});

test("Stripe-style header vectors", () => {
  for (const v of vectors.header_stripe_style) {
    const got = ws.verifyStripeHeader(v.secret, v.payload, v.header, {
      toleranceSeconds: v.tolerance_seconds,
      now: v.now,
    });
    assert.strictEqual(got, v.expect_valid, v.name);
  }
});

test("Stripe-style header: malformed headers rejected", () => {
  assert.strictEqual(ws.verifyStripeHeader("s", "p", ""), false);
  assert.strictEqual(ws.verifyStripeHeader("s", "p", "v1=abc"), false);
  assert.strictEqual(ws.verifyStripeHeader("s", "p", "t=notanumber,v1=abc"), false);
});

test("GitHub-style header vectors", () => {
  for (const v of vectors.header_github_style) {
    assert.strictEqual(ws.verifyGithubHeader(v.secret, v.payload, v.header), v.expect_valid, v.name);
  }
});

test("GitHub-style header: sha1 and junk rejected", () => {
  assert.strictEqual(ws.verifyGithubHeader("s", "p", "sha1=deadbeef"), false);
  assert.strictEqual(ws.verifyGithubHeader("s", "p", "garbage"), false);
});

test("checkSecret vectors", () => {
  for (const v of vectors.check_secret) {
    const r = ws.checkSecret(v.secret);
    assert.strictEqual(r.ok, v.expect_ok, v.secret);
    if (v.expect_issue) assert.ok(r.issues.includes(v.expect_issue), v.secret);
    else assert.deepStrictEqual(r.issues, []);
  }
});

test("custom algorithm registry", () => {
  ws.registerAlgorithm("hmac-sha256-upper", (secret, payload, sig) =>
    ws.verifyHmac(secret, payload, sig.toLowerCase())
  );
  const sig = ws.signHmac("k", "payload");
  assert.strictEqual(ws.verifyWithAlgorithm("hmac-sha256-upper", "k", "payload", sig.toUpperCase()), true);
  assert.strictEqual(ws.verifyWithAlgorithm("unknown-algo", "k", "payload", sig), false);
  assert.ok(ws.listAlgorithms().includes("hmac-sha256-upper"));
});
