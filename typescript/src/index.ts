import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
} from "node:crypto";

export type Bytes = Uint8Array;
export type BytesLike = string | Uint8Array;

/** Normalize input to bytes. Strings are UTF-8. Hex strings must be passed as Uint8Array by the caller. */
function toBytes(input: BytesLike): Uint8Array {
  if (typeof input === "string") return new TextEncoder().encode(input);
  return input;
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("invalid hex string");
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/** Timing-safe hex signature comparison. Length differences return false without comparing. */
export function safeCompareHex(a: string, b: string): boolean {
  const na = a.toLowerCase();
  const nb = b.toLowerCase();
  if (na.length !== nb.length) return false;
  try {
    return timingSafeEqual(Buffer.from(na, "hex"), Buffer.from(nb, "hex"));
  } catch {
    return false;
  }
}

/** Compute HMAC-SHA256 over payload. Returns lowercase hex. */
export function signHmac(secret: BytesLike, payload: BytesLike): string {
  return createHmac("sha256", toBytes(secret)).update(toBytes(payload)).digest("hex");
}

/** Verify an HMAC-SHA256 hex signature in constant time. */
export function verifyHmac(secret: BytesLike, payload: BytesLike, signatureHex: string): boolean {
  if (!/^[0-9a-fA-F]+$/.test(signatureHex)) return false;
  return safeCompareHex(signHmac(secret, payload), signatureHex);
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Sign payload with a 32-byte Ed25519 secret key. Returns lowercase hex signature. */
export function signEd25519(secretKeyHex: string, payload: BytesLike): string {
  const raw = fromHex(secretKeyHex);
  if (raw.length !== 32) throw new Error("ed25519 secret key must be 32 bytes");
  const key = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "pkcs8",
  });
  return toHex(cryptoSign(null, toBytes(payload), key));
}

/** Verify an Ed25519 hex signature against a 32-byte public key. */
export function verifyEd25519(publicKeyHex: string, payload: BytesLike, signatureHex: string): boolean {
  let pubRaw: Uint8Array;
  let sig: Uint8Array;
  try {
    pubRaw = fromHex(publicKeyHex);
    sig = fromHex(signatureHex);
  } catch {
    return false;
  }
  if (pubRaw.length !== 32 || sig.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pubRaw)]),
      format: "der",
      type: "spki",
    });
    return cryptoVerify(null, toBytes(payload), key, Buffer.from(sig));
  } catch {
    return false;
  }
}

export interface StripeHeaderOptions {
  /** Max allowed age of the timestamp in seconds. Default 300. */
  toleranceSeconds?: number;
  /** Current unix time in seconds. Injectable for tests. Default Date.now()/1000. */
  now?: number;
}

/**
 * Verify a Stripe-style header: `t=<unix>,v1=<hex>` where the HMAC covers `"<t>.<payload>"`.
 * Rejects expired timestamps outside the tolerance window (replay protection).
 */
export function verifyStripeHeader(
  secret: BytesLike,
  payload: BytesLike,
  header: string,
  options: StripeHeaderOptions = {}
): boolean {
  const tolerance = options.toleranceSeconds ?? 300;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  let t: string | null = null;
  let v1: string | null = null;
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === "t") t = v;
    else if (k === "v1" && v1 === null) v1 = v;
  }
  if (t === null || v1 === null) return false;
  if (!/^\d+$/.test(t)) return false;
  const ts = parseInt(t, 10);
  if (Number.isNaN(ts) || Math.abs(now - ts) > tolerance) return false;
  if (typeof payload === "string") {
    return verifyHmac(secret, `${t}.${payload}`, v1);
  }
  const expected = createHmac("sha256", toBytes(secret))
    .update(Buffer.concat([Buffer.from(`${t}.`, "utf8"), Buffer.from(payload)]))
    .digest("hex");
  return safeCompareHex(expected, v1);
}

/** Verify a GitHub-style header: `sha256=<hex hmac over raw payload>`. */
export function verifyGithubHeader(secret: BytesLike, payload: BytesLike, header: string): boolean {
  const m = /^sha256=([0-9a-fA-F]+)$/.exec(header.trim());
  if (!m) return false;
  return verifyHmac(secret, payload, m[1]);
}

export interface SecretAudit {
  ok: boolean;
  issues: string[];
}

/** Weakness scan for webhook secrets. Flags secrets under 32 bytes or with low character entropy. */
export function checkSecret(secret: string): SecretAudit {
  const issues: string[] = [];
  const bytes = new TextEncoder().encode(secret);
  if (bytes.length < 32) issues.push("too_short");
  const distinct = new Set(secret.split("")).size;
  if (distinct < 8) issues.push("low_entropy");
  return { ok: issues.length === 0, issues };
}

export type CustomVerifier = (secret: BytesLike, payload: BytesLike, signature: string) => boolean;

const registry = new Map<string, CustomVerifier>();

/** Register a custom verification algorithm by name. */
export function registerAlgorithm(name: string, verifier: CustomVerifier): void {
  registry.set(name, verifier);
}

/** Verify with a registered algorithm. Unknown names return false. */
export function verifyWithAlgorithm(
  name: string,
  secret: BytesLike,
  payload: BytesLike,
  signature: string
): boolean {
  const fn = registry.get(name);
  if (!fn) return false;
  return fn(secret, payload, signature);
}

/** List registered algorithm names. */
export function listAlgorithms(): string[] {
  return [...registry.keys()];
}
