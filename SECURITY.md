# Security Policy

## Reporting a vulnerability

Do not open a public issue for security vulnerabilities. Email the repository owner instead. We will acknowledge within 72 hours and coordinate disclosure.

## Design notes

- **Constant-time compares.** Every signature comparison uses a constant-time primitive: `crypto.timingSafeEqual` (Node), `hmac.compare_digest` (Python), `hmac.Equal` (Go), `hash_equals` (PHP), `hmac::Mac::verify_slice` / `subtle::ConstantTimeEq` (Rust). Signature length mismatches return false. Length is not secret.
- **Replay protection.** Stripe-style verification binds the timestamp into the signed payload (`"<t>.<payload>"`) and rejects timestamps outside the tolerance window. The clock is injectable for deterministic tests.
- **No SHA-1.** GitHub-style verification accepts `sha256=` only. `sha1=` headers are rejected as legacy-unsafe.
- **Fail closed.** Malformed headers, invalid hex, wrong key lengths, and unknown algorithms return false. They never throw at verification time.
- **Secret hygiene.** `checkSecret` flags secrets under 32 bytes and secrets with fewer than 8 distinct characters. Run it on your secrets before you deploy.

## Scope

Supported: the verification primitives in this repository. Not supported: how you wire them into your HTTP stack. Always verify before parsing or acting on a payload. Compare against the raw request body bytes, not a re-serialized form.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
