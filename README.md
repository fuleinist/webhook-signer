# webhook-signer

Multi-language SDK for webhook signature verification. One shared API. One shared test-vector suite. Five implementations.

Webhook security is a universal pain point. Every SaaS builder rewrites signature verification. Most implementations get it wrong: non-timing-safe compares, no replay protection, weak secrets. webhook-signer provides correct, tested, minimal verification primitives in five languages. All of them pass the same vectors from RFC 4231 (HMAC-SHA256) and RFC 8032 (Ed25519).

## Features

- **HMAC-SHA256** sign and verify, constant-time compare
- **Ed25519** sign and verify
- **Stripe-style headers** (`t=<unix>,v1=<hex>`) with replay-protection tolerance window
- **GitHub-style headers** (`sha256=<hex>`); SHA-1 rejected as legacy-unsafe
- **Secret weakness scan** — flags short and low-entropy secrets before you ship
- **Custom algorithm registry** — plug in your own verifier
- **Shared cross-language test vectors** — every implementation proves parity against `vectors/vectors.json`

## Support matrix

| Language   | Package                       | Dependencies                    | HMAC | Ed25519 | Headers | Audit | Registry |
|------------|-------------------------------|---------------------------------|------|---------|---------|-------|----------|
| TypeScript | `@webhook-signer/core`        | none (`node:crypto`)            | ✅   | ✅      | ✅      | ✅    | ✅       |
| Python     | `webhook-signer`              | stdlib + `cryptography`         | ✅   | ✅      | ✅      | ✅    | ✅       |
| Go         | `.../webhook-signer/go`       | stdlib only                     | ✅   | ✅      | ✅      | ✅    | ✅       |
| PHP        | `WebhookSigner\WebhookSigner` | `ext-hash` + `ext-sodium`       | ✅   | ✅      | ✅      | ✅    | ✅       |
| Rust       | `webhook_signer`              | hmac, sha2, ed25519-dalek, hex  | ✅   | ✅      | ✅      | ✅    | ✅       |

## Quickstarts

### TypeScript

```ts
import { verifyHmac, verifyStripeHeader, checkSecret } from "@webhook-signer/core";

const ok = verifyHmac(secret, requestBody, signatureHex); // timing-safe
const okStripe = verifyStripeHeader(secret, body, header, { toleranceSeconds: 300 });
const audit = checkSecret(secret); // { ok: false, issues: ["too_short"] }
```

### Python

```python
from webhook_signer import verify_hmac, verify_stripe_header, check_secret

ok = verify_hmac(secret, request_body, signature_hex)  # timing-safe
ok_stripe = verify_stripe_header(secret, body, header, tolerance_seconds=300)
audit = check_secret(secret)  # {"ok": False, "issues": ["too_short"]}
```

### Go

```go
import webhooksigner "github.com/fuleinist/webhook-signer/go"

ok := webhooksigner.VerifyHMAC(secret, requestBody, signatureHex)
okStripe := webhooksigner.VerifyStripeHeader(secret, body, header,
    webhooksigner.StripeHeaderOptions{ToleranceSeconds: 300})
audit := webhooksigner.CheckSecret(string(secret))
```

### PHP

```php
use WebhookSigner\WebhookSigner;

$ok = WebhookSigner::verifyHmac($secret, $requestBody, $signatureHex);
$okStripe = WebhookSigner::verifyStripeHeader($secret, $body, $header, 300);
$audit = WebhookSigner::checkSecret($secret); // ['ok' => false, 'issues' => ['too_short']]
```

### Rust

```rust
use webhook_signer::{check_secret, verify_hmac, verify_stripe_header, StripeHeaderOptions};

let ok = verify_hmac(secret.as_bytes(), &request_body, &signature_hex);
let ok_stripe = verify_stripe_header(secret.as_bytes(), &body, &header,
    &StripeHeaderOptions { tolerance_seconds: 300, now_unix: None });
let audit = check_secret(&secret);
```

## Header formats

**Stripe style.** The header carries a timestamp and a signature: `t=1700000000,v1=<hex>`. The HMAC covers `"<t>.<payload>"`. Verification rejects timestamps outside the tolerance window (default 300 seconds). This blocks replay attacks. Inject `now` in tests.

**GitHub style.** The header carries only the signature: `sha256=<hex>`. The HMAC covers the raw payload. `sha1=` headers are rejected: SHA-1 is legacy-unsafe.

## Test vectors

`vectors/vectors.json` is the single source of truth. It contains:

- HMAC-SHA256 cases from RFC 4231 plus binary and empty payloads
- Ed25519 cases from RFC 8032 plus a JSON payload case
- Stripe-style header cases: valid, expired timestamp, tampered payload, wrong secret
- GitHub-style header cases: valid and tampered
- Secret-audit cases: short, low-entropy, and healthy secrets

Regenerate with `node tools/generate-vectors.js`. The generator self-verifies every vector before writing.

## Security

Every signature comparison is constant-time in every language. See [SECURITY.md](SECURITY.md) for the disclosure policy and design notes.

## Running the tests

```bash
# TypeScript
cd typescript && npm install && npm run build && npm test

# Python
cd python && python -m unittest discover -s tests -t .

# Go
cd go && go test ./...

# PHP (requires ext-sodium)
cd php && php tests/run.php

# Rust
cd rust && cargo test
```

## Status

v0.1.0 — verification primitives only. No HTTP middleware yet, no key rotation, no SHA-1. See SPEC.md for non-goals.

## License

MIT
