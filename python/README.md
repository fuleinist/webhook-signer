# webhook_signer (Python)

Webhook signature verification primitives: HMAC-SHA256, Ed25519, Stripe/GitHub header formats, secret weakness audit.

## Install

```bash
pip install -e .
```

Requires stdlib + `cryptography`.

## Usage

```python
from webhook_signer import verify_hmac, verify_stripe_header, check_secret

# Raw HMAC-SHA256 (timing-safe)
ok = verify_hmac(secret, request_body, signature_hex)

# Stripe-style header with replay protection
ok = verify_stripe_header(secret, body, header, tolerance_seconds=300)

# Audit a secret before shipping
audit = check_secret(secret)  # {"ok": bool, "issues": ["too_short", ...]}
```

## Tests

```bash
python -m unittest discover -s tests -t .
```

Tests load the shared cross-language vectors from `../vectors/vectors.json`.
