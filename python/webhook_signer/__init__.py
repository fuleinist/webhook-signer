"""webhook_signer — webhook signature verification primitives.

HMAC-SHA256, Ed25519, Stripe/GitHub header formats, secret auditing.
Stdlib + cryptography only. Every compare is timing-safe.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Callable, Dict, List, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BytesLike = Union[str, bytes]

__all__ = [
    "sign_hmac",
    "verify_hmac",
    "sign_ed25519",
    "verify_ed25519",
    "verify_stripe_header",
    "verify_github_header",
    "check_secret",
    "register_algorithm",
    "verify_with_algorithm",
    "list_algorithms",
]


def _to_bytes(value: BytesLike) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


def _is_hex(value: str) -> bool:
    if len(value) == 0 or len(value) % 2 != 0:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def sign_hmac(secret: BytesLike, payload: BytesLike) -> str:
    """Compute HMAC-SHA256. Returns lowercase hex."""
    return hmac.new(_to_bytes(secret), _to_bytes(payload), hashlib.sha256).hexdigest()


def verify_hmac(secret: BytesLike, payload: BytesLike, signature_hex: str) -> bool:
    """Verify an HMAC-SHA256 hex signature in constant time."""
    if not _is_hex(signature_hex):
        return False
    expected = sign_hmac(secret, payload)
    return hmac.compare_digest(expected.lower(), signature_hex.lower())


def sign_ed25519(secret_key_hex: str, payload: BytesLike) -> str:
    """Sign payload with a 32-byte Ed25519 secret key. Returns lowercase hex."""
    raw = bytes.fromhex(secret_key_hex)
    if len(raw) != 32:
        raise ValueError("ed25519 secret key must be 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(raw)
    return key.sign(_to_bytes(payload)).hex()


def verify_ed25519(public_key_hex: str, payload: BytesLike, signature_hex: str) -> bool:
    """Verify an Ed25519 hex signature against a 32-byte public key."""
    try:
        pub_raw = bytes.fromhex(public_key_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(pub_raw) != 32 or len(sig) != 64:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(pub_raw)
        key.verify(sig, _to_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_stripe_header(
    secret: BytesLike,
    payload: BytesLike,
    header: str,
    tolerance_seconds: int = 300,
    now: Optional[int] = None,
) -> bool:
    """Verify a Stripe-style header ``t=<unix>,v1=<hex>``.

    The HMAC covers ``"<t>.<payload>"``. Timestamps outside the tolerance
    window are rejected (replay protection).
    """
    current = int(now if now is not None else time.time())
    t: Optional[str] = None
    v1: Optional[str] = None
    for part in header.split(","):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip()
        v = v.strip()
        if k == "t":
            t = v
        elif k == "v1" and v1 is None:
            v1 = v
    if t is None or v1 is None:
        return False
    if not t.isdigit():
        return False
    ts = int(t)
    if abs(current - ts) > tolerance_seconds:
        return False
    payload_bytes = _to_bytes(payload)
    signed = t.encode("utf-8") + b"." + payload_bytes
    expected = hmac.new(_to_bytes(secret), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1.lower())


def verify_github_header(secret: BytesLike, payload: BytesLike, header: str) -> bool:
    """Verify a GitHub-style header ``sha256=<hex hmac over raw payload>``."""
    header = header.strip()
    if not header.startswith("sha256="):
        return False
    return verify_hmac(secret, payload, header[len("sha256="):])


def check_secret(secret: str) -> Dict[str, object]:
    """Weakness scan. Flags ``too_short`` (<32 bytes) and ``low_entropy`` (<8 distinct chars)."""
    issues: List[str] = []
    if len(secret.encode("utf-8")) < 32:
        issues.append("too_short")
    if len(set(secret)) < 8:
        issues.append("low_entropy")
    return {"ok": not issues, "issues": issues}


CustomVerifier = Callable[[BytesLike, BytesLike, str], bool]

_registry: Dict[str, CustomVerifier] = {}


def register_algorithm(name: str, verifier: CustomVerifier) -> None:
    """Register a custom verification algorithm by name."""
    _registry[name] = verifier


def verify_with_algorithm(
    name: str, secret: BytesLike, payload: BytesLike, signature: str
) -> bool:
    """Verify with a registered algorithm. Unknown names return False."""
    fn = _registry.get(name)
    if fn is None:
        return False
    return bool(fn(secret, payload, signature))


def list_algorithms() -> List[str]:
    """List registered algorithm names."""
    return sorted(_registry.keys())
