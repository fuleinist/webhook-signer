"""Vector tests for webhook_signer. Run: python -m unittest discover -s tests -t ."""

import json
import os
import unittest

from webhook_signer import (
    check_secret,
    list_algorithms,
    register_algorithm,
    sign_ed25519,
    sign_hmac,
    verify_ed25519,
    verify_github_header,
    verify_hmac,
    verify_stripe_header,
    verify_with_algorithm,
)

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "..", "..", "vectors", "vectors.json"), encoding="utf-8") as f:
    VECTORS = json.load(f)


def payload_bytes(v):
    if v.get("payload_encoding") == "hex":
        return bytes.fromhex(v["payload_hex"])
    return v["payload"].encode("utf-8")


def secret_bytes(v):
    if v.get("key_hex"):
        return bytes.fromhex(v["key_hex"])
    return v["key"].encode("utf-8")


class HmacVectors(unittest.TestCase):
    def test_sign_matches(self):
        for v in VECTORS["hmac_sha256"]:
            self.assertEqual(sign_hmac(secret_bytes(v), payload_bytes(v)), v["signature_hex"], v["name"])

    def test_verify_accepts_valid(self):
        for v in VECTORS["hmac_sha256"]:
            self.assertTrue(verify_hmac(secret_bytes(v), payload_bytes(v), v["signature_hex"]), v["name"])

    def test_verify_rejects_wrong_secret(self):
        for v in VECTORS["hmac_sha256"]:
            self.assertFalse(verify_hmac(b"not-the-right-secret-key-value", payload_bytes(v), v["signature_hex"]), v["name"])


class Ed25519Vectors(unittest.TestCase):
    def test_verify_accepts_valid(self):
        for v in VECTORS["ed25519"]:
            self.assertTrue(verify_ed25519(v["public_key_hex"], payload_bytes(v), v["signature_hex"]), v["name"])

    def test_sign_reproduces(self):
        for v in VECTORS["ed25519"]:
            self.assertEqual(sign_ed25519(v["secret_key_hex"], payload_bytes(v)), v["signature_hex"], v["name"])

    def test_tampered_rejected(self):
        v = VECTORS["ed25519"][2]
        self.assertFalse(verify_ed25519(v["public_key_hex"], v["payload"] + "x", v["signature_hex"]))

    def test_bad_keys_no_throw(self):
        self.assertFalse(verify_ed25519("abcd", "payload", "ef01"))
        self.assertFalse(verify_ed25519(VECTORS["ed25519"][0]["public_key_hex"], "x", "zz-not-hex"))


class StripeHeaderVectors(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS["header_stripe_style"]:
            got = verify_stripe_header(
                v["secret"], v["payload"], v["header"],
                tolerance_seconds=v["tolerance_seconds"], now=v["now"],
            )
            self.assertEqual(got, v["expect_valid"], v["name"])

    def test_malformed(self):
        self.assertFalse(verify_stripe_header("s", "p", ""))
        self.assertFalse(verify_stripe_header("s", "p", "v1=abc"))
        self.assertFalse(verify_stripe_header("s", "p", "t=notanumber,v1=abc"))


class GithubHeaderVectors(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS["header_github_style"]:
            self.assertEqual(
                verify_github_header(v["secret"], v["payload"], v["header"]),
                v["expect_valid"], v["name"],
            )

    def test_sha1_and_junk_rejected(self):
        self.assertFalse(verify_github_header("s", "p", "sha1=deadbeef"))
        self.assertFalse(verify_github_header("s", "p", "garbage"))


class CheckSecretVectors(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS["check_secret"]:
            r = check_secret(v["secret"])
            self.assertEqual(r["ok"], v["expect_ok"], v["secret"])
            if v["expect_issue"]:
                self.assertIn(v["expect_issue"], r["issues"])
            else:
                self.assertEqual(r["issues"], [])


class Registry(unittest.TestCase):
    def test_custom_algorithm(self):
        register_algorithm("hmac-sha256-lower", lambda s, p, sig: verify_hmac(s, p, sig.lower()))
        sig = sign_hmac("k", "payload")
        self.assertTrue(verify_with_algorithm("hmac-sha256-lower", "k", "payload", sig.upper()))
        self.assertFalse(verify_with_algorithm("unknown-algo", "k", "payload", sig))
        self.assertIn("hmac-sha256-lower", list_algorithms())


if __name__ == "__main__":
    unittest.main()
