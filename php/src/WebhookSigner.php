<?php

declare(strict_types=1);

namespace WebhookSigner;

/**
 * Webhook signature verification primitives: HMAC-SHA256, Ed25519,
 * Stripe/GitHub header formats, secret auditing.
 *
 * Requires PHP >= 8.1 with ext-sodium and ext-hash.
 * Every signature comparison is timing-safe.
 */
final class WebhookSigner
{
    /** Registered custom algorithms: name => callable(secret, payload, signature): bool */
    private static array $registry = [];

    private function __construct()
    {
    }

    /** Compute HMAC-SHA256 over payload. Returns lowercase hex. */
    public static function signHmac(string $secret, string $payload): string
    {
        return hash_hmac('sha256', $payload, $secret);
    }

    /** Verify an HMAC-SHA256 hex signature in constant time. */
    public static function verifyHmac(string $secret, string $payload, string $signatureHex): bool
    {
        if (!ctype_xdigit($signatureHex) || $signatureHex === '' || strlen($signatureHex) % 2 !== 0) {
            return false;
        }
        return hash_equals(self::signHmac($secret, $payload), strtolower($signatureHex));
    }

    /** Sign payload with a 32-byte Ed25519 secret key (hex). Returns lowercase hex signature. */
    public static function signEd25519(string $secretKeyHex, string $payload): string
    {
        $raw = self::hexToBinChecked($secretKeyHex);
        if (strlen($raw) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('ed25519 secret key must be 32 bytes');
        }
        $keypair = sodium_crypto_sign_seed_keypair($raw);
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        return bin2hex(sodium_crypto_sign_detached($payload, $secretKey));
    }

    /** Verify an Ed25519 hex signature against a 32-byte hex public key. Never throws. */
    public static function verifyEd25519(string $publicKeyHex, string $payload, string $signatureHex): bool
    {
        try {
            $pub = self::hexToBinChecked($publicKeyHex);
            $sig = self::hexToBinChecked($signatureHex);
        } catch (\InvalidArgumentException) {
            return false;
        }
        if (strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $payload, $pub);
        } catch (\SodiumException) {
            return false;
        }
    }

    /**
     * Verify a Stripe-style header "t=<unix>,v1=<hex>".
     * The HMAC covers "<t>.<payload>". Timestamps outside the tolerance
     * window are rejected (replay protection).
     *
     * @param int|null $now Current unix time in seconds. Null means time().
     */
    public static function verifyStripeHeader(
        string $secret,
        string $payload,
        string $header,
        int $toleranceSeconds = 300,
        ?int $now = null
    ): bool {
        $current = $now ?? time();
        $t = null;
        $v1 = null;
        foreach (explode(',', $header) as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            $k = trim(substr($part, 0, $eq));
            $v = trim(substr($part, $eq + 1));
            if ($k === 't') {
                $t = $v;
            } elseif ($k === 'v1' && $v1 === null) {
                $v1 = $v;
            }
        }
        if ($t === null || $v1 === null) {
            return false;
        }
        if (!preg_match('/^\d+$/', $t)) {
            return false;
        }
        $ts = (int) $t;
        if (abs($current - $ts) > $toleranceSeconds) {
            return false;
        }
        $expected = hash_hmac('sha256', $t . '.' . $payload, $secret);
        if (!ctype_xdigit($v1) || $v1 === '') {
            return false;
        }
        return hash_equals($expected, strtolower($v1));
    }

    /** Verify a GitHub-style header "sha256=<hex hmac over raw payload>". SHA-1 is rejected. */
    public static function verifyGithubHeader(string $secret, string $payload, string $header): bool
    {
        $header = trim($header);
        if (!str_starts_with($header, 'sha256=')) {
            return false;
        }
        return self::verifyHmac($secret, $payload, substr($header, 7));
    }

    /**
     * Weakness scan for webhook secrets.
     *
     * @return array{ok: bool, issues: list<string>}
     */
    public static function checkSecret(string $secret): array
    {
        $issues = [];
        if (strlen($secret) < 32) {
            $issues[] = 'too_short';
        }
        if (count(array_unique(str_split($secret))) < 8) {
            $issues[] = 'low_entropy';
        }
        return ['ok' => $issues === [], 'issues' => $issues];
    }

    /** Register a custom verification algorithm by name. */
    public static function registerAlgorithm(string $name, callable $verifier): void
    {
        self::$registry[$name] = $verifier;
    }

    /** Verify with a registered algorithm. Unknown names return false. */
    public static function verifyWithAlgorithm(string $name, string $secret, string $payload, string $signature): bool
    {
        $fn = self::$registry[$name] ?? null;
        if ($fn === null) {
            return false;
        }
        return (bool) $fn($secret, $payload, $signature);
    }

    /** List registered algorithm names in sorted order. */
    public static function listAlgorithms(): array
    {
        $names = array_keys(self::$registry);
        sort($names);
        return $names;
    }

    private static function hexToBinChecked(string $hex): string
    {
        if ($hex === '' || strlen($hex) % 2 !== 0 || !ctype_xdigit($hex)) {
            throw new \InvalidArgumentException('invalid hex string');
        }
        return hex2bin($hex);
    }
}
