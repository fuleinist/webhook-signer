<?php

declare(strict_types=1);

/**
 * Zero-dependency test runner for WebhookSigner.
 * Run: php tests/run.php   (from the php/ directory)
 * Loads shared vectors from ../../vectors/vectors.json.
 */

require __DIR__ . '/../src/WebhookSigner.php';

use WebhookSigner\WebhookSigner;

$vectors = json_decode(file_get_contents(__DIR__ . '/../../vectors/vectors.json'), true, 512, JSON_THROW_ON_ERROR);

$passed = 0;
$failed = 0;

function check(string $name, bool $cond): void
{
    global $passed, $failed;
    if ($cond) {
        $passed++;
    } else {
        $failed++;
        echo "FAIL: $name\n";
    }
}

function payloadBytes(array $v): string
{
    if (($v['payload_encoding'] ?? 'utf8') === 'hex') {
        return hex2bin($v['payload_hex']);
    }
    return $v['payload'];
}

function secretBytes(array $v): string
{
    return isset($v['key_hex']) && $v['key_hex'] !== '' ? hex2bin($v['key_hex']) : $v['key'];
}

// HMAC-SHA256 vectors
foreach ($vectors['hmac_sha256'] as $v) {
    check("hmac sign {$v['name']}", WebhookSigner::signHmac(secretBytes($v), payloadBytes($v)) === $v['signature_hex']);
    check("hmac verify {$v['name']}", WebhookSigner::verifyHmac(secretBytes($v), payloadBytes($v), $v['signature_hex']));
    check("hmac wrong secret {$v['name']}", !WebhookSigner::verifyHmac('not-the-right-secret-key-value', payloadBytes($v), $v['signature_hex']));
}

// Ed25519 vectors
foreach ($vectors['ed25519'] as $v) {
    check("ed25519 verify {$v['name']}", WebhookSigner::verifyEd25519($v['public_key_hex'], payloadBytes($v), $v['signature_hex']));
    check("ed25519 sign {$v['name']}", WebhookSigner::signEd25519($v['secret_key_hex'], payloadBytes($v)) === $v['signature_hex']);
}
check('ed25519 tampered', !WebhookSigner::verifyEd25519($vectors['ed25519'][2]['public_key_hex'], $vectors['ed25519'][2]['payload'] . 'x', $vectors['ed25519'][2]['signature_hex']));
check('ed25519 bad key', !WebhookSigner::verifyEd25519('abcd', 'payload', 'ef01'));
check('ed25519 bad sig hex', !WebhookSigner::verifyEd25519($vectors['ed25519'][0]['public_key_hex'], 'x', 'zz-not-hex'));

// Stripe-style header vectors
foreach ($vectors['header_stripe_style'] as $v) {
    $got = WebhookSigner::verifyStripeHeader($v['secret'], $v['payload'], $v['header'], $v['tolerance_seconds'], $v['now']);
    check("stripe {$v['name']}", $got === $v['expect_valid']);
}
check('stripe empty header', !WebhookSigner::verifyStripeHeader('s', 'p', ''));
check('stripe missing t', !WebhookSigner::verifyStripeHeader('s', 'p', 'v1=abc'));
check('stripe bad timestamp', !WebhookSigner::verifyStripeHeader('s', 'p', 't=notanumber,v1=abc'));

// GitHub-style header vectors
foreach ($vectors['header_github_style'] as $v) {
    $got = WebhookSigner::verifyGithubHeader($v['secret'], $v['payload'], $v['header']);
    check("github {$v['name']}", $got === $v['expect_valid']);
}
check('github sha1 rejected', !WebhookSigner::verifyGithubHeader('s', 'p', 'sha1=deadbeef'));
check('github garbage rejected', !WebhookSigner::verifyGithubHeader('s', 'p', 'garbage'));

// checkSecret vectors
foreach ($vectors['check_secret'] as $v) {
    $r = WebhookSigner::checkSecret($v['secret']);
    check("checkSecret ok {$v['secret']}", $r['ok'] === $v['expect_ok']);
    if ($v['expect_issue'] !== null) {
        check("checkSecret issue {$v['secret']}", in_array($v['expect_issue'], $r['issues'], true));
    } else {
        check("checkSecret no issues {$v['secret']}", $r['issues'] === []);
    }
}

// Registry
WebhookSigner::registerAlgorithm('hmac-sha256-lower', fn($s, $p, $sig) => WebhookSigner::verifyHmac($s, $p, strtolower($sig)));
$sig = WebhookSigner::signHmac('k', 'payload');
check('registry custom', WebhookSigner::verifyWithAlgorithm('hmac-sha256-lower', 'k', 'payload', strtoupper($sig)));
check('registry unknown', !WebhookSigner::verifyWithAlgorithm('unknown-algo', 'k', 'payload', $sig));
check('registry listed', in_array('hmac-sha256-lower', WebhookSigner::listAlgorithms(), true));

echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
