// Package webhooksigner provides webhook signature verification primitives:
// HMAC-SHA256, Ed25519, Stripe/GitHub header formats, and secret auditing.
// Standard library only. Every signature comparison is constant-time.
package webhooksigner

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SignHMAC computes HMAC-SHA256 over payload and returns lowercase hex.
func SignHMAC(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC verifies an HMAC-SHA256 hex signature in constant time.
func VerifyHMAC(secret, payload []byte, signatureHex string) bool {
	sig, err := hex.DecodeString(strings.ToLower(signatureHex))
	if err != nil || len(sig) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hmac.Equal(sig, mac.Sum(nil))
}

// SignEd25519 signs payload with a 32-byte Ed25519 secret key (hex).
func SignEd25519(secretKeyHex string, payload []byte) (string, error) {
	raw, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return "", errors.New("invalid hex secret key")
	}
	if len(raw) != 32 {
		return "", errors.New("ed25519 secret key must be 32 bytes")
	}
	key := ed25519.NewKeyFromSeed(raw)
	return hex.EncodeToString(ed25519.Sign(key, payload)), nil
}

// VerifyEd25519 verifies an Ed25519 hex signature against a 32-byte hex public key.
// It never panics; malformed input returns false.
func VerifyEd25519(publicKeyHex string, payload []byte, signatureHex string) bool {
	pubRaw, err := hex.DecodeString(strings.ToLower(publicKeyHex))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(strings.ToLower(signatureHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubRaw), payload, sig)
}

// StripeHeaderOptions configures Stripe-style verification.
type StripeHeaderOptions struct {
	// ToleranceSeconds is the maximum allowed timestamp age. Default 300.
	ToleranceSeconds int
	// NowUnix overrides the current time (seconds). Zero means time.Now().
	NowUnix int64
}

// VerifyStripeHeader verifies a Stripe-style header "t=<unix>,v1=<hex>".
// The HMAC covers "<t>.<payload>". Timestamps outside the tolerance window
// are rejected (replay protection).
func VerifyStripeHeader(secret, payload []byte, header string, opts StripeHeaderOptions) bool {
	tolerance := opts.ToleranceSeconds
	if tolerance <= 0 {
		tolerance = 300
	}
	now := opts.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	var t, v1 string
	haveT, haveV1 := false, false
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch {
		case k == "t":
			t, haveT = v, true
		case k == "v1" && !haveV1:
			v1, haveV1 = v, true
		}
	}
	if !haveT || !haveV1 {
		return false
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil || ts < 0 {
		return false
	}
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(tolerance) {
		return false
	}
	signed := make([]byte, 0, len(t)+1+len(payload))
	signed = append(signed, t...)
	signed = append(signed, '.')
	signed = append(signed, payload...)
	return VerifyHMAC(secret, signed, v1)
}

// VerifyGithubHeader verifies a GitHub-style header "sha256=<hex hmac over raw payload>".
// SHA-1 headers are rejected as legacy-unsafe.
func VerifyGithubHeader(secret, payload []byte, header string) bool {
	header = strings.TrimSpace(header)
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	return VerifyHMAC(secret, payload, sig)
}

// SecretAudit reports weaknesses in a webhook secret.
type SecretAudit struct {
	OK     bool
	Issues []string
}

// CheckSecret flags secrets shorter than 32 bytes ("too_short") or with
// fewer than 8 distinct characters ("low_entropy").
func CheckSecret(secret string) SecretAudit {
	var issues []string
	if len(secret) < 32 {
		issues = append(issues, "too_short")
	}
	seen := map[rune]struct{}{}
	for _, r := range secret {
		seen[r] = struct{}{}
	}
	if len(seen) < 8 {
		issues = append(issues, "low_entropy")
	}
	return SecretAudit{OK: len(issues) == 0, Issues: issues}
}

// CustomVerifier verifies a signature with a caller-supplied algorithm.
type CustomVerifier func(secret, payload []byte, signature string) bool

var registry = map[string]CustomVerifier{}

// RegisterAlgorithm registers a custom verification algorithm by name.
func RegisterAlgorithm(name string, fn CustomVerifier) {
	registry[name] = fn
}

// VerifyWithAlgorithm verifies with a registered algorithm.
// Unknown names return false.
func VerifyWithAlgorithm(name string, secret, payload []byte, signature string) bool {
	fn, ok := registry[name]
	if !ok {
		return false
	}
	return fn(secret, payload, signature)
}

// ListAlgorithms returns registered algorithm names in sorted order.
func ListAlgorithms() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
