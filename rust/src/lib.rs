//! webhook_signer — webhook signature verification primitives.
//!
//! HMAC-SHA256, Ed25519, Stripe/GitHub header formats, secret auditing.
//! Every signature comparison is constant-time.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Custom verifier: (secret, payload, signature) -> bool
pub type CustomVerifier = Box<dyn Fn(&[u8], &[u8], &str) -> bool + Send + Sync>;

fn registry() -> &'static Mutex<HashMap<String, CustomVerifier>> {
    static REG: OnceLock<Mutex<HashMap<String, CustomVerifier>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Compute HMAC-SHA256 over payload. Returns lowercase hex.
pub fn sign_hmac(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 hex signature in constant time.
pub fn verify_hmac(secret: &[u8], payload: &[u8], signature_hex: &str) -> bool {
    let Ok(sig) = hex::decode(signature_hex) else {
        return false;
    };
    if sig.is_empty() {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload);
    mac.verify_slice(&sig).is_ok()
}

/// Sign payload with a 32-byte Ed25519 secret key (hex). Returns lowercase hex signature.
pub fn sign_ed25519(secret_key_hex: &str, payload: &[u8]) -> Result<String, String> {
    let raw = hex::decode(secret_key_hex).map_err(|_| "invalid hex secret key".to_string())?;
    if raw.len() != 32 {
        return Err("ed25519 secret key must be 32 bytes".to_string());
    }
    let key = SigningKey::from_bytes(raw.as_slice().try_into().unwrap());
    let sig: Signature = key.sign(payload);
    Ok(hex::encode(sig.to_bytes()))
}

/// Verify an Ed25519 hex signature against a 32-byte hex public key. Never panics.
pub fn verify_ed25519(public_key_hex: &str, payload: &[u8], signature_hex: &str) -> bool {
    let (Ok(pub_raw), Ok(sig_raw)) = (hex::decode(public_key_hex), hex::decode(signature_hex)) else {
        return false;
    };
    let (Ok(pk_arr), Ok(sig_arr)) = (
        <[u8; 32]>::try_from(pub_raw.as_slice()),
        <[u8; 64]>::try_from(sig_raw.as_slice()),
    ) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(payload, &sig).is_ok()
}

/// Options for Stripe-style header verification.
#[derive(Debug, Clone)]
pub struct StripeHeaderOptions {
    /// Maximum allowed timestamp age in seconds. Default 300.
    pub tolerance_seconds: i64,
    /// Current unix time in seconds. None means SystemTime::now().
    pub now_unix: Option<i64>,
}

impl Default for StripeHeaderOptions {
    fn default() -> Self {
        Self {
            tolerance_seconds: 300,
            now_unix: None,
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verify a Stripe-style header `t=<unix>,v1=<hex>`.
/// The HMAC covers `"<t>.<payload>"`. Timestamps outside the tolerance
/// window are rejected (replay protection).
pub fn verify_stripe_header(secret: &[u8], payload: &[u8], header: &str, opts: &StripeHeaderOptions) -> bool {
    let tolerance = if opts.tolerance_seconds > 0 {
        opts.tolerance_seconds
    } else {
        300
    };
    let now = opts.now_unix.unwrap_or_else(now_unix);
    let mut t: Option<&str> = None;
    let mut v1: Option<&str> = None;
    for part in header.split(',') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        match k.trim() {
            "t" => t = Some(v.trim()),
            "v1" => {
                if v1.is_none() {
                    v1 = Some(v.trim());
                }
            }
            _ => {}
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else {
        return false;
    };
    let Ok(ts) = t.parse::<i64>() else {
        return false;
    };
    if ts < 0 || (now - ts).abs() > tolerance {
        return false;
    }
    let mut signed = Vec::with_capacity(t.len() + 1 + payload.len());
    signed.extend_from_slice(t.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(payload);
    verify_hmac(secret, &signed, v1)
}

/// Verify a GitHub-style header `sha256=<hex hmac over raw payload>`. SHA-1 is rejected.
pub fn verify_github_header(secret: &[u8], payload: &[u8], header: &str) -> bool {
    let header = header.trim();
    let Some(sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    verify_hmac(secret, payload, sig)
}

/// Result of a secret weakness scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAudit {
    pub ok: bool,
    pub issues: Vec<&'static str>,
}

/// Flags secrets shorter than 32 bytes (`too_short`) or with fewer than
/// 8 distinct characters (`low_entropy`).
pub fn check_secret(secret: &str) -> SecretAudit {
    let mut issues = Vec::new();
    if secret.len() < 32 {
        issues.push("too_short");
    }
    let mut distinct: Vec<char> = secret.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 8 {
        issues.push("low_entropy");
    }
    SecretAudit {
        ok: issues.is_empty(),
        issues,
    }
}

/// Register a custom verification algorithm by name.
pub fn register_algorithm<F>(name: &str, verifier: F)
where
    F: Fn(&[u8], &[u8], &str) -> bool + Send + Sync + 'static,
{
    registry()
        .lock()
        .expect("registry lock")
        .insert(name.to_string(), Box::new(verifier));
}

/// Verify with a registered algorithm. Unknown names return false.
pub fn verify_with_algorithm(name: &str, secret: &[u8], payload: &[u8], signature: &str) -> bool {
    let guard = registry().lock().expect("registry lock");
    match guard.get(name) {
        Some(f) => f(secret, payload, signature),
        None => false,
    }
}

/// List registered algorithm names in sorted order.
pub fn list_algorithms() -> Vec<String> {
    let mut names: Vec<String> = registry().lock().expect("registry lock").keys().cloned().collect();
    names.sort();
    names
}

/// Constant-time hex string comparison helper (exposed for embedders).
pub fn safe_compare_hex(a: &str, b: &str) -> bool {
    let (la, lb) = (a.to_lowercase(), b.to_lowercase());
    if la.len() != lb.len() {
        return false;
    }
    la.as_bytes().ct_eq(lb.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_hmac_roundtrip() {
        let sig = sign_hmac(b"key", b"payload");
        assert!(verify_hmac(b"key", b"payload", &sig));
        assert!(!verify_hmac(b"key", b"payloadx", &sig));
    }

    #[test]
    fn safe_compare_works() {
        assert!(safe_compare_hex("ABCD", "abcd"));
        assert!(!safe_compare_hex("abcd", "abce"));
        assert!(!safe_compare_hex("abcd", "abc"));
    }
}
