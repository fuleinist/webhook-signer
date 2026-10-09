//! Cross-language vector tests. Loads ../vectors/vectors.json.

use serde::Deserialize;
use std::fs;
use webhook_signer::*;

#[derive(Deserialize)]
struct Vectors {
    hmac_sha256: Vec<HmacVector>,
    ed25519: Vec<Ed25519Vector>,
    header_stripe_style: Vec<StripeVector>,
    header_github_style: Vec<GithubVector>,
    check_secret: Vec<SecretVector>,
}

#[derive(Deserialize)]
struct HmacVector {
    name: String,
    #[serde(default)]
    key_hex: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    payload_encoding: Option<String>,
    signature_hex: String,
}

#[derive(Deserialize)]
struct Ed25519Vector {
    name: String,
    secret_key_hex: String,
    public_key_hex: String,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    payload_encoding: Option<String>,
    signature_hex: String,
}

#[derive(Deserialize)]
struct StripeVector {
    name: String,
    secret: String,
    payload: String,
    header: String,
    now: i64,
    tolerance_seconds: i64,
    expect_valid: bool,
}

#[derive(Deserialize)]
struct GithubVector {
    name: String,
    secret: String,
    payload: String,
    header: String,
    expect_valid: bool,
}

#[derive(Deserialize)]
struct SecretVector {
    secret: String,
    expect_ok: bool,
    expect_issue: Option<String>,
}

fn load() -> Vectors {
    let raw = fs::read_to_string("../vectors/vectors.json").expect("read vectors");
    serde_json::from_str(&raw).expect("parse vectors")
}

fn payload_bytes(enc: &Option<String>, payload: &Option<String>, payload_hex: &Option<String>) -> Vec<u8> {
    if enc.as_deref() == Some("hex") {
        hex::decode(payload_hex.as_deref().unwrap_or("")).expect("payload hex")
    } else {
        payload.clone().unwrap_or_default().into_bytes()
    }
}

#[test]
fn hmac_vectors_sign() {
    for v in load().hmac_sha256 {
        let secret = match &v.key_hex {
            Some(h) => hex::decode(h).unwrap(),
            None => v.key.clone().unwrap().into_bytes(),
        };
        let payload = payload_bytes(&v.payload_encoding, &v.payload, &v.payload_hex);
        assert_eq!(sign_hmac(&secret, &payload), v.signature_hex, "{}", v.name);
        assert!(verify_hmac(&secret, &payload, &v.signature_hex), "{}", v.name);
        assert!(
            !verify_hmac(b"not-the-right-secret-key-value", &payload, &v.signature_hex),
            "{}",
            v.name
        );
    }
}

#[test]
fn ed25519_vectors() {
    for v in load().ed25519 {
        let payload = payload_bytes(&v.payload_encoding, &v.payload, &v.payload_hex);
        assert!(
            verify_ed25519(&v.public_key_hex, &payload, &v.signature_hex),
            "{}",
            v.name
        );
        assert_eq!(
            sign_ed25519(&v.secret_key_hex, &payload).unwrap(),
            v.signature_hex,
            "{}",
            v.name
        );
    }
}

#[test]
fn ed25519_negative() {
    let vs = load().ed25519;
    let v = &vs[2];
    let payload = payload_bytes(&v.payload_encoding, &v.payload, &v.payload_hex);
    let mut tampered = payload.clone();
    tampered.push(b'x');
    assert!(!verify_ed25519(&v.public_key_hex, &tampered, &v.signature_hex));
    assert!(!verify_ed25519("abcd", b"payload", "ef01"));
    assert!(!verify_ed25519(&v.public_key_hex, b"x", "zz-not-hex"));
}

#[test]
fn stripe_header_vectors() {
    for v in load().header_stripe_style {
        let got = verify_stripe_header(
            v.secret.as_bytes(),
            v.payload.as_bytes(),
            &v.header,
            &StripeHeaderOptions {
                tolerance_seconds: v.tolerance_seconds,
                now_unix: Some(v.now),
            },
        );
        assert_eq!(got, v.expect_valid, "{}", v.name);
    }
    let opts = StripeHeaderOptions::default();
    assert!(!verify_stripe_header(b"s", b"p", "", &opts));
    assert!(!verify_stripe_header(b"s", b"p", "v1=abc", &opts));
    assert!(!verify_stripe_header(b"s", b"p", "t=notanumber,v1=abc", &opts));
}

#[test]
fn github_header_vectors() {
    for v in load().header_github_style {
        let got = verify_github_header(v.secret.as_bytes(), v.payload.as_bytes(), &v.header);
        assert_eq!(got, v.expect_valid, "{}", v.name);
    }
    assert!(!verify_github_header(b"s", b"p", "sha1=deadbeef"));
    assert!(!verify_github_header(b"s", b"p", "garbage"));
}

#[test]
fn check_secret_vectors() {
    for v in load().check_secret {
        let r = check_secret(&v.secret);
        assert_eq!(r.ok, v.expect_ok, "{}", v.secret);
        match &v.expect_issue {
            Some(issue) => assert!(
                r.issues.iter().any(|i| *i == issue.as_str()),
                "{} missing {}",
                v.secret,
                issue
            ),
            None => assert!(r.issues.is_empty(), "{}", v.secret),
        }
    }
}

#[test]
fn custom_registry() {
    register_algorithm("hmac-sha256-ci", |s, p, sig| verify_hmac(s, p, &sig.to_lowercase()));
    let sig = sign_hmac(b"k", b"payload");
    assert!(verify_with_algorithm("hmac-sha256-ci", b"k", b"payload", &sig.to_uppercase()));
    assert!(!verify_with_algorithm("unknown-algo", b"k", b"payload", &sig));
    assert!(list_algorithms().contains(&"hmac-sha256-ci".to_string()));
}
