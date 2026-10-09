# SPEC.md — webhook-signer

Multi-language SDK for webhook signature verification. One shared API. One shared test-vector suite. Five implementations: TypeScript, Python, Go, PHP, Rust.

## Problem

Webhook security is a universal pain point. Every SaaS builder rewrites signature verification. Most implementations get it wrong: non-timing-safe compares, no replay protection, weak secrets. This project provides correct, tested, minimal implementations in five languages that all pass the same vectors.

## Design

- Shared test vectors live in `vectors/vectors.json`. Every implementation must pass all of them. Vectors come from RFC 4231 (HMAC-SHA256) and RFC 8032 (Ed25519), plus header-format and secret-audit cases.
- Every signature compare is timing-safe. No early exits on mismatch.
- Header formats supported:
  - Stripe style: `t=<unix>,v1=<hex hmac over "t.payload">`, with a replay tolerance window.
  - GitHub style: `sha256=<hex hmac over raw payload>`.
- Custom algorithms: a registry lets users add their own verifier (TypeScript and Python).

## Features

- **F1 — Shared vectors.** `vectors/vectors.json` holds HMAC-SHA256 cases, Ed25519 cases, Stripe-style header cases (valid, expired, tampered, wrong secret), GitHub-style header cases, and check-secret cases. A generator script self-verifies every vector with Node crypto before writing.
- **F2 — TypeScript (`typescript/`).** `signHmac`, `verifyHmac`, `signEd25519`, `verifyEd25519`, `verifyStripeHeader` (tolerance + injectable clock), `verifyGithubHeader`, `checkSecret`, custom-algorithm registry (`registerAlgorithm` / `verifyWithAlgorithm`). Zero runtime deps (`node:crypto` only). `tsc --strict` clean.
- **F3 — Python (`python/`).** Package `webhook_signer`. Same API surface. Stdlib `hmac`/`hashlib` + `cryptography` for Ed25519. Algorithm registry included.
- **F4 — Go (`go/`).** Package `webhooksigner`. Same API surface. Stdlib only (`crypto/hmac`, `crypto/sha256`, `crypto/ed25519`).
- **F5 — PHP (`php/`).** Class `WebhookSigner\WebhookSigner`. Same API surface. `hash_hmac` + `sodium` for Ed25519.
- **F6 — Rust (`rust/`).** Crate `webhook_signer`. Same API surface. `hmac` + `sha2` + `ed25519-dalek` crates.
- **F7 — Cross-language test parity.** Each implementation ships a test suite that loads `vectors/vectors.json` and asserts every case, including all negative cases.
- **F8 — Replay protection.** Stripe-style verification takes `toleranceSeconds` and an injectable current time. Timestamps outside the window fail.
- **F9 — Secret weakness scan.** `checkSecret` flags secrets shorter than 32 bytes (`too_short`) and secrets with fewer than 8 distinct characters (`low_entropy`). Returns ok + issue list.
- **F10 — Docs.** Root README with per-language quickstarts and a support matrix. SECURITY.md with disclosure policy. Per-language READMEs where useful.

## Acceptance criteria

- **AC1.** All vector tests pass in all five languages.
- **AC2.** TypeScript compiles with `tsc --strict`, zero errors, zero runtime deps.
- **AC3.** Python needs only stdlib + `cryptography`.
- **AC4.** Go needs only the standard library.
- **AC5.** PHP tests pass with `ext-sodium` enabled.
- **AC6.** Invalid signatures, tampered payloads, and wrong secrets are rejected in every language.
- **AC7.** Expired timestamps are rejected when a tolerance is set. Fresh timestamps pass.
- **AC8.** Repo tagged `v0.1.0` and pushed.

## Non-goals (v0.1.0)

- No key rotation management.
- No HTTP server middleware (verification primitives only; framework glue comes later).
- No SHA-1 support in GitHub-style headers (documented as legacy-unsafe).
- No signed package registry.

## Build log

- Cycle 1: SPEC.md, vectors generator, shared vectors, LICENSE, .gitignore.
