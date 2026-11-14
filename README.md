# aoIdents

**Identity, trust and cryptography for the aoheyra mesh.** A pure-Rust, sans-IO crate: no networking, no I/O, no FFI. It owns who a node *is*, how contacts are trusted, and how messages are signed, sealed and replay-checked.

> **Status: pre-alpha.** IDN-00 (scaffold, package naming, MSRV, CI with cargo-audit), IDN-01 (crypto-suite ADR), IDN-02 (core types and errors), IDN-03 (identity generation and derivation), IDN-04 (context-separated sign/verify), IDN-05 (key store trait), IDN-07 (identity card and QR string), IDN-08 (contact book logic), IDN-09 (sealed message v1), IDN-10 (multi-recipient sealed message), IDN-11 (signed public blobs), IDN-12 (rotating tag generator), IDN-19 (threat model) and IDN-20 (handle ADR) are implemented; everything below is design from the backlog (`IDN-xx` issues) and is not implemented until its issue is closed.

Cargo package name: `ao_idents`.

---

## Where this crate sits

```
                aoheyra  (app: Rust core + Kotlin UI)
                   │  depends on all three
        ┌──────────┼───────────┐
        ▼          ▼           ▼
    aoMesh ───▶ aoNetwork    aoIdents
        │                       ▲
        └───────────────────────┘

aoNetwork and aoIdents never depend on each other.
```

aoMesh treats `NodeId` as an opaque type and calls aoIdents for signing, sealing, verification and replay checks. aoNetwork never sees any of it.

## What it provides

| Area | Provided | Issue |
|---|---|---|
| **Identity** | `Identity::generate(rng)`, `from_seed`; one 32-byte seed derives the Ed25519 signing key and the X25519 agreement key via HKDF with separate labels; `NodeId` | IDN-02, 03 |
| **Sign / verify** | Context-separated signatures with mandatory domain string; strict verification | IDN-04 |
| **Key storage seam** | `KeyStore` trait over sealed secret blobs; `MemoryKeyStore` for tests (Android Keystore impl lives in aoheyra) | IDN-05 |
| **Identity card** | `IdentityCard` (self-signed), QR text form `aoheyra:id:<base32>` with checksum, short hash for announcements | IDN-07 |
| **Sealed messages** | 1:1 offline-friendly sealed message; multi-recipient variant (about 8) | IDN-09, 10 |
| **Signed public blobs** | `SignedBlob {origin, seq, timestamp, payload, sig}` for presence and public channels | IDN-11 |
| **Rotating tags** | `RotatingTag`: 16-byte link tag and 8-byte beacon hint, unlinkable to `NodeId`; optional pairwise mode for contacts | IDN-12 |
| **Contacts** | Trust-on-first-use, key-change detection, safety number; `ContactStore` trait (aoheyra persists) | IDN-08 |
| **Replay guard** | Per-sender sliding window at the final recipient; serializable | IDN-14 |
| **Backup** | Seed export as Argon2id passphrase-encrypted blob; import verifies `NodeId` | IDN-06 |
| **Hop handshake** | Sans-IO Noise XX state machine authenticating neighbours against their `IdentityCard` | IDN-13 |
| **Later** | Prekeys and forward secrecy, key rotation and revocation, group keys | IDN-15..17 |

## Crypto suite (fixed by the ADR, IDN-01)

| Purpose | Primitive |
|---|---|
| Signatures | Ed25519, `verify_strict` only; small-order keys rejected |
| Key agreement | X25519 |
| AEAD | XChaCha20-Poly1305 |
| Hashing | BLAKE3 |
| Key derivation | HKDF |
| Password hashing (backup) | Argon2id, documented parameters |
| Hop handshake | Noise XX (`snow`) |

Rules that follow from this:

- **No custom primitives.** Only vetted, widely reviewed crates.
- A **suite-ID byte** sits in every structure so algorithms can change later.
- **One canonical binary encoding** for signed structures (hand-rolled fixed layouts or `postcard`, exactly one).
- Every signature and every KDF use has its **own domain-separation string**. A signature made under one context never verifies under another.
- `NodeId` = first 16 bytes of the hash of the public keys.
- Secrets are zeroized on drop, have redacted `Debug`, and `Clone` is explicit.
- Anything needing randomness takes an **RNG parameter**; nothing reads global randomness or the system clock.

## Threat model (summary; full text is [docs/threat-model.md](docs/threat-model.md))

Attackers considered: passive eavesdropper, malicious relay, impersonator, spammer or Sybil, device thief.

Protected in the MVP: message **content** (sealed to the recipient), sender **authenticity**, integrity, replay at the recipient.

**Explicitly not protected in the MVP** (the threat model must say so plainly):

- Origin and destination are **visible to relays** so they can rate-limit spam.
- **No forward secrecy** against compromise of the recipient's long-term key (addressed later by IDN-15).
- Contact graph and traffic patterns visible to anyone who can observe relays.

## API sketch

Illustrative; real signatures come from the issues above.

```rust
let id = Identity::generate(&mut rng);
let card = id.card("Alice", now)?;               // IdentityCard, self-signed
let qr = card.to_qr_string();                    // aoheyra:id:<base32>

let sealed = id.seal(&bob_card, message_id, plaintext, now, &mut rng)?;
let opened = bob.open(&sealed)?;                 // plaintext + authenticated sender

let sig = id.sign(ctx::MESH_PACKET, &bytes);
verify(&id.public(), ctx::MESH_PACKET, &bytes, &sig)?;
```

`open` fails for tampering with any field, for the wrong recipient, and (with `ReplayGuard`) for replays.

## Design rules

- **Pure and sans-IO.** No sockets, files, threads, FFI or global state. Persistence is behind traits (`KeyStore`, `ContactStore`) that aoheyra implements.
- **Typed errors only.** A changed key for a known `NodeId` is never silently accepted.
- **Distinct concerns stay distinct:** `ReplayGuard` here is a per-sender acceptance check at the final recipient. aoMesh's seen-cache is forwarding dedupe. Do not merge them.
- **Hardening is part of the feature,** not a later pass: known-answer vectors, property tests and audit gating ship with the code (IDN-18).

## Development

Requires Rust 1.85+ (edition 2024; the MSRV is pinned as `rust-version` in `Cargo.toml` and enforced by CI).

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo audit
cargo doc --no-deps --all-features
```

Test vectors live in `tests/vectors/`. CI fails on any security advisory.

## Roadmap

| Milestone | Issues | Outcome |
|---|---|---|
| **M0 Foundations** | IDN-00, 01, 02, 19 | Repo exists and CI is green; crypto-suite ADR; core types; threat model |
| **M1 Primitives** | IDN-03, 04, 05, 07 | Identity derivation, contextual signatures, `KeyStore`, identity card and QR |
| **M2 Messaging crypto** | IDN-09..12 | Sealed messages, multi-recipient, signed blobs, rotating tags |
| **M3 Contacts and replay** | IDN-08, 14 | Contact book logic, replay guard |
| **M4 Verification** | IDN-18 | Vectors, property tests, audit tooling |
| **M6 Hardening** | IDN-06, 13, 15, 16, 17 | Backup, hop handshake, prekeys/forward secrecy, rotation/revocation, group keys |

Issue titles carry the ID, e.g. `[IDN-09] Sealed message v1`.

## Contributing

1. Read the issue's scope and "Done when" line, the ADR (IDN-01) and the [threat model](docs/threat-model.md) (IDN-19).
2. Read the [rules](AGENTS.md); the cryptography section is stricter than in the other repos.
3. Security-sensitive changes need a reviewer other than the author.

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), not in a public issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option. Decision: APP-01, applied to all four repos.
