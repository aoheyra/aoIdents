# ADR-0001: Crypto suite v1 and canonical encoding

- **Status:** accepted, pending sign-off by a reviewer other than the author (IDN-01 done-when)
- **Date:** 2026-11-05
- **Related:** IDN-02..IDN-17 implement this; IDN-06 (Argon2id) and IDN-13 (Noise) pin their own parameters; IDN-20 (handle) uses the derivation namespace

## Decision

Suite ID `0x01` fixes the primitives below. Every structure starts with its suite byte; an unknown suite byte is a typed error, never a guess.

| Use | Primitive | Crate | Rule |
|---|---|---|---|
| Signatures | Ed25519 | `ed25519-dalek` | `verify_strict` only; small-order and non-canonical keys rejected; batch verification deferred (IDN-04) |
| Key agreement | X25519 | `x25519-dalek` | all-zero shared secret rejected (contributory behaviour) |
| AEAD | XChaCha20-Poly1305 | `chacha20poly1305` | 24-byte nonce from the injected RNG, fresh per encryption, never reused |
| Hash, IDs | BLAKE3-256 | `blake3` | truncated to 16 bytes for `NodeId` (128-bit collision resistance) |
| Key derivation | HKDF-SHA-256 (RFC 5869) | `hkdf` + `sha2` | Extract with salt = suite byte `0x01`; one distinct `info` string per use (table below) |
| Password KDF (IDN-06) | Argon2id | `argon2` | parameters documented in IDN-06 |
| Hop handshake (IDN-13) | Noise XX | `snow` | separate protocol; static keys verified against the IdentityCard |

KDF options: **HKDF-SHA-256 (chosen)** — the backlog specifies HKDF; RFC 5869, standard, audited; SHA-256 exists only inside HKDF. BLAKE3-KDF rejected: one less crate, but it is not HKDF and would silently diverge from the stated suite.

No custom primitives. Every crate is the mainstream RustCrypto/dalek implementation, MIT/Apache-2.0, already covered by `deny.toml`. This ADR itself adds no dependencies.

## Key hierarchy (IDN-03)

- Seed: 32 bytes from the injected CSPRNG (`Identity::generate`) or fixed input bytes (`from_seed`).
- `signing_sk = HKDF(seed, info = "aoheyra/idn/v1/derive/signing") → 32 bytes`
- `agreement_sk = HKDF(seed, info = "aoheyra/idn/v1/derive/agreement") → 32 bytes` (clamped as X25519 requires)
- The agreement public key is bound to the identity by an Ed25519 signature (domain `…/bind-agreement`), so a substituted key is detectable.
- `NodeId = BLAKE3("aoheyra/idn/v1/node-id" ‖ 0x01 ‖ signing_pk ‖ agreement_pk)[..16]`

Both public keys are hashed: a `NodeId` can never be reinterpreted under different key material. The suite byte is included so a future suite cannot collide with v1 identities.

## Domain separation

Exactly one string from the namespace `aoheyra/idn/v1/...` (ASCII, no NUL) per signature or KDF use. Signature preimage is `u8 domain_len ‖ domain ‖ msg`, so no domain can be confused with a message prefix. Strings are versioned (`v1`): a suite change bumps the namespace instead of editing strings in place. **New uses must add a row here first** — this table is the registry.

| Domain string | Kind | Used by |
|---|---|---|
| `aoheyra/idn/v1/derive/signing` | HKDF info | seed → signing key (IDN-03) |
| `aoheyra/idn/v1/derive/agreement` | HKDF info | seed → agreement key (IDN-03) |
| `aoheyra/idn/v1/node-id` | BLAKE3 input | `NodeId` derivation (IDN-03) |
| `aoheyra/idn/v1/bind-agreement` | signature | agreement key bound to identity (IDN-03) |
| `aoheyra/idn/v1/card` | signature | IdentityCard self-signature (IDN-07) |
| `aoheyra/idn/v1/card-hash` | BLAKE3 input | QR checksum (4 bytes) and card announcement hash (8 bytes) (IDN-07) |
| `aoheyra/idn/v1/msg` | signature | sender authentication inside sealed message (IDN-09) |
| `aoheyra/idn/v1/blob` | signature | SignedBlob: presence, public channels (IDN-11) |
| `aoheyra/idn/v1/prekey-bundle` | signature | signed prekey bundle (IDN-15) |
| `aoheyra/idn/v1/rotation` | signature | key rotation statement (IDN-16) |
| `aoheyra/idn/v1/revocation` | signature | revocation notice (IDN-16) |
| `aoheyra/idn/v1/group-admin` | signature | channel member add/remove (IDN-17) |
| `aoheyra/idn/v1/seal` | HKDF info | ephemeral DH → AEAD key (IDN-09) |
| `aoheyra/idn/v1/wrap` | HKDF info | content key per recipient (IDN-10) |
| `aoheyra/idn/v1/pairwise-tag` | HKDF info | contact-recognisable rotating tag (IDN-12) |
| `aoheyra/idn/v1/epoch-tag` | HKDF info | baseline per-epoch rotating tag, suffixed with the epoch index (IDN-12) |
| `aoheyra/idn/v1/backup` | HKDF info | passphrase-encrypted backup blob (IDN-06) |
| `aoheyra/idn/v1/prekey` | HKDF info | X3DH initial agreement (IDN-15) |
| `aoheyra/idn/v1/group-sender` | HKDF info | sender key for channels (IDN-17) |
| `aoheyra/idn/v1/safety-number` | BLAKE3 input | out-of-band comparison (IDN-08) |
| `aoheyra/idn/v1/handle` | BLAKE3 input | handle number derivation (IDN-20) |

## Canonical encoding

**One** encoding for every structure that is signed, hashed or verified: **hand-rolled fixed layouts**.

Options: `postcard` — deterministic, but drags `serde` into signed structures and yields less explicit decode errors than bounds-checked layouts. Chosen against: zero dependencies, explicit errors, and one style across the project (aoNetwork hand-rolls its wire format too).

Rules:

1. Fields in the documented order; integers big-endian, fixed width.
2. Byte strings length-prefixed (`u8` or `u16`, as documented per field).
3. Decode bounds-checks every field before indexing; trailing bytes rejected; unknown suite byte rejected.
4. No `serde` on any signed or hashed structure.
5. Signatures cover the encoded bytes exactly — never a re-encoding.

The QR string (`aoheyra:id:<base32>`, IDN-07) and the aoNetwork/aoMesh wire formats are separate encodings, not governed here.

## Secret handling

Zeroize on drop; redacted `Debug`; explicit `Clone`; constant-time comparison (`subtle`) for secret-derived values; randomness and time are always parameters — nothing reads global RNG or the clock.

## Consequences

- Upgrades are unambiguous: new suite byte, new namespace version; old structures stay verifiable under their own suite.
- SHA-256 enters the tree only inside HKDF — accepted cost of the stated suite.
- The handle number (IDN-20) is display-level, not a security boundary: uniqueness comes from the key, not the 12 digits.
