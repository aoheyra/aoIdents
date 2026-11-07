//! Identity generation and derivation: the ADR-0001 key hierarchy.
//!
//! One 32-byte seed derives everything: an Ed25519 signing key and an
//! X25519 agreement key through HKDF with distinct labels, a `NodeId`
//! hashing both public keys, and a binding signature that ties the
//! agreement key to the signing key. Randomness is injected - nothing here
//! reads a global RNG.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as AgreementPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::types::{NodeId, PublicIdentity, SecretIdentity, Signature, SuiteId};

/// HKDF Extract salt: the suite byte (ADR-0001, "Key derivation").
const SUITE_BYTE: u8 = 0x01;

/// Signature domain: agreement key bound to identity (ADR-0001 registry).
pub(crate) const DOMAIN_BIND_AGREEMENT: &str = "aoheyra/idn/v1/bind-agreement";

/// BLAKE3 input domain for `NodeId` (ADR-0001 registry).
const DOMAIN_NODE_ID: &str = "aoheyra/idn/v1/node-id";

/// HKDF info label for the signing key (ADR-0001 registry).
const INFO_SIGNING: &str = "aoheyra/idn/v1/derive/signing";

/// HKDF info label for the agreement key (ADR-0001 registry).
const INFO_AGREEMENT: &str = "aoheyra/idn/v1/derive/agreement";

/// One identity: the public half (shareable), the secret half (zeroized),
/// and the derived `NodeId`.
///
/// `Debug` prints the public parts and a redacted secret.
pub struct Identity {
    suite: SuiteId,
    public: PublicIdentity,
    secret: SecretIdentity,
    node_id: NodeId,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("suite", &self.suite)
            .field("public", &self.public)
            .field("secret", &self.secret) // redacted by SecretIdentity
            .field("node_id", &self.node_id)
            .finish()
    }
}

impl Identity {
    /// Generate a fresh identity from the injected RNG (32 seed bytes).
    pub fn generate<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let identity = Self::from_seed(seed);
        seed.zeroize();
        identity
    }

    /// Derive an identity from a fixed 32-byte seed (ADR-0001 hierarchy).
    ///
    /// Deterministic: the same seed always produces the same keys, binding
    /// and `NodeId` (known-answer tests in `tests/idn03_identity.rs`).
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let mut signing_sk = hkdf_expand(&seed, INFO_SIGNING);
        let mut agreement_sk = hkdf_expand(&seed, INFO_AGREEMENT);

        let signing_key = SigningKey::from_bytes(&signing_sk);
        let signing_pk = signing_key.verifying_key().to_bytes();

        let agreement_secret = StaticSecret::from(agreement_sk);
        let agreement_pk = AgreementPublicKey::from(&agreement_secret).to_bytes();

        // Bind the agreement key to this identity so a substituted key is
        // detectable by any verifier (ADR-0001, bind-agreement).
        let binding = signing_key.sign(&preimage(DOMAIN_BIND_AGREEMENT, &agreement_pk));
        let binding = Signature::from_bytes(binding.to_bytes());

        let node_id = compute_node_id(&signing_pk, &agreement_pk);

        let public = PublicIdentity::new(signing_pk, agreement_pk, binding);
        let secret = SecretIdentity::from_parts(signing_sk, agreement_sk);

        // Local copies of key material never outlive this function.
        signing_sk.zeroize();
        agreement_sk.zeroize();
        seed.zeroize();

        Self {
            suite: SuiteId::V1,
            public,
            secret,
            node_id,
        }
    }

    /// The shareable public half, including the binding signature.
    #[must_use]
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// The derived `NodeId`: BLAKE3 over domain, suite byte and both
    /// public keys, truncated to 16 bytes (ADR-0001).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The suite this identity was derived under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The secret half, for signing inside this crate (IDN-04).
    pub(crate) fn secret(&self) -> &SecretIdentity {
        &self.secret
    }
}

/// HKDF-SHA-256 expand with salt = suite byte, one label per use
/// (ADR-0001). Returns32 bytes.
fn hkdf_expand(seed: &[u8; 32], info: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&[SUITE_BYTE]), seed);
    let mut okm = [0u8; 32];
    // RFC 5869 caps HKDF-Expand output at 255 * HashLen = 8160 bytes for
    // SHA-256, so requesting 32 bytes can never fail: the error depends
    // only on this constant, never on the (external) seed. This mirrors
    // the `hkdf` crate's own documented usage.
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is always a valid HKDF-SHA-256 output length");
    okm
}

/// `NodeId = BLAKE3(domain ‖ suite byte ‖ signing_pk ‖ agreement_pk)[..16]`
/// (ADR-0001). Both public keys are hashed so an identity can never be
/// reinterpreted under different key material.
fn compute_node_id(signing_pk: &[u8; 32], agreement_pk: &[u8; 32]) -> NodeId {
    let mut input = Vec::with_capacity(DOMAIN_NODE_ID.len() + 1 + 32 + 32);
    input.extend_from_slice(DOMAIN_NODE_ID.as_bytes());
    input.push(SUITE_BYTE);
    input.extend_from_slice(signing_pk);
    input.extend_from_slice(agreement_pk);

    let digest = blake3::hash(&input);
    let mut bytes = [0u8; 16];
    // digest is BLAKE3-256 (32 bytes); slicing to 16 cannot go out of range.
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    NodeId::from_bytes(bytes)
}

/// ADR-0001 signature preimage: `u8 domain_len ‖ domain ‖ msg`, so no
/// domain can be confused with a message prefix.
///
/// `domain` must be one of this crate's ADR-registered constants (all well
/// under 256 bytes). User-supplied contexts are validated before this is
/// called (IDN-04), and `tests/idn03_identity.rs` checks every constant
/// against an independently built preimage, so a too-long domain fails
/// there instead of truncating silently.
pub(crate) fn preimage(domain: &str, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + domain.len() + msg.len());
    out.push(domain.len() as u8);
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(msg);
    out
}
