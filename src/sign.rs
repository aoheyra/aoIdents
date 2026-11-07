//! Context-separated signatures (ADR-0001 domain separation).
//!
//! Every signature covers `u8 domain_len ‖ domain ‖ msg`, so a signature
//! made under one context can never verify under another, and no domain
//! can be confused with a message prefix. Verification is strict Ed25519:
//! canonical encodings only, small-order keys and points rejected.

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, VerifyingKey};

use crate::Identity;
use crate::identity::{DOMAIN_BIND_AGREEMENT, preimage};
use crate::types::{IdentError, PublicIdentity, Signature};

impl Identity {
    /// Sign `msg` under the mandatory domain string `ctx`.
    ///
    /// `ctx` must be a registered domain: 1..=255 ASCII bytes, no NUL
    /// (ADR-0001 registry). Anything else is [`IdentError::InvalidDomain`];
    /// a wrong length can never truncate silently because validation
    /// happens before the length prefix is written.
    pub fn sign(&self, ctx: &str, msg: &[u8]) -> Result<Signature, IdentError> {
        validate_domain(ctx)?;
        let key = SigningKey::from_bytes(self.secret().signing_sk());
        let sig = key.sign(&preimage(ctx, msg));
        Ok(Signature::from_bytes(sig.to_bytes()))
    }
}

impl PublicIdentity {
    /// Verify a signature over `msg` under `ctx`, with strict Ed25519
    /// rules: canonical signature encoding, no small-order public key or
    /// `R` point, context bound into the preimage.
    ///
    /// Errors: [`IdentError::InvalidDomain`] (bad context),
    /// [`IdentError::InvalidPublicKey`] (key does not decode or is
    /// small-order), [`IdentError::InvalidSignature`] (does not verify).
    pub fn verify(&self, ctx: &str, msg: &[u8], sig: &Signature) -> Result<(), IdentError> {
        validate_domain(ctx)?;
        let vk = VerifyingKey::from_bytes(self.signing_pk())
            .map_err(|_| IdentError::InvalidPublicKey)?;
        if vk.is_weak() {
            // A small-order key would "verify" almost any message.
            return Err(IdentError::InvalidPublicKey);
        }
        let sig = DalekSignature::from_bytes(sig.as_bytes());
        vk.verify_strict(&preimage(ctx, msg), &sig)
            .map_err(|_| IdentError::InvalidSignature)
    }

    /// Verify the bind-agreement binding: the agreement key belongs to
    /// this signing key (ADR-0001). A substituted agreement key fails
    /// here with a typed error.
    pub fn verify_binding(&self) -> Result<(), IdentError> {
        self.verify(
            DOMAIN_BIND_AGREEMENT,
            self.agreement_pk(),
            self.agreement_binding(),
        )
    }
}

/// Validate a signature domain: 1..=255 ASCII bytes, no NUL - exactly the
/// range the preimage's one-byte length prefix can represent.
pub(crate) fn validate_domain(domain: &str) -> Result<(), IdentError> {
    if domain.is_empty() || domain.len() > 255 || !domain.is_ascii() || domain.contains('\0') {
        return Err(IdentError::InvalidDomain);
    }
    Ok(())
}
