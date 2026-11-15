//! Key rotation statements and revocation notices (IDN-16).
//!
//! A [`RotationStatement`] chains a fresh identity to the one it
//! replaces: the **old** key signs the successor's keys, so trust in
//! the old contact authorises the new one, and the **new** key
//! counter-signs, so no unwilling third party can be designated as
//! someone's successor without holding that successor's secret. The
//! contact book applies a verified statement as an explicit operation
//! ([`ContactBook::rotate`](crate::ContactBook::rotate)), never as a
//! side effect of an announcement.
//!
//! A [`RevocationNotice`] is the opposite direction of trust: an
//! identity signing that its own keys are dead, so gossip can retire a
//! key before its holder - or whoever stole it - can abuse it. The
//! contact book answers with [`ContactBook::revoke`](crate::ContactBook::revoke),
//! which blocks instead of deleting: a deleted contact would come back
//! through trust-on-first-use on the next presentation.
//!
//! Both encodings are fixed length, suite byte first, fields in the
//! documented order (ADR-0001 canonical encoding):
//!
//! ```text
//! rotation:   suite(1) | old_signing_pk(32) | old_agreement_pk(32)
//!             | new_signing_pk(32) | new_agreement_pk(32)
//!             | old_signature(64) | new_signature(64)        = 257 bytes
//!
//! revocation: suite(1) | signing_pk(32) | agreement_pk(32)
//!             | signature(64)                                = 97 bytes
//! ```
//!
//! Both signatures cover the body - everything before the signature
//! fields - under their own ADR-0001 domain, so a statement or notice
//! never verifies in another role.

use crate::Identity;
use crate::identity::compute_node_id;
use crate::sign::verify_signing_pk;
use crate::types::{IdentError, NodeId, Signature, SuiteId};

/// Signature domain for rotation statements (ADR-0001 registry).
const DOMAIN_ROTATION: &str = "aoheyra/idn/v1/rotation";

/// Signature domain for revocation notices (ADR-0001 registry).
const DOMAIN_REVOCATION: &str = "aoheyra/idn/v1/revocation";

/// Bytes per public key.
const KEY_LEN: usize = 32;

/// Ed25519 signature bytes.
const SIG_LEN: usize = 64;

/// Everything both rotation signatures cover: suite + four keys.
const ROTATION_BODY_LEN: usize = 1 + 4 * KEY_LEN;

/// Total rotation statement length: body + both signatures.
const ROTATION_LEN: usize = ROTATION_BODY_LEN + 2 * SIG_LEN;

/// Everything the revocation signature covers: suite + two keys.
const REVOCATION_BODY_LEN: usize = 1 + 2 * KEY_LEN;

/// Total revocation notice length: body + signature.
const REVOCATION_LEN: usize = REVOCATION_BODY_LEN + SIG_LEN;

/// A signed statement chaining a successor identity to the one it
/// replaces (IDN-16).
///
/// The old key signs the successor's keys ("this is me now"), the new
/// key counter-signs the same body ("I accept"), so both directions of
/// the succession are proven by the secrets they name. A statement
/// whose two key pairs are identical is refused
/// ([`IdentError::InvalidRotation`]): rotating a contact onto itself
/// would erase it instead of migrating it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationStatement {
    suite: SuiteId,
    old_signing_pk: [u8; KEY_LEN],
    old_agreement_pk: [u8; KEY_LEN],
    new_signing_pk: [u8; KEY_LEN],
    new_agreement_pk: [u8; KEY_LEN],
    old_signature: Signature,
    new_signature: Signature,
}

/// A self-signed notice that an identity's keys are dead (IDN-16),
/// meant for gossip: peers that receive it stop trusting the keys
/// before the holder - or a thief - can act on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationNotice {
    suite: SuiteId,
    signing_pk: [u8; KEY_LEN],
    agreement_pk: [u8; KEY_LEN],
    signature: Signature,
}

impl RotationStatement {
    /// Sign a rotation from `old` to `new` with both identities'
    /// secrets.
    ///
    /// # Errors
    ///
    /// [`IdentError::InvalidRotation`] when the two identities are the
    /// same (rotating onto itself); a signing failure otherwise.
    pub fn sign(old: &Identity, new: &Identity) -> Result<Self, IdentError> {
        if old.node_id() == new.node_id() {
            return Err(IdentError::InvalidRotation);
        }
        let old_public = old.public();
        let new_public = new.public();
        let body = rotation_body(
            old.suite(),
            old_public.signing_pk(),
            old_public.agreement_pk(),
            new_public.signing_pk(),
            new_public.agreement_pk(),
        );
        let old_signature = old.sign(DOMAIN_ROTATION, &body)?;
        let new_signature = new.sign(DOMAIN_ROTATION, &body)?;
        Ok(Self {
            suite: old.suite(),
            old_signing_pk: *old_public.signing_pk(),
            old_agreement_pk: *old_public.agreement_pk(),
            new_signing_pk: *new_public.signing_pk(),
            new_agreement_pk: *new_public.agreement_pk(),
            old_signature,
            new_signature,
        })
    }

    /// Verify both signatures and the statement's own consistency.
    ///
    /// # Errors
    ///
    /// [`IdentError::InvalidRotation`] when old and new are the same
    /// key pair; [`IdentError::InvalidPublicKey`] /
    /// [`IdentError::InvalidSignature`] when either signature does not
    /// verify. The cheap consistency check runs first, so a crafted
    /// self-rotation reports why it is refused rather than how its
    /// signatures fail.
    pub fn verify(&self) -> Result<(), IdentError> {
        if self.old_signing_pk == self.new_signing_pk
            && self.old_agreement_pk == self.new_agreement_pk
        {
            return Err(IdentError::InvalidRotation);
        }
        let body = rotation_body(
            self.suite,
            &self.old_signing_pk,
            &self.old_agreement_pk,
            &self.new_signing_pk,
            &self.new_agreement_pk,
        );
        verify_signing_pk(
            &self.old_signing_pk,
            DOMAIN_ROTATION,
            &body,
            &self.old_signature,
        )?;
        verify_signing_pk(
            &self.new_signing_pk,
            DOMAIN_ROTATION,
            &body,
            &self.new_signature,
        )
    }

    /// The [`NodeId`] being replaced.
    #[must_use]
    pub fn old_node_id(&self) -> NodeId {
        compute_node_id(&self.old_signing_pk, &self.old_agreement_pk)
    }

    /// The successor's [`NodeId`].
    #[must_use]
    pub fn new_node_id(&self) -> NodeId {
        compute_node_id(&self.new_signing_pk, &self.new_agreement_pk)
    }

    /// The old identity's public keys: `(signing_pk, agreement_pk)`.
    #[must_use]
    pub fn old_keys(&self) -> (&[u8; KEY_LEN], &[u8; KEY_LEN]) {
        (&self.old_signing_pk, &self.old_agreement_pk)
    }

    /// The successor's public keys: `(signing_pk, agreement_pk)`.
    #[must_use]
    pub fn new_keys(&self) -> (&[u8; KEY_LEN], &[u8; KEY_LEN]) {
        (&self.new_signing_pk, &self.new_agreement_pk)
    }

    /// The canonical encoding: body bytes followed by both signatures.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = rotation_body(
            self.suite,
            &self.old_signing_pk,
            &self.old_agreement_pk,
            &self.new_signing_pk,
            &self.new_agreement_pk,
        );
        out.extend_from_slice(self.old_signature.as_bytes());
        out.extend_from_slice(self.new_signature.as_bytes());
        out
    }

    /// Decode an encoded rotation statement. The length is fixed, so
    /// truncated, over-long or trailing input is
    /// [`IdentError::MalformedRotation`] and an unknown suite byte is
    /// [`IdentError::UnknownSuite`]. Never panics on any input;
    /// signature validity is decided by [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() != ROTATION_LEN {
            return Err(IdentError::MalformedRotation);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let old_signing_pk = copy_key(&bytes[1..1 + KEY_LEN], IdentError::MalformedRotation)?;
        let old_agreement_pk = copy_key(
            &bytes[1 + KEY_LEN..1 + 2 * KEY_LEN],
            IdentError::MalformedRotation,
        )?;
        let new_signing_pk = copy_key(
            &bytes[1 + 2 * KEY_LEN..1 + 3 * KEY_LEN],
            IdentError::MalformedRotation,
        )?;
        let new_agreement_pk = copy_key(
            &bytes[1 + 3 * KEY_LEN..1 + 4 * KEY_LEN],
            IdentError::MalformedRotation,
        )?;
        let old_signature = copy_signature(
            &bytes[ROTATION_BODY_LEN..ROTATION_BODY_LEN + SIG_LEN],
            IdentError::MalformedRotation,
        )?;
        let new_signature = copy_signature(
            &bytes[ROTATION_BODY_LEN + SIG_LEN..],
            IdentError::MalformedRotation,
        )?;
        Ok(Self {
            suite,
            old_signing_pk,
            old_agreement_pk,
            new_signing_pk,
            new_agreement_pk,
            old_signature,
            new_signature,
        })
    }
}

impl RevocationNotice {
    /// Sign a revocation with the identity's own secret: only the
    /// holder of a key can retire it.
    ///
    /// # Errors
    ///
    /// A signing failure (the domain is a fixed registered string, so
    /// in practice none).
    pub fn sign(identity: &Identity) -> Result<Self, IdentError> {
        let public = identity.public();
        let body = revocation_body(identity.suite(), public.signing_pk(), public.agreement_pk());
        let signature = identity.sign(DOMAIN_REVOCATION, &body)?;
        Ok(Self {
            suite: identity.suite(),
            signing_pk: *public.signing_pk(),
            agreement_pk: *public.agreement_pk(),
            signature,
        })
    }

    /// Verify the self-signature.
    ///
    /// # Errors
    ///
    /// [`IdentError::InvalidPublicKey`] / [`IdentError::InvalidSignature`]
    /// when the notice was not signed by the keys it revokes.
    pub fn verify(&self) -> Result<(), IdentError> {
        let body = revocation_body(self.suite, &self.signing_pk, &self.agreement_pk);
        verify_signing_pk(&self.signing_pk, DOMAIN_REVOCATION, &body, &self.signature)
    }

    /// The [`NodeId`] whose keys the notice retires.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        compute_node_id(&self.signing_pk, &self.agreement_pk)
    }

    /// The canonical encoding: body bytes followed by the signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = revocation_body(self.suite, &self.signing_pk, &self.agreement_pk);
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Decode an encoded revocation notice. The length is fixed, so
    /// truncated, over-long or trailing input is
    /// [`IdentError::MalformedRevocation`] and an unknown suite byte
    /// is [`IdentError::UnknownSuite`]. Never panics on any input;
    /// signature validity is decided by [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() != REVOCATION_LEN {
            return Err(IdentError::MalformedRevocation);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let signing_pk = copy_key(&bytes[1..1 + KEY_LEN], IdentError::MalformedRevocation)?;
        let agreement_pk = copy_key(
            &bytes[1 + KEY_LEN..1 + 2 * KEY_LEN],
            IdentError::MalformedRevocation,
        )?;
        let signature = copy_signature(
            &bytes[REVOCATION_BODY_LEN..],
            IdentError::MalformedRevocation,
        )?;
        Ok(Self {
            suite,
            signing_pk,
            agreement_pk,
            signature,
        })
    }
}

/// The signed rotation body: suite byte then the four keys in
/// (old, new) order. Both signatures cover exactly these bytes, which
/// fixes each key's role positionally.
fn rotation_body(
    suite: SuiteId,
    old_signing_pk: &[u8; KEY_LEN],
    old_agreement_pk: &[u8; KEY_LEN],
    new_signing_pk: &[u8; KEY_LEN],
    new_agreement_pk: &[u8; KEY_LEN],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(ROTATION_BODY_LEN);
    body.push(suite.byte());
    body.extend_from_slice(old_signing_pk);
    body.extend_from_slice(old_agreement_pk);
    body.extend_from_slice(new_signing_pk);
    body.extend_from_slice(new_agreement_pk);
    debug_assert_eq!(body.len(), ROTATION_BODY_LEN);
    body
}

/// The signed revocation body: suite byte then the two keys.
fn revocation_body(
    suite: SuiteId,
    signing_pk: &[u8; KEY_LEN],
    agreement_pk: &[u8; KEY_LEN],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(REVOCATION_BODY_LEN);
    body.push(suite.byte());
    body.extend_from_slice(signing_pk);
    body.extend_from_slice(agreement_pk);
    debug_assert_eq!(body.len(), REVOCATION_BODY_LEN);
    body
}

/// Copy a fixed-length key field out of a decode slice. The caller
/// has already checked the total length, so `malformed` is the
/// defensive arm - reported in the caller's own variant.
fn copy_key(bytes: &[u8], malformed: IdentError) -> Result<[u8; KEY_LEN], IdentError> {
    bytes.try_into().map_err(|_| malformed)
}

/// Copy a fixed-length signature field out of a decode slice; same
/// defensive contract as [`copy_key`].
fn copy_signature(bytes: &[u8], malformed: IdentError) -> Result<Signature, IdentError> {
    let raw: [u8; SIG_LEN] = bytes.try_into().map_err(|_| malformed)?;
    Ok(Signature::from_bytes(raw))
}
