//! Core types: identifiers, key material, signatures and the typed error
//! every failure in this crate reports.
//!
//! Nothing here parses untrusted variable-length input yet (that arrives
//! with the card and message codecs); constructors take fixed-size arrays,
//! so they are total and cannot be made to over-allocate.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Crypto suite identifier.
///
/// Suite `0x01` is fixed by ADR-0001. Every structure that carries a suite
/// byte decodes it through [`TryFrom<u8>`], so an unknown suite is a typed
/// error rather than a guess.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SuiteId(u8);

impl SuiteId {
    /// Suite v1: Ed25519, X25519, XChaCha20-Poly1305, BLAKE3, HKDF-SHA-256.
    pub const V1: SuiteId = SuiteId(0x01);

    /// The suite byte as it appears on the wire.
    #[must_use]
    pub fn byte(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for SuiteId {
    type Error = IdentError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(SuiteId::V1),
            other => Err(IdentError::UnknownSuite(other)),
        }
    }
}

/// The 16-byte cryptographic identity of a node: the first 16 bytes of the
/// BLAKE3 hash of the public keys (ADR-0001, "NodeId derivation").
///
/// This is the identity relays and the directory key on; human-facing
/// handles are an alias for it (IDN-20), never a replacement.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; 16]);

impl NodeId {
    /// Wrap raw identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({self})")
    }
}

/// An Ed25519 signature: opaque bytes until verified against a context
/// (IDN-04). The constructor never claims validity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wrap raw signature bytes. Validity is decided by
    /// `PublicIdentity::verify`, never here.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

/// The public half of an identity: both public keys plus the signature
/// that binds the agreement key to the signing key (ADR-0001,
/// `bind-agreement`), so a substituted agreement key is detectable by any
/// verifier holding this struct.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    signing_pk: [u8; 32],
    agreement_pk: [u8; 32],
    agreement_binding: Signature,
}

impl PublicIdentity {
    /// Assemble from raw public key bytes and the binding signature.
    #[must_use]
    pub const fn new(
        signing_pk: [u8; 32],
        agreement_pk: [u8; 32],
        agreement_binding: Signature,
    ) -> Self {
        Self {
            signing_pk,
            agreement_pk,
            agreement_binding,
        }
    }

    /// The Ed25519 signing public key.
    #[must_use]
    pub fn signing_pk(&self) -> &[u8; 32] {
        &self.signing_pk
    }

    /// The X25519 agreement public key.
    #[must_use]
    pub fn agreement_pk(&self) -> &[u8; 32] {
        &self.agreement_pk
    }

    /// The signature binding `agreement_pk` to `signing_pk`.
    #[must_use]
    pub fn agreement_binding(&self) -> &Signature {
        &self.agreement_binding
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicIdentity { signing_pk: ")?;
        write_hex(f, &self.signing_pk)?;
        f.write_str(", agreement_pk: ")?;
        write_hex(f, &self.agreement_pk)?;
        f.write_str(", agreement_binding: ")?;
        fmt::Debug::fmt(&self.agreement_binding, f)?;
        f.write_str(" }")
    }
}

/// The secret half of an identity: the Ed25519 signing key and the X25519
/// agreement key derived from one 32-byte seed (ADR-0001 key hierarchy).
///
/// - zeroized on drop (the fields are `zeroize::Zeroizing`),
/// - `Debug` prints `<redacted>`, never contents,
/// - equality is constant-time (`subtle`),
/// - `Clone` is deliberate: key material must be duplicable for stores and
///   in-memory use, and every copy zeroizes on drop.
#[derive(Clone)]
pub struct SecretIdentity {
    signing_sk: Zeroizing<[u8; 32]>,
    agreement_sk: Zeroizing<[u8; 32]>,
}

impl SecretIdentity {
    /// Assemble from raw secret key bytes: HKDF output from
    /// `Identity::from_seed`, or a blob loaded back through a `KeyStore`.
    #[must_use]
    pub fn from_parts(signing_sk: [u8; 32], agreement_sk: [u8; 32]) -> Self {
        Self {
            signing_sk: Zeroizing::new(signing_sk),
            agreement_sk: Zeroizing::new(agreement_sk),
        }
    }

    /// The signing key bytes for signing inside this crate (IDN-04).
    /// Never exposed publicly: signatures go through `Identity::sign`.
    pub(crate) fn signing_sk(&self) -> &[u8; 32] {
        &self.signing_sk
    }

    /// The agreement key bytes for the Diffie-Hellman inside this
    /// crate (IDN-09). Never exposed publicly: sealed messages open
    /// through `SealedMessage::open`.
    pub(crate) fn agreement_sk(&self) -> &[u8; 32] {
        &self.agreement_sk
    }
}

impl Zeroize for SecretIdentity {
    fn zeroize(&mut self) {
        self.signing_sk.as_mut_slice().zeroize();
        self.agreement_sk.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for SecretIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretIdentity(<redacted>)")
    }
}

impl ConstantTimeEq for SecretIdentity {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.signing_sk
            .as_slice()
            .ct_eq(other.signing_sk.as_slice())
            & self
                .agreement_sk
                .as_slice()
                .ct_eq(other.agreement_sk.as_slice())
    }
}

impl PartialEq for SecretIdentity {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for SecretIdentity {}

/// Every failure this crate can report: typed, with context, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentError {
    /// A suite byte no version of this crate knows (ADR-0001: unknown is a
    /// typed error, never a guess).
    UnknownSuite(u8),
    /// An empty, over-long, non-ASCII or NUL-containing signature domain.
    InvalidDomain,
    /// A public key that does not decode, or is small-order ("weak").
    InvalidPublicKey,
    /// A signature that does not verify under the given context/message.
    InvalidSignature,
    /// A card display name over the 24-byte limit (IDN-07).
    NameTooLong,
    /// A card encoding with a bad length or an over-long name field
    /// (IDN-07).
    MalformedCard,
    /// A QR string without the `aoheyra:id:` prefix, outside the
    /// base32 alphabet, or with non-canonical padding (IDN-07).
    InvalidQr,
    /// A QR string whose 4-byte checksum does not match the card
    /// bytes (IDN-07).
    ChecksumMismatch,
    /// A payload whose sealed encoding would exceed the 65535-byte
    /// length field (IDN-09).
    PayloadTooLarge,
    /// AEAD authentication failed: wrong recipient, wrong message ID
    /// or a tampered field (IDN-09).
    OpenFailed,
    /// A sealed-message encoding or decrypted payload that does not
    /// parse (IDN-09).
    MalformedSealed,
    /// Presented keys that do not hash to the claimed `NodeId`: for
    /// a known contact this is a key change, for an unknown claim it
    /// is a mismatch - nothing was stored (IDN-08).
    KeyChanged(NodeId),
    /// A trust or petname change aimed at a `NodeId` the book does
    /// not hold (IDN-08).
    UnknownContact,
    /// A contact book already holding its maximum entry count
    /// (IDN-08).
    ContactBookFull,
    /// A petname over the 64-byte local limit (IDN-08).
    PetnameTooLong,
}

impl fmt::Display for IdentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentError::UnknownSuite(byte) => {
                write!(f, "unknown crypto suite byte 0x{byte:02x}")
            }
            IdentError::InvalidDomain => {
                f.write_str("invalid signature domain: must be 1..=255 ASCII bytes without NUL")
            }
            IdentError::InvalidPublicKey => f.write_str("invalid or small-order public key"),
            IdentError::InvalidSignature => f.write_str("signature does not verify"),
            IdentError::NameTooLong => f.write_str("display name exceeds the 24-byte card limit"),
            IdentError::MalformedCard => {
                f.write_str("identity card encoding is malformed or truncated")
            }
            IdentError::InvalidQr => {
                f.write_str("QR string must be aoheyra:id:<base32 A-Z2-7> with zero padding")
            }
            IdentError::ChecksumMismatch => {
                f.write_str("QR checksum does not match the card bytes")
            }
            IdentError::PayloadTooLarge => {
                f.write_str("payload exceeds the 65535-byte sealed encoding limit")
            }
            IdentError::OpenFailed => {
                f.write_str("seal did not open: wrong recipient, wrong message ID or tampered data")
            }
            IdentError::MalformedSealed => {
                f.write_str("sealed-message encoding is malformed or truncated")
            }
            IdentError::KeyChanged(node_id) => write!(
                f,
                "presented keys do not match claimed NodeId {node_id}: key change or mismatch, nothing stored"
            ),
            IdentError::UnknownContact => f.write_str("no such contact in the book"),
            IdentError::ContactBookFull => f.write_str("contact book is at its 512-entry capacity"),
            IdentError::PetnameTooLong => f.write_str("petname exceeds the 64-byte limit"),
        }
    }
}

impl std::error::Error for IdentError {}

/// Lowercase hex of `bytes`, no prefix or separators.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
