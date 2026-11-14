//! Identity cards and the QR string (IDN-07).
//!
//! An [`IdentityCard`] is the shareable, self-signed statement "this is
//! my public identity": both public keys, a display name, a creation
//! time and a signature over all of it. The QR form is
//! `aoheyra:id:<base32>` with a checksum, small enough for one QR
//! code, and a short hash of the card identifies it in announcements.

use crate::Identity;
use crate::identity::preimage;
use crate::sign::verify_signing_pk;
use crate::types::{IdentError, Signature, SuiteId};

/// Signature domain for the card self-signature (ADR-0001 registry).
const DOMAIN_CARD: &str = "aoheyra/idn/v1/card";

/// BLAKE3 input domain for the QR checksum and the announcement hash
/// (ADR-0001 registry).
const DOMAIN_CARD_HASH: &str = "aoheyra/idn/v1/card-hash";

/// Fixed prefix of the QR text form.
const QR_PREFIX: &str = "aoheyra:id:";

/// Maximum display-name length in bytes (backlog: at most 24).
const MAX_DISPLAY_NAME: usize = 24;

/// Fixed body bytes before the name: suite(1) + signing_pk(32) +
/// agreement_pk(32) + name_len(1) + created_at(8).
const BODY_FIXED: usize = 1 + 32 + 32 + 1 + 8;

/// Signature bytes after the body.
const SIG_LEN: usize = 64;

/// Minimum encoded card length: empty name.
const MIN_CARD_LEN: usize = BODY_FIXED + SIG_LEN;

/// RFC 4648 base32 alphabet, uppercase only (QR text is case-fixed).
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A self-signed public identity: both public keys, a display name of
/// at most 24 bytes, a creation time and the identity's signature
/// over all of it.
///
/// The signature covers the canonical encoding of every field except
/// itself, so a tampered key, name or timestamp never verifies.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityCard {
    suite: SuiteId,
    signing_pk: [u8; 32],
    agreement_pk: [u8; 32],
    display_name: Vec<u8>,
    created_at: u64,
    self_signature: Signature,
}

impl core::fmt::Debug for IdentityCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityCard")
            .field("suite", &self.suite)
            .field("signing_pk", &self.signing_pk)
            .field("agreement_pk", &self.agreement_pk)
            .field("display_name", &String::from_utf8_lossy(&self.display_name))
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Build this identity's card: `display_name` is at most 24 bytes
    /// ([`IdentError::NameTooLong`] beyond that), `created_at` is
    /// caller-owned time (this crate never reads a clock).
    pub fn card(&self, display_name: &[u8], created_at: u64) -> Result<IdentityCard, IdentError> {
        if display_name.len() > MAX_DISPLAY_NAME {
            return Err(IdentError::NameTooLong);
        }
        let public = self.public();
        let body = body_bytes(
            self.suite(),
            public.signing_pk(),
            public.agreement_pk(),
            display_name,
            created_at,
        );
        let self_signature = self.sign(DOMAIN_CARD, &body)?;
        Ok(IdentityCard {
            suite: self.suite(),
            signing_pk: *public.signing_pk(),
            agreement_pk: *public.agreement_pk(),
            display_name: display_name.to_vec(),
            created_at,
            self_signature,
        })
    }
}

impl IdentityCard {
    /// Verify the self-signature: strict Ed25519 over the canonical
    /// body under the card domain, so every field is covered.
    pub fn verify(&self) -> Result<(), IdentError> {
        verify_signing_pk(
            &self.signing_pk,
            DOMAIN_CARD,
            &self.body(),
            &self.self_signature,
        )
    }

    /// The canonical encoding: body bytes followed by the signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(self.self_signature.as_bytes());
        out
    }

    /// Decode an encoded card. Every field is bounds-checked before it
    /// is read: a truncated, over-long or over-named input is
    /// [`IdentError::MalformedCard`], an unknown suite byte is
    /// [`IdentError::UnknownSuite`]. Never panics; signature validity
    /// is decided by [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < MIN_CARD_LEN {
            return Err(IdentError::MalformedCard);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let mut signing_pk = [0u8; 32];
        signing_pk.copy_from_slice(&bytes[1..33]);
        let mut agreement_pk = [0u8; 32];
        agreement_pk.copy_from_slice(&bytes[33..65]);
        let name_len = bytes[65] as usize;
        if name_len > MAX_DISPLAY_NAME {
            return Err(IdentError::MalformedCard);
        }
        let body_len = BODY_FIXED + name_len;
        // Exact length catches truncation and trailing bytes alike.
        if bytes.len() != body_len + SIG_LEN {
            return Err(IdentError::MalformedCard);
        }
        let display_name = bytes[66..66 + name_len].to_vec();
        let mut created = [0u8; 8];
        created.copy_from_slice(&bytes[66 + name_len..body_len]);
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(&bytes[body_len..]);
        Ok(Self {
            suite,
            signing_pk,
            agreement_pk,
            display_name,
            created_at: u64::from_be_bytes(created),
            self_signature: Signature::from_bytes(sig),
        })
    }

    /// The QR text form `aoheyra:id:<base32>`: the encoded card plus a
    /// 4-byte checksum, base32-encoded. Worst case (24-byte name) is
    /// 277 characters, which fits a single QR code in byte mode.
    #[must_use]
    pub fn to_qr_string(&self) -> String {
        let card = self.encode();
        let checksum = card_hash(&card)[..4].to_vec();
        let mut payload = card;
        payload.extend_from_slice(&checksum);
        let mut out = String::with_capacity(QR_PREFIX.len() + payload.len() * 8 / 5 + 8);
        out.push_str(QR_PREFIX);
        out.push_str(&base32_encode(&payload));
        out
    }

    /// Parse and verify the QR text form: prefix, canonical base32,
    /// checksum, card structure and self-signature, in that order -
    /// a typo fails at the checksum, a tampered card at the
    /// signature. Errors: [`IdentError::InvalidQr`] (prefix or
    /// alphabet), [`IdentError::ChecksumMismatch`],
    /// [`IdentError::MalformedCard`], then the signature errors.
    pub fn from_qr_string(qr: &str) -> Result<Self, IdentError> {
        let payload = qr.strip_prefix(QR_PREFIX).ok_or(IdentError::InvalidQr)?;
        let decoded = base32_decode(payload)?;
        if decoded.len() < 4 {
            return Err(IdentError::MalformedCard);
        }
        let (card, checksum) = decoded.split_at(decoded.len() - 4);
        if checksum != &card_hash(card)[..4] {
            return Err(IdentError::ChecksumMismatch);
        }
        let card = Self::decode(card)?;
        card.verify()?;
        Ok(card)
    }

    /// An 8-byte hash of the card for short announcements: enough to
    /// name a card in a beacon without carrying it.
    #[must_use]
    pub fn announcement_hash(&self) -> [u8; 8] {
        let hash = card_hash(&self.encode());
        let mut out = [0u8; 8];
        out.copy_from_slice(&hash[..8]);
        out
    }

    /// The suite this card was signed under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The Ed25519 signing public key.
    #[must_use]
    pub fn signing_pk(&self) -> &[u8; 32] {
        &self.signing_pk
    }

    /// The X25519 agreement public key, covered by the self-signature.
    #[must_use]
    pub fn agreement_pk(&self) -> &[u8; 32] {
        &self.agreement_pk
    }

    /// The display name bytes (at most 24).
    #[must_use]
    pub fn display_name(&self) -> &[u8] {
        &self.display_name
    }

    /// The caller-owned creation time.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The self-signature over the canonical body.
    #[must_use]
    pub fn self_signature(&self) -> &Signature {
        &self.self_signature
    }

    /// The canonical body: `suite ‖ signing_pk ‖ agreement_pk ‖
    /// name_len ‖ name ‖ created_at` (ADR-0001 rules).
    fn body(&self) -> Vec<u8> {
        body_bytes(
            self.suite,
            &self.signing_pk,
            &self.agreement_pk,
            &self.display_name,
            self.created_at,
        )
    }
}

/// Assemble the canonical card body.
fn body_bytes(
    suite: SuiteId,
    signing_pk: &[u8; 32],
    agreement_pk: &[u8; 32],
    display_name: &[u8],
    created_at: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BODY_FIXED + display_name.len());
    out.push(suite.byte());
    out.extend_from_slice(signing_pk);
    out.extend_from_slice(agreement_pk);
    out.push(display_name.len() as u8);
    out.extend_from_slice(display_name);
    out.extend_from_slice(&created_at.to_be_bytes());
    out
}

/// BLAKE3 over the registered hash domain and the card bytes: the
/// checksum truncates to 4 bytes, the announcement hash to 8.
fn card_hash(card: &[u8]) -> [u8; 32] {
    let input = preimage(DOMAIN_CARD_HASH, card);
    *blake3::hash(&input).as_bytes()
}

/// RFC 4648 base32, no padding: the final character carries the
/// zero bits left over from the last byte.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32_ALPHABET[((acc >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(
            B32_ALPHABET[((acc << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// Decode RFC 4648 base32 without padding. Anything outside the
/// alphabet, or leftover bits that are not zero padding (a
/// non-canonical spelling of the same bytes), is
/// [`IdentError::InvalidQr`].
fn base32_decode(text: &str) -> Result<Vec<u8>, IdentError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.bytes() {
        let value = B32_ALPHABET
            .iter()
            .position(|&alphabet| alphabet == byte)
            .ok_or(IdentError::InvalidQr)? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Fewer than five leftover bits by construction; they must be
    // zero, so only one spelling of a byte string is accepted.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(IdentError::InvalidQr);
    }
    Ok(out)
}
