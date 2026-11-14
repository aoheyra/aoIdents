//! Sealed messages: one-to-one encryption that works offline (IDN-09).
//!
//! The sender draws a fresh ephemeral X25519 key, derives an AEAD key
//! from the ephemeral-to-recipient-static Diffie-Hellman via HKDF,
//! signs the plaintext and the recipient's `NodeId` with its identity
//! key, and encrypts everything under XChaCha20-Poly1305. The
//! associated data binds the suite, the message ID and the recipient.
//!
//! The recipient is offline when the message is created: only their
//! public identity is needed. Opening requires their secret identity.
//!
//! **Honest limitation:** there is no forward secrecy against
//! recipient key compromise. The content key is a DH against the
//! recipient's *static* agreement key, so anyone holding that secret
//! can open any past sealed message they recorded. Prekeys (IDN-15)
//! are the planned fix; this document does not pretend otherwise.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as AgreementPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::Identity;
use crate::identity::{compute_node_id, hkdf_expand};
use crate::types::{IdentError, NodeId, PublicIdentity, Signature, SuiteId};

/// Signature domain: sender authentication inside the sealed message
/// (ADR-0001 registry).
const DOMAIN_MSG: &str = "aoheyra/idn/v1/msg";

/// HKDF info: ephemeral DH to AEAD key (ADR-0001 registry).
const INFO_SEAL: &str = "aoheyra/idn/v1/seal";

/// Length of the message identifier bound into the associated data.
/// Fixed so the associated data layout is unambiguous.
pub const MSG_ID_LEN: usize = 16;

/// The authenticated sender inside the ciphertext:
/// `signing_pk(32) ‖ agreement_pk(32) ‖ agreement_binding(64)`.
const SENDER_IDENTITY_LEN: usize = 32 + 32 + 64;

/// The sender's signature over `plaintext ‖ recipient NodeId`.
const MSG_SIG_LEN: usize = 64;

/// XChaCha20-Poly1305 nonce length (ADR-0001: 24 bytes from the
/// injected RNG, fresh per encryption).
const NONCE_LEN: usize = 24;

/// Poly1305 tag length, appended to the ciphertext.
const TAG_LEN: usize = 16;

/// `suite(1) ‖ eph_pk(32) ‖ nonce(24) ‖ ciphertext_len(2)`.
const HEADER_LEN: usize = 1 + 32 + NONCE_LEN + 2;

/// Smallest possible ciphertext: sender identity, signature, empty
/// plaintext, AEAD tag.
const MIN_CIPHERTEXT_LEN: usize = SENDER_IDENTITY_LEN + MSG_SIG_LEN + TAG_LEN;

/// Largest plaintext that still fits the `u16` ciphertext length.
const MAX_PLAINTEXT_LEN: usize = u16::MAX as usize - MIN_CIPHERTEXT_LEN;

/// A sealed message: encryptable by anyone holding the recipient's
/// public identity, openable only by the recipient.
///
/// `Debug` prints field lengths, never ciphertext contents.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedMessage {
    suite: SuiteId,
    eph_pk: [u8; 32],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// What [`SealedMessage::open`] yields: the plaintext and the sender
/// whose identity is authenticated by the signature inside the seal.
///
/// `Debug` prints the plaintext length, never the plaintext.
pub struct OpenedMessage {
    plaintext: Vec<u8>,
    sender: PublicIdentity,
}

impl core::fmt::Debug for SealedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedMessage")
            .field("suite", &self.suite)
            .field("eph_pk", &self.eph_pk)
            .field("nonce", &self.nonce)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl core::fmt::Debug for OpenedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedMessage")
            .field("plaintext_len", &self.plaintext.len())
            .field("sender", &self.sender)
            .finish()
    }
}

impl SealedMessage {
    /// Seal `plaintext` to `recipient` under an associated data of
    /// `suite`, `msg_id` and the recipient's `NodeId`.
    ///
    /// `rng` supplies the ephemeral key and the nonce; both are drawn
    /// fresh per call (`CryptoRng` because message confidentiality
    /// depends on them).
    ///
    /// Errors: [`IdentError::PayloadTooLarge`] (plaintext over the
    /// 65535-byte encoding limit),
    /// [`IdentError::InvalidPublicKey`] (a recipient key that does
    /// not contribute to the DH), plus the signing errors of the
    /// sender's identity.
    pub fn seal<R: RngCore + CryptoRng + ?Sized>(
        sender: &Identity,
        recipient: &PublicIdentity,
        msg_id: &[u8; MSG_ID_LEN],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Self, IdentError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(IdentError::PayloadTooLarge);
        }
        let recipient_node_id = compute_node_id(recipient.signing_pk(), recipient.agreement_pk());

        // The signature binds the plaintext to this exact recipient,
        // so a forwarded ciphertext cannot be re-presented as a
        // message to someone else. `signed` is a plaintext copy, so
        // it wipes on every path, including early returns.
        let mut signed = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
        signed.extend_from_slice(plaintext);
        signed.extend_from_slice(recipient_node_id.as_bytes());
        let msg_sig = sender.sign(DOMAIN_MSG, &signed)?;

        let mut inner = Vec::with_capacity(SENDER_IDENTITY_LEN + MSG_SIG_LEN + plaintext.len());
        inner.extend_from_slice(sender.public().signing_pk());
        inner.extend_from_slice(sender.public().agreement_pk());
        inner.extend_from_slice(sender.public().agreement_binding().as_bytes());
        inner.extend_from_slice(msg_sig.as_bytes());
        inner.extend_from_slice(plaintext);

        // One ephemeral key per message; `diffie_hellman` consumes it.
        let eph = EphemeralSecret::random_from_rng(&mut *rng);
        let eph_pk = AgreementPublicKey::from(&eph).to_bytes();
        let shared = eph.diffie_hellman(&AgreementPublicKey::from(*recipient.agreement_pk()));
        if !shared.was_contributory() {
            // A low-order recipient key would pin the shared secret to
            // the identity point, which every observer also computes.
            return Err(IdentError::InvalidPublicKey);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let aad = associated_data(sender.suite(), msg_id, &recipient_node_id);
        let cipher = cipher_from(hkdf_expand(shared.as_bytes(), INFO_SEAL));
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &inner,
                    aad: &aad,
                },
            )
            // Bounds above keep the plaintext and AAD far under the
            // AEAD length limits, so length is the only failure cause.
            .map_err(|_| IdentError::PayloadTooLarge)?;
        inner.zeroize();

        Ok(Self {
            suite: sender.suite(),
            eph_pk,
            nonce,
            ciphertext,
        })
    }

    /// Open the seal as `recipient` under the same `msg_id` it was
    /// sealed with, returning the plaintext and the authenticated
    /// sender.
    ///
    /// A wrong recipient, a wrong `msg_id` or any tampered field fails
    /// the AEAD check: [`IdentError::OpenFailed`]. A well-authenticated
    /// payload that does not parse is [`IdentError::MalformedSealed`];
    /// an embedded identity whose binding or signature fails carries
    /// [`IdentError::InvalidPublicKey`] / [`IdentError::InvalidSignature`].
    pub fn open(
        &self,
        recipient: &Identity,
        msg_id: &[u8; MSG_ID_LEN],
    ) -> Result<OpenedMessage, IdentError> {
        if self.ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(IdentError::MalformedSealed);
        }
        let node_id = recipient.node_id();
        let aad = associated_data(self.suite, msg_id, &node_id);

        let secret = StaticSecret::from(*recipient.secret().agreement_sk());
        let shared = secret.diffie_hellman(&AgreementPublicKey::from(self.eph_pk));
        if !shared.was_contributory() {
            return Err(IdentError::InvalidPublicKey);
        }
        let cipher = cipher_from(hkdf_expand(shared.as_bytes(), INFO_SEAL));

        let mut inner = cipher
            .decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| IdentError::OpenFailed)?;

        // The AEAD already authenticated `inner`; the length check
        // still guards against a malicious *sender* of short payloads.
        if inner.len() < SENDER_IDENTITY_LEN + MSG_SIG_LEN {
            inner.zeroize();
            return Err(IdentError::MalformedSealed);
        }
        let mut signing_pk = [0u8; 32];
        signing_pk.copy_from_slice(&inner[..32]);
        let mut agreement_pk = [0u8; 32];
        agreement_pk.copy_from_slice(&inner[32..64]);
        let mut binding = [0u8; 64];
        binding.copy_from_slice(&inner[64..128]);
        let mut msg_sig = [0u8; MSG_SIG_LEN];
        msg_sig.copy_from_slice(&inner[128..192]);
        let plaintext = inner.split_off(SENDER_IDENTITY_LEN + MSG_SIG_LEN);

        let sender = PublicIdentity::new(signing_pk, agreement_pk, Signature::from_bytes(binding));
        sender.verify_binding()?;
        let mut signed = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
        signed.extend_from_slice(&plaintext);
        signed.extend_from_slice(node_id.as_bytes());
        sender.verify(DOMAIN_MSG, &signed, &Signature::from_bytes(msg_sig))?;

        Ok(OpenedMessage { plaintext, sender })
    }

    /// The canonical wire encoding:
    /// `suite(1) ‖ eph_pk(32) ‖ nonce(24) ‖ ciphertext_len(2) ‖
    /// ciphertext`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.push(self.suite.byte());
        out.extend_from_slice(&self.eph_pk);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode the wire encoding. Every field is bounds-checked before
    /// it is read: a truncated or trailing input is
    /// [`IdentError::MalformedSealed`], an unknown suite byte is
    /// [`IdentError::UnknownSuite`]. Opening decides validity, never
    /// this function.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < HEADER_LEN {
            return Err(IdentError::MalformedSealed);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let mut eph_pk = [0u8; 32];
        eph_pk.copy_from_slice(&bytes[1..33]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[33..33 + NONCE_LEN]);
        let mut length = [0u8; 2];
        length.copy_from_slice(&bytes[33 + NONCE_LEN..HEADER_LEN]);
        let ciphertext_len = usize::from(u16::from_be_bytes(length));
        if ciphertext_len < MIN_CIPHERTEXT_LEN || bytes.len() != HEADER_LEN + ciphertext_len {
            return Err(IdentError::MalformedSealed);
        }
        Ok(Self {
            suite,
            eph_pk,
            nonce,
            ciphertext: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// The suite this message was sealed under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The sender's ephemeral X25519 public key for this message.
    #[must_use]
    pub fn eph_pk(&self) -> &[u8; 32] {
        &self.eph_pk
    }

    /// The 24-byte AEAD nonce, fresh per message.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The AEAD ciphertext, including the trailing tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl OpenedMessage {
    /// The decrypted plaintext.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// The authenticated sender: binding and message signature both
    /// verified during [`SealedMessage::open`].
    #[must_use]
    pub fn sender(&self) -> &PublicIdentity {
        &self.sender
    }
}

/// The associated data: `suite ‖ msg_id ‖ recipient NodeId`, so a
/// ciphertext only opens in its own suite, for its own message ID, at
/// its own recipient.
fn associated_data(suite: SuiteId, msg_id: &[u8; MSG_ID_LEN], recipient: &NodeId) -> [u8; 33] {
    let mut ad = [0u8; 33];
    ad[0] = suite.byte();
    ad[1..1 + MSG_ID_LEN].copy_from_slice(msg_id);
    ad[1 + MSG_ID_LEN..].copy_from_slice(recipient.as_bytes());
    ad
}

/// Build the AEAD cipher from derived key bytes and wipe both copies
/// of the key we hold: the raw HKDF output and the `Key` array. The
/// cipher keeps its own state (the `zeroize` feature drops it).
fn cipher_from(mut raw: [u8; 32]) -> XChaCha20Poly1305 {
    let mut key = Key::from(raw);
    let cipher = XChaCha20Poly1305::new(&key);
    key.zeroize();
    raw.zeroize();
    cipher
}
