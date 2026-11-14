//! Multi-recipient sealed messages (IDN-10).
//!
//! One random content key encrypts the payload once; the key is
//! wrapped separately for each recipient through an ephemeral
//! Diffie-Hellman, so up to [`MAX_RECIPIENTS`] offline recipients
//! open the same ciphertext with nothing but their secret identity.
//!
//! Canonical wire layout (hand-rolled, versioned by the suite byte):
//!
//! ```text
//! suite(1) | msg_id(16) | nonce(24) | wraps_len(1)
//!         | wraps(RECIPIENT_WRAP_LEN x n) | ciphertext_len(2) | ciphertext
//! ```
//!
//! **Growth:** every recipient adds exactly [`RECIPIENT_WRAP_LEN`]
//! (112) bytes - `key_id(8) | eph_pk(32) | nonce(24) | wrapped
//! key(48)` - and nothing else; ciphertext length depends only on
//! the plaintext. A test asserts the figure.
//!
//! **Sender authentication** matches IDN-09: the sender identity and
//! a signature over `plaintext | msg_id` live *inside* the content
//! ciphertext, so every recipient verifies the same statement. The
//! signature deliberately does not cover the wrap list: a relay that
//! corrupts one wrap denies service to that one recipient only,
//! while signing the list would let a single dropped wrap break the
//! message for everyone. A relay cannot forge wraps at all - that
//! needs the content key, which only the recipient-side DH
//! produces.
//!
//! Recipients are addressed by a short `key_id` (the first 8 bytes
//! of their agreement key). The opener tries every wrap whose
//! `key_id` matches its own, so a prefix collision costs one extra
//! attempt, never a misparse.
//!
//! **No forward secrecy** against recipient key compromise - same
//! honest limitation as IDN-09; prekeys (IDN-15) are the fix.

use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as AgreementPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::Identity;
use crate::identity::{compute_node_id, hkdf_expand};
use crate::seal::{
    DOMAIN_MSG, MAX_PLAINTEXT_LEN, MIN_CIPHERTEXT_LEN, MSG_ID_LEN, MSG_SIG_LEN, NONCE_LEN,
    OpenedMessage, SENDER_IDENTITY_LEN, cipher_from,
};
use crate::types::{IdentError, NodeId, PublicIdentity, Signature, SuiteId};

/// HKDF info: content key per recipient (ADR-0001 registry).
const INFO_WRAP: &str = "aoheyra/idn/v1/wrap";

/// Maximum recipients in one seal: the backlog's "about 8" - a
/// conversation-sized set, and a bound on hostile expansion.
pub const MAX_RECIPIENTS: usize = 8;

/// Bytes one recipient adds to the encoding:
/// `key_id(8) | eph_pk(32) | nonce(24) | wrapped key(32 + 16 tag)`.
pub const RECIPIENT_WRAP_LEN: usize = 8 + 32 + NONCE_LEN + 32 + 16;

/// `suite(1) | msg_id(16) | nonce(24) | wraps_len(1)` - everything
/// before the wrap list.
const PREFIX_LEN: usize = 1 + MSG_ID_LEN + NONCE_LEN + 1;

/// `ciphertext_len(2)` after the wrap list.
const TRAILER_LEN: usize = 2;

/// A message sealed to several recipients: one content ciphertext,
/// one wrap per recipient.
///
/// `Debug` prints field lengths, never ciphertext or wrap contents.
#[derive(Clone, PartialEq, Eq)]
pub struct MultiSealedMessage {
    suite: SuiteId,
    msg_id: [u8; MSG_ID_LEN],
    nonce: [u8; NONCE_LEN],
    /// Concatenated `RECIPIENT_WRAP_LEN`-byte wraps.
    wraps: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl core::fmt::Debug for MultiSealedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultiSealedMessage")
            .field("suite", &self.suite)
            .field("msg_id", &self.msg_id)
            .field("nonce", &self.nonce)
            .field("wraps_len", &self.wraps.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl MultiSealedMessage {
    /// Seal `plaintext` to every identity in `recipients`.
    ///
    /// `rng` supplies the content key, the content nonce and each
    /// recipient's ephemeral material (`CryptoRng`: all of it is
    /// message-confidential).
    ///
    /// Errors: [`IdentError::NoRecipients`],
    /// [`IdentError::TooManyRecipients`] beyond [`MAX_RECIPIENTS`],
    /// [`IdentError::DuplicateRecipient`] (same identity twice),
    /// [`IdentError::PayloadTooLarge`] (plaintext over the
    /// 65535-byte ciphertext field),
    /// [`IdentError::InvalidPublicKey`] (a recipient key that does
    /// not contribute to the DH), plus the sender's signing errors.
    pub fn seal<R: RngCore + CryptoRng + ?Sized>(
        sender: &Identity,
        recipients: &[&PublicIdentity],
        msg_id: &[u8; MSG_ID_LEN],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Self, IdentError> {
        if recipients.is_empty() {
            return Err(IdentError::NoRecipients);
        }
        if recipients.len() > MAX_RECIPIENTS {
            return Err(IdentError::TooManyRecipients);
        }
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(IdentError::PayloadTooLarge);
        }

        // Duplicate detection before any crypto: one identity twice
        // would otherwise produce two wraps for the same key.
        let mut seen: Vec<NodeId> = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let node_id = compute_node_id(recipient.signing_pk(), recipient.agreement_pk());
            if seen.contains(&node_id) {
                return Err(IdentError::DuplicateRecipient(node_id));
            }
            seen.push(node_id);
        }

        let suite = sender.suite();

        // Same sender statement as IDN-09, but binding the message
        // id instead of one recipient: every recipient must be able
        // to verify it with only public data.
        let mut signed = Zeroizing::new(Vec::with_capacity(plaintext.len() + MSG_ID_LEN));
        signed.extend_from_slice(plaintext);
        signed.extend_from_slice(msg_id);
        let msg_sig = sender.sign(DOMAIN_MSG, &signed)?;

        let mut inner = Zeroizing::new(Vec::with_capacity(
            SENDER_IDENTITY_LEN + MSG_SIG_LEN + plaintext.len(),
        ));
        inner.extend_from_slice(sender.public().signing_pk());
        inner.extend_from_slice(sender.public().agreement_pk());
        inner.extend_from_slice(sender.public().agreement_binding().as_bytes());
        inner.extend_from_slice(msg_sig.as_bytes());
        inner.extend_from_slice(plaintext);

        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *key);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        // One wrap per recipient, built before the content so the
        // content encryption can consume and wipe the key last.
        let mut wraps = Vec::with_capacity(RECIPIENT_WRAP_LEN * recipients.len());
        for recipient in recipients {
            let mut key_id = [0u8; 8];
            key_id.copy_from_slice(&recipient.agreement_pk()[..8]);

            let eph = EphemeralSecret::random_from_rng(&mut *rng);
            let eph_pk = AgreementPublicKey::from(&eph).to_bytes();
            let shared = eph.diffie_hellman(&AgreementPublicKey::from(*recipient.agreement_pk()));
            if !shared.was_contributory() {
                // Low-order recipient key: refuse rather than hand
                // out a wrap everyone can derive the key for.
                return Err(IdentError::InvalidPublicKey);
            }
            let wrap_key = hkdf_expand(shared.as_bytes(), INFO_WRAP.as_bytes());
            let mut wrap_nonce = [0u8; NONCE_LEN];
            rng.fill_bytes(&mut wrap_nonce);

            let aad = wrap_associated_data(suite, msg_id, &key_id);
            // 32-byte key, fixed AAD: the only AEAD failure mode is
            // length, which the constants make impossible.
            let wrapped = cipher_from(wrap_key)
                .encrypt(
                    &XNonce::from(wrap_nonce),
                    Payload {
                        msg: &key[..],
                        aad: &aad,
                    },
                )
                .map_err(|_| IdentError::PayloadTooLarge)?;
            debug_assert_eq!(wrapped.len(), 48, "32-byte key plus tag");

            wraps.extend_from_slice(&key_id);
            wraps.extend_from_slice(&eph_pk);
            wraps.extend_from_slice(&wrap_nonce);
            wraps.extend_from_slice(&wrapped);
        }

        let aad = content_associated_data(suite, msg_id);
        let cipher = cipher_from(*key);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &inner[..],
                    aad: &aad,
                },
            )
            // Plaintext and AAD are far under the AEAD limits above,
            // so length is the only possible cause.
            .map_err(|_| IdentError::PayloadTooLarge)?;

        Ok(Self {
            suite,
            msg_id: *msg_id,
            nonce,
            wraps,
            ciphertext,
        })
    }

    /// Open the seal as `recipient`, returning the plaintext and the
    /// authenticated sender.
    ///
    /// The opener first finds every wrap addressed to its own
    /// `key_id` and derives the content key from the first one that
    /// unwraps; a missing or corrupted wrap is
    /// [`IdentError::OpenFailed`]. Content and signature checks are
    /// the same as [`crate::SealedMessage::open`]:
    /// [`IdentError::OpenFailed`] for tampering,
    /// [`IdentError::MalformedSealed`] for an in-authenticated but
    /// malformed payload, [`IdentError::InvalidPublicKey`] /
    /// [`IdentError::InvalidSignature`] for a bad embedded sender.
    pub fn open(&self, recipient: &Identity) -> Result<OpenedMessage, IdentError> {
        if self.ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(IdentError::MalformedSealed);
        }

        let agreement_pk = recipient.public().agreement_pk();
        let mut my_key_id = [0u8; 8];
        my_key_id.copy_from_slice(&agreement_pk[..8]);

        let secret = StaticSecret::from(*recipient.secret().agreement_sk());
        let mut content_key: Option<[u8; 32]> = None;
        for wrap in self.wraps.chunks_exact(RECIPIENT_WRAP_LEN) {
            if wrap[..8] != my_key_id {
                continue;
            }
            let mut eph_pk = [0u8; 32];
            eph_pk.copy_from_slice(&wrap[8..40]);
            let mut wrap_nonce = [0u8; NONCE_LEN];
            wrap_nonce.copy_from_slice(&wrap[40..40 + NONCE_LEN]);
            let wrapped = &wrap[40 + NONCE_LEN..RECIPIENT_WRAP_LEN];

            let shared = secret.diffie_hellman(&AgreementPublicKey::from(eph_pk));
            if !shared.was_contributory() {
                // A hostile sender's low-order ephemeral in this
                // slot: try the next matching wrap, never derive a
                // key everyone shares.
                continue;
            }
            let wrap_key = hkdf_expand(shared.as_bytes(), INFO_WRAP.as_bytes());
            let aad = wrap_associated_data(self.suite, &self.msg_id, &my_key_id);
            if let Ok(unwrapped) = cipher_from(wrap_key).decrypt(
                &XNonce::from(wrap_nonce),
                Payload {
                    msg: wrapped,
                    aad: &aad,
                },
            ) {
                if unwrapped.len() == 32 {
                    let mut derived = [0u8; 32];
                    derived.copy_from_slice(&unwrapped);
                    content_key = Some(derived);
                    break;
                }
            }
        }
        let content_key = content_key.ok_or(IdentError::OpenFailed)?;

        let aad = content_associated_data(self.suite, &self.msg_id);
        let mut inner = cipher_from(content_key)
            .decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| IdentError::OpenFailed)?;

        // The AEAD authenticated `inner`; the length check still
        // guards against a malicious *sender* of short payloads.
        if inner.len() < SENDER_IDENTITY_LEN + MSG_SIG_LEN {
            return Err(IdentError::MalformedSealed);
        }
        let mut signing_pk = [0u8; 32];
        signing_pk.copy_from_slice(&inner[..32]);
        let mut agreement_pk = [0u8; 32];
        agreement_pk.copy_from_slice(&inner[32..64]);
        let mut binding = [0u8; 64];
        binding.copy_from_slice(&inner[64..128]);
        let mut msg_sig = [0u8; MSG_SIG_LEN];
        msg_sig.copy_from_slice(&inner[128..128 + MSG_SIG_LEN]);
        let plaintext = inner.split_off(SENDER_IDENTITY_LEN + MSG_SIG_LEN);

        let sender = PublicIdentity::new(signing_pk, agreement_pk, Signature::from_bytes(binding));
        sender.verify_binding()?;
        let mut signed = Zeroizing::new(Vec::with_capacity(plaintext.len() + MSG_ID_LEN));
        signed.extend_from_slice(&plaintext);
        signed.extend_from_slice(&self.msg_id);
        sender.verify(DOMAIN_MSG, &signed, &Signature::from_bytes(msg_sig))?;

        Ok(OpenedMessage::new(plaintext, sender))
    }

    /// The canonical wire encoding (see the module docs for the
    /// layout).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(PREFIX_LEN + self.wraps.len() + TRAILER_LEN + self.ciphertext.len());
        out.push(self.suite.byte());
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.nonce);
        out.push((self.wraps.len() / RECIPIENT_WRAP_LEN) as u8);
        out.extend_from_slice(&self.wraps);
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode the wire encoding. Every field is bounds-checked
    /// before it is read: a truncated or trailing input is
    /// [`IdentError::MalformedSealed`], an unknown suite is
    /// [`IdentError::UnknownSuite`], zero wraps is
    /// [`IdentError::NoRecipients`] and more than
    /// [`MAX_RECIPIENTS`] is [`IdentError::TooManyRecipients`].
    /// Opening decides validity, never this function.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < PREFIX_LEN {
            return Err(IdentError::MalformedSealed);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let mut msg_id = [0u8; MSG_ID_LEN];
        msg_id.copy_from_slice(&bytes[1..1 + MSG_ID_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + MSG_ID_LEN..PREFIX_LEN - 1]);
        let wraps_len = usize::from(bytes[PREFIX_LEN - 1]);
        if wraps_len == 0 {
            return Err(IdentError::NoRecipients);
        }
        if wraps_len > MAX_RECIPIENTS {
            return Err(IdentError::TooManyRecipients);
        }
        let wraps_end = PREFIX_LEN + wraps_len * RECIPIENT_WRAP_LEN;
        // wraps_end >= PREFIX_LEN + RECIPIENT_WRAP_LEN, so the two
        // bytes of ciphertext length are in range only if the total
        // is large enough.
        if bytes.len() < wraps_end + TRAILER_LEN {
            return Err(IdentError::MalformedSealed);
        }
        let mut length = [0u8; 2];
        length.copy_from_slice(&bytes[wraps_end..wraps_end + TRAILER_LEN]);
        let ciphertext_len = usize::from(u16::from_be_bytes(length));
        if ciphertext_len < MIN_CIPHERTEXT_LEN
            || bytes.len() != wraps_end + TRAILER_LEN + ciphertext_len
        {
            return Err(IdentError::MalformedSealed);
        }
        Ok(Self {
            suite,
            msg_id,
            nonce,
            wraps: bytes[PREFIX_LEN..wraps_end].to_vec(),
            ciphertext: bytes[wraps_end + TRAILER_LEN..].to_vec(),
        })
    }

    /// The suite this message was sealed under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The message id bound into both associated data and the sender
    /// signature; carried on the wire so recipients need no side
    /// channel for it.
    #[must_use]
    pub fn msg_id(&self) -> &[u8; MSG_ID_LEN] {
        &self.msg_id
    }

    /// The 24-byte content AEAD nonce, fresh per message.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The raw wrap list: [`MAX_RECIPIENTS`] x [`RECIPIENT_WRAP_LEN`]
    /// bytes.
    #[must_use]
    pub fn wraps(&self) -> &[u8] {
        &self.wraps
    }

    /// The content AEAD ciphertext, including the trailing tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Content associated data: `suite | msg_id`, so a ciphertext only
/// opens in its own suite for its own message id.
fn content_associated_data(suite: SuiteId, msg_id: &[u8; MSG_ID_LEN]) -> [u8; 1 + MSG_ID_LEN] {
    let mut ad = [0u8; 1 + MSG_ID_LEN];
    ad[0] = suite.byte();
    ad[1..].copy_from_slice(msg_id);
    ad
}

/// Wrap associated data: `suite | msg_id | key_id`, so a wrap only
/// unwraps in its own slot of its own message.
fn wrap_associated_data(suite: SuiteId, msg_id: &[u8; MSG_ID_LEN], key_id: &[u8; 8]) -> [u8; 25] {
    let mut ad = [0u8; 25];
    ad[0] = suite.byte();
    ad[1..1 + MSG_ID_LEN].copy_from_slice(msg_id);
    ad[1 + MSG_ID_LEN..].copy_from_slice(key_id);
    ad
}
