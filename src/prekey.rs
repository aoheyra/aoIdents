//! Signed prekey bundles and X3DH-style initial agreement (IDN-15).
//!
//! A recipient publishes a [`PrekeyBundle`] - its identity keys, a
//! signed prekey and a handful of one-time prekeys, all signed by the
//! identity key - through announcements, then goes offline. A sender
//! seals a message to the bundle with [`PrekeySealedMessage::seal`]:
//! one X3DH agreement over four Diffie-Hellman shares, so only the
//! holder of the bundle's *prekey secrets* can open it.
//!
//! **Why the prekeys are independent random keys, never derived from
//! the identity seed:** the session key needs all four shares, and
//! three of them need prekey secrets that live outside the long-term
//! key. Once the recipient has opened a message and deleted the
//! prekeys it used, even a full compromise of the long-term key
//! cannot rebuild the session key - the done-when of IDN-15, shown by
//! a test.
//!
//! One-time prekeys are deleted by [`PrekeySealedMessage::open`]
//! itself, on success only: a message that fails to open cannot burn
//! a slot, and a caller cannot forget to delete.
//!
//! ```text
//! bundle:    suite(1) | signing_pk(32) | agreement_pk(32)
//!            | signed_prekey_pk(32) | one_time_count(1)
//!            | one_time_pks(32 x n) | signature(64)
//!
//! sealed:    suite(1) | sender_agreement_pk(32) | eph_pk(32)
//!            | one_time_index(1) | nonce(24) | ciphertext_len(2)
//!            | ciphertext
//! ```
//!
//! The bundle signature covers everything before it under the
//! ADR-0001 domain `aoheyra/idn/v1/prekey-bundle`. Inside the
//! ciphertext lives the sender's signing key, its agreement binding
//! and a signature over `payload || eph_pk` under
//! `aoheyra/idn/v1/msg`, so the sender is authenticated the same way
//! IDN-09 authenticates it, and the binding ties the sender's
//! agreement key (the one the header's DH used) to that signing key.

use core::fmt;

use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as AgreementPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::Identity;
use crate::identity::compute_node_id;
use crate::seal::{DOMAIN_MSG, NONCE_LEN, OpenedMessage, cipher_from};
use crate::sign::verify_signing_pk;
use crate::types::{IdentError, NodeId, PublicIdentity, Signature, SuiteId};

/// Signature domain for prekey bundles (ADR-0001 registry).
const DOMAIN_BUNDLE: &str = "aoheyra/idn/v1/prekey-bundle";

/// HKDF info for the X3DH session key (ADR-0001 registry).
const INFO_PREKEY: &str = "aoheyra/idn/v1/prekey";

/// Bytes per public or secret key.
const KEY_LEN: usize = 32;

/// Ed25519 signature bytes.
const SIG_LEN: usize = 64;

/// AEAD tag bytes.
const TAG_LEN: usize = 16;

/// Bundle bytes before the one-time prekey list:
/// suite(1) + signing_pk(32) + agreement_pk(32) + signed prekey(32)
/// + count(1).
const BUNDLE_PREFIX_LEN: usize = 1 + 3 * KEY_LEN + 1;

/// What the ciphertext must at least carry: the sender's signing key,
/// agreement binding and message signature, plus the tag.
const INNER_LEN: usize = KEY_LEN + 2 * SIG_LEN;
const MIN_CIPHERTEXT_LEN: usize = INNER_LEN + TAG_LEN;

/// Largest payload: the encoding's two-byte length covers the
/// ciphertext, which covers the inner framing plus the plaintext.
const MAX_PLAINTEXT_LEN: usize = u16::MAX as usize - MIN_CIPHERTEXT_LEN;

/// Sealed-message header length: suite(1) + sender agreement key(32)
/// + ephemeral key(32) + one-time index(1) + nonce(24) + length(2).
const MSG_HEADER_LEN: usize = 1 + 2 * KEY_LEN + 1 + NONCE_LEN + 2;

/// Upper bound on a bundle's one-time prekeys: enough for a day of
/// offline messages at mesh rates, small enough that a hostile count
/// byte can never drive an allocation (checked before any).
pub const MAX_ONE_TIME_PREKEYS: usize = 16;

/// The public prekey bundle a recipient publishes so offline senders
/// can run X3DH against it (IDN-15).
///
/// The bundle is signed by the recipient's identity key; [`Self::verify`]
/// checks that signature before any key in it is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyBundle {
    suite: SuiteId,
    signing_pk: [u8; KEY_LEN],
    agreement_pk: [u8; KEY_LEN],
    signed_prekey_pk: [u8; KEY_LEN],
    one_time_pks: Vec<[u8; KEY_LEN]>,
    signature: Signature,
}

/// The recipient-side secrets of a [`PrekeyBundle`] (IDN-15).
///
/// These are drawn independently from the injected RNG, never derived
/// from the identity seed - that separation is what makes a message
/// survive a long-term key compromise once the prekeys are deleted.
/// Slots become `None` when consumed; the key bytes are zeroized on
/// deletion and on drop.
pub struct PrekeySecrets {
    signed_prekey_sk: Option<Zeroizing<[u8; KEY_LEN]>>,
    one_time_sks: Vec<Option<Zeroizing<[u8; KEY_LEN]>>>,
}

/// A message sealed to a prekey bundle under X3DH (IDN-15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeySealedMessage {
    suite: SuiteId,
    sender_agreement_pk: [u8; KEY_LEN],
    eph_pk: [u8; KEY_LEN],
    one_time_index: u8,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl fmt::Debug for PrekeySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redacted: the slots hold secret keys, so only
        // how many are still present is printed.
        let present = self.one_time_sks.iter().filter(|s| s.is_some()).count();
        f.debug_struct("PrekeySecrets")
            .field("signed_prekey_present", &self.signed_prekey_sk.is_some())
            .field(
                "one_time_present",
                &format_args!("{present}/{}", self.one_time_sks.len()),
            )
            .finish_non_exhaustive()
    }
}

impl PrekeyBundle {
    /// Generate a fresh bundle for `identity` with `one_time_count`
    /// one-time prekeys, plus the secrets that open messages sealed
    /// to it.
    ///
    /// Every prekey is an independent random key from `rng` (a
    /// `CryptoRng`, because a guessable prekey gives away the
    /// session); the bundle is signed by the identity key.
    ///
    /// # Errors
    ///
    /// [`IdentError::InvalidPrekeyCount`] for a count outside
    /// `1..=`[`MAX_ONE_TIME_PREKEYS`]; a signing failure otherwise.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(
        identity: &Identity,
        one_time_count: u8,
        rng: &mut R,
    ) -> Result<(Self, PrekeySecrets), IdentError> {
        let count = usize::from(one_time_count);
        if count == 0 || count > MAX_ONE_TIME_PREKEYS {
            return Err(IdentError::InvalidPrekeyCount);
        }

        let public = identity.public();
        let signed_prekey_sk = draw_key(rng);
        let signed_prekey_pk = public_key_of(&signed_prekey_sk);
        let mut one_time_sks = Vec::with_capacity(count);
        let mut one_time_pks = Vec::with_capacity(count);
        for _ in 0..count {
            let sk = draw_key(rng);
            one_time_pks.push(public_key_of(&sk));
            one_time_sks.push(Some(sk));
        }

        let mut body = Vec::with_capacity(BUNDLE_PREFIX_LEN + count * KEY_LEN);
        body.push(identity.suite().byte());
        body.extend_from_slice(public.signing_pk());
        body.extend_from_slice(public.agreement_pk());
        body.extend_from_slice(&signed_prekey_pk);
        body.push(one_time_count);
        for pk in &one_time_pks {
            body.extend_from_slice(pk);
        }
        let signature = identity.sign(DOMAIN_BUNDLE, &body)?;

        Ok((
            Self {
                suite: identity.suite(),
                signing_pk: *public.signing_pk(),
                agreement_pk: *public.agreement_pk(),
                signed_prekey_pk,
                one_time_pks,
                signature,
            },
            PrekeySecrets {
                signed_prekey_sk: Some(signed_prekey_sk),
                one_time_sks,
            },
        ))
    }

    /// Verify the identity signature over the whole bundle.
    ///
    /// # Errors
    ///
    /// [`IdentError::InvalidPublicKey`] for a key the signature cannot
    /// be checked against, [`IdentError::InvalidSignature`] for a
    /// forged or tampered bundle.
    pub fn verify(&self) -> Result<(), IdentError> {
        verify_signing_pk(
            &self.signing_pk,
            DOMAIN_BUNDLE,
            &self.bundle_body(),
            &self.signature,
        )
    }

    /// The recipient's [`NodeId`], derived from the bundle's keys.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        compute_node_id(&self.signing_pk, &self.agreement_pk)
    }

    /// The suite this bundle was generated under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The recipient's Ed25519 signing key.
    #[must_use]
    pub fn signing_pk(&self) -> &[u8; KEY_LEN] {
        &self.signing_pk
    }

    /// The recipient's long-term X25519 agreement key.
    #[must_use]
    pub fn agreement_pk(&self) -> &[u8; KEY_LEN] {
        &self.agreement_pk
    }

    /// How many one-time prekeys the bundle carries.
    #[must_use]
    pub fn one_time_count(&self) -> usize {
        self.one_time_pks.len()
    }

    /// The canonical encoding (see the module docs for the layout).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.bundle_body();
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Decode a bundle. Every field is bounds-checked before it is
    /// read: a truncated or trailing input is
    /// [`IdentError::MalformedPrekeyBundle`], a count outside
    /// `1..=`[`MAX_ONE_TIME_PREKEYS`] is [`IdentError::InvalidPrekeyCount`]
    /// (refused before the key list is allocated), an unknown suite
    /// byte is [`IdentError::UnknownSuite`]. Signature validity is
    /// decided by [`Self::verify`], never here.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < BUNDLE_PREFIX_LEN + SIG_LEN {
            return Err(IdentError::MalformedPrekeyBundle);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let signing_pk = copy_key(&bytes[1..1 + KEY_LEN], IdentError::MalformedPrekeyBundle)?;
        let agreement_pk = copy_key(
            &bytes[1 + KEY_LEN..1 + 2 * KEY_LEN],
            IdentError::MalformedPrekeyBundle,
        )?;
        let signed_prekey_pk = copy_key(
            &bytes[1 + 2 * KEY_LEN..1 + 3 * KEY_LEN],
            IdentError::MalformedPrekeyBundle,
        )?;
        let count = usize::from(bytes[1 + 3 * KEY_LEN]);
        if count == 0 || count > MAX_ONE_TIME_PREKEYS {
            return Err(IdentError::InvalidPrekeyCount);
        }
        let expected = BUNDLE_PREFIX_LEN + count * KEY_LEN + SIG_LEN;
        if bytes.len() != expected {
            return Err(IdentError::MalformedPrekeyBundle);
        }
        let mut one_time_pks = Vec::with_capacity(count);
        for i in 0..count {
            let start = BUNDLE_PREFIX_LEN + i * KEY_LEN;
            one_time_pks.push(copy_key(
                &bytes[start..start + KEY_LEN],
                IdentError::MalformedPrekeyBundle,
            )?);
        }
        let signature = copy_signature(
            &bytes[expected - SIG_LEN..],
            IdentError::MalformedPrekeyBundle,
        )?;
        Ok(Self {
            suite,
            signing_pk,
            agreement_pk,
            signed_prekey_pk,
            one_time_pks,
            signature,
        })
    }

    /// Everything the bundle signature covers: the encoding without
    /// the trailing signature.
    fn bundle_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(BUNDLE_PREFIX_LEN + self.one_time_pks.len() * KEY_LEN);
        body.push(self.suite.byte());
        body.extend_from_slice(&self.signing_pk);
        body.extend_from_slice(&self.agreement_pk);
        body.extend_from_slice(&self.signed_prekey_pk);
        body.push(self.one_time_pks.len() as u8);
        for pk in &self.one_time_pks {
            body.extend_from_slice(pk);
        }
        body
    }
}

impl PrekeySecrets {
    /// Drop the signed prekey - what rotation does once the
    /// successor's bundle is published. Messages still sealed to it
    /// stop opening; the deletion is idempotent.
    pub fn delete_signed_prekey(&mut self) {
        // The Zeroizing slot zeroes its bytes as it drops.
        self.signed_prekey_sk = None;
    }

    /// Take the one-time prekey at `index` for this open, returning
    /// `None` when it is out of range or already consumed.
    fn one_time_at(&self, index: usize) -> Option<&Zeroizing<[u8; KEY_LEN]>> {
        self.one_time_sks.get(index).and_then(Option::as_ref)
    }

    /// Burn the one-time prekey at `index` after a successful open;
    /// out-of-range indexes are ignored (the open already failed).
    fn burn_one_time(&mut self, index: usize) {
        if let Some(slot) = self.one_time_sks.get_mut(index) {
            *slot = None;
        }
    }
}

impl PrekeySealedMessage {
    /// Seal `payload` to `bundle`, consuming one of its one-time
    /// prekey slots (picked at random so concurrent senders sharing
    /// one published bundle spread across the slots).
    ///
    /// `rng` supplies the ephemeral key and the nonce; both are drawn
    /// fresh per call (`CryptoRng` because confidentiality depends on
    /// them). The ephemeral is held as a `StaticSecret` because X3DH
    /// runs three DHs over the same ephemeral key and the
    /// single-use `EphemeralSecret` is consumed by the first.
    ///
    /// # Errors
    ///
    /// [`IdentError::PayloadTooLarge`] (payload over the encoding
    /// limit, refused before allocation), [`IdentError::InvalidSignature`]
    /// (a forged bundle), [`IdentError::InvalidPublicKey`] (a bundle
    /// key that does not contribute to a DH), plus the signing errors
    /// of the sender's identity.
    pub fn seal<R: RngCore + CryptoRng + ?Sized>(
        sender: &Identity,
        bundle: &PrekeyBundle,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Self, IdentError> {
        if payload.len() > MAX_PLAINTEXT_LEN {
            return Err(IdentError::PayloadTooLarge);
        }
        bundle.verify()?;

        let mut eph_raw = Zeroizing::new([0_u8; KEY_LEN]);
        rng.fill_bytes(&mut *eph_raw);
        let eph = StaticSecret::from(*eph_raw);
        let eph_pk = AgreementPublicKey::from(&eph).to_bytes();

        let mut pick = [0_u8; 1];
        rng.fill_bytes(&mut pick);
        let index = usize::from(pick[0]) % bundle.one_time_pks.len();

        // The sender authenticates itself inside the ciphertext, the
        // same way IDN-09 does; `signed` is a plaintext copy so it
        // wipes on every path, including early returns.
        let mut signed = Zeroizing::new(Vec::with_capacity(payload.len() + KEY_LEN));
        signed.extend_from_slice(payload);
        signed.extend_from_slice(&eph_pk);
        let msg_sig = sender.sign(DOMAIN_MSG, &signed)?;

        let mut inner = Vec::with_capacity(INNER_LEN + payload.len());
        inner.extend_from_slice(sender.public().signing_pk());
        inner.extend_from_slice(sender.public().agreement_binding().as_bytes());
        inner.extend_from_slice(msg_sig.as_bytes());
        inner.extend_from_slice(payload);

        let sender_sk = StaticSecret::from(*sender.secret().agreement_sk());
        let shared1 = sender_sk.diffie_hellman(&AgreementPublicKey::from(bundle.signed_prekey_pk));
        let shared2 = eph.diffie_hellman(&AgreementPublicKey::from(bundle.agreement_pk));
        let shared3 = eph.diffie_hellman(&AgreementPublicKey::from(bundle.signed_prekey_pk));
        let shared4 = eph.diffie_hellman(&AgreementPublicKey::from(bundle.one_time_pks[index]));
        for shared in [&shared1, &shared2, &shared3, &shared4] {
            if !shared.was_contributory() {
                // A low-order key would pin the shared secret to the
                // identity point, which every observer also computes.
                inner.zeroize();
                return Err(IdentError::InvalidPublicKey);
            }
        }

        let mut ikm = Zeroizing::new(Vec::with_capacity(4 * KEY_LEN));
        for shared in [&shared1, &shared2, &shared3, &shared4] {
            ikm.extend_from_slice(shared.as_bytes());
        }

        let mut nonce = [0_u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let aad = associated_data(
            sender.suite(),
            sender.public().agreement_pk(),
            &eph_pk,
            index as u8,
        );
        let cipher = cipher_from(derive_sk(sender.suite(), &ikm));
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
            sender_agreement_pk: *sender.public().agreement_pk(),
            eph_pk,
            one_time_index: index as u8,
            nonce,
            ciphertext,
        })
    }

    /// Open the message as `recipient`, using the bundle secrets it
    /// was sealed to. On success the one-time prekey slot is consumed
    /// (a failed open never burns a slot).
    ///
    /// # Errors
    ///
    /// [`IdentError::PrekeyUnavailable`] when the slot was already
    /// consumed, the signed prekey was deleted, or the index is out
    /// of range; [`IdentError::OpenFailed`] when the AEAD check fails
    /// (wrong recipient, tampered field); [`IdentError::MalformedPrekeyMessage`]
    /// for a well-authenticated payload that does not parse; and the
    /// binding/signature errors of an embedded sender identity.
    pub fn open(
        &self,
        recipient: &Identity,
        secrets: &mut PrekeySecrets,
    ) -> Result<OpenedMessage, IdentError> {
        if self.ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(IdentError::MalformedPrekeyMessage);
        }
        let index = usize::from(self.one_time_index);
        let opk = secrets
            .one_time_at(index)
            .ok_or(IdentError::PrekeyUnavailable)?;
        let spk = secrets
            .signed_prekey_sk
            .as_ref()
            .ok_or(IdentError::PrekeyUnavailable)?;

        let recipient_sk = StaticSecret::from(*recipient.secret().agreement_sk());
        let spk_sk = StaticSecret::from(**spk);
        let opk_sk = StaticSecret::from(**opk);
        let shared1 = spk_sk.diffie_hellman(&AgreementPublicKey::from(self.sender_agreement_pk));
        let shared2 = recipient_sk.diffie_hellman(&AgreementPublicKey::from(self.eph_pk));
        let shared3 = spk_sk.diffie_hellman(&AgreementPublicKey::from(self.eph_pk));
        let shared4 = opk_sk.diffie_hellman(&AgreementPublicKey::from(self.eph_pk));
        for shared in [&shared1, &shared2, &shared3, &shared4] {
            if !shared.was_contributory() {
                return Err(IdentError::InvalidPublicKey);
            }
        }
        let mut ikm = Zeroizing::new(Vec::with_capacity(4 * KEY_LEN));
        for shared in [&shared1, &shared2, &shared3, &shared4] {
            ikm.extend_from_slice(shared.as_bytes());
        }

        let aad = associated_data(
            self.suite,
            &self.sender_agreement_pk,
            &self.eph_pk,
            self.one_time_index,
        );
        let cipher = cipher_from(derive_sk(self.suite, &ikm));
        let mut inner = cipher
            .decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| IdentError::OpenFailed)?;

        if inner.len() < INNER_LEN {
            inner.zeroize();
            return Err(IdentError::MalformedPrekeyMessage);
        }
        let mut signing_pk = [0_u8; KEY_LEN];
        signing_pk.copy_from_slice(&inner[..KEY_LEN]);
        let mut binding = [0_u8; SIG_LEN];
        binding.copy_from_slice(&inner[KEY_LEN..KEY_LEN + SIG_LEN]);
        let mut msg_sig = [0_u8; SIG_LEN];
        msg_sig.copy_from_slice(&inner[KEY_LEN + SIG_LEN..INNER_LEN]);
        let payload = inner.split_off(INNER_LEN);

        // The binding ties the header's agreement key - the one the
        // DH used - to the embedded signing key, so a mismatched pair
        // fails here.
        let sender = PublicIdentity::new(
            signing_pk,
            self.sender_agreement_pk,
            Signature::from_bytes(binding),
        );
        sender.verify_binding()?;
        let mut signed = Zeroizing::new(Vec::with_capacity(payload.len() + KEY_LEN));
        signed.extend_from_slice(&payload);
        signed.extend_from_slice(&self.eph_pk);
        sender.verify(DOMAIN_MSG, &signed, &Signature::from_bytes(msg_sig))?;

        // Everything authenticated: delete the one-time prekey now.
        secrets.burn_one_time(index);
        Ok(OpenedMessage::new(payload, sender))
    }

    /// The canonical wire encoding (see the module docs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MSG_HEADER_LEN + self.ciphertext.len());
        out.push(self.suite.byte());
        out.extend_from_slice(&self.sender_agreement_pk);
        out.extend_from_slice(&self.eph_pk);
        out.push(self.one_time_index);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode the wire encoding. Every field is bounds-checked before
    /// it is read: a truncated or trailing input is
    /// [`IdentError::MalformedPrekeyMessage`], an unknown suite byte
    /// is [`IdentError::UnknownSuite`]. Opening decides validity,
    /// never this function.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < MSG_HEADER_LEN {
            return Err(IdentError::MalformedPrekeyMessage);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let sender_agreement_pk =
            copy_key(&bytes[1..1 + KEY_LEN], IdentError::MalformedPrekeyMessage)?;
        let eph_pk = copy_key(
            &bytes[1 + KEY_LEN..1 + 2 * KEY_LEN],
            IdentError::MalformedPrekeyMessage,
        )?;
        let one_time_index = bytes[1 + 2 * KEY_LEN];
        let nonce_start = 1 + 2 * KEY_LEN + 1;
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[nonce_start..nonce_start + NONCE_LEN]);
        let len_start = nonce_start + NONCE_LEN;
        let mut length = [0_u8; 2];
        length.copy_from_slice(&bytes[len_start..MSG_HEADER_LEN]);
        let ciphertext_len = usize::from(u16::from_be_bytes(length));
        if ciphertext_len < MIN_CIPHERTEXT_LEN || bytes.len() != MSG_HEADER_LEN + ciphertext_len {
            return Err(IdentError::MalformedPrekeyMessage);
        }
        Ok(Self {
            suite,
            sender_agreement_pk,
            eph_pk,
            one_time_index,
            nonce,
            ciphertext: bytes[MSG_HEADER_LEN..].to_vec(),
        })
    }

    /// The suite this message was sealed under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The sender's long-term agreement key: the header half of the
    /// first DH share.
    #[must_use]
    pub fn sender_agreement_pk(&self) -> &[u8; KEY_LEN] {
        &self.sender_agreement_pk
    }

    /// The sender's ephemeral X25519 public key.
    #[must_use]
    pub fn eph_pk(&self) -> &[u8; KEY_LEN] {
        &self.eph_pk
    }

    /// Which one-time prekey slot this message was sealed to.
    #[must_use]
    pub fn one_time_index(&self) -> u8 {
        self.one_time_index
    }

    /// The 24-byte AEAD nonce, fresh per message.
    #[must_use]
    pub fn nonce(&self) -> [u8; NONCE_LEN] {
        self.nonce
    }

    /// The ciphertext, including the AEAD tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Draw an independent 32-byte prekey secret from the caller's RNG.
fn draw_key<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Zeroizing<[u8; KEY_LEN]> {
    let mut raw = Zeroizing::new([0_u8; KEY_LEN]);
    rng.fill_bytes(&mut *raw);
    raw
}

/// The X25519 public key for a drawn prekey secret. The clamping
/// happens inside the DH, so any 32 bytes are a valid secret here.
fn public_key_of(sk: &Zeroizing<[u8; KEY_LEN]>) -> [u8; KEY_LEN] {
    AgreementPublicKey::from(&StaticSecret::from(**sk)).to_bytes()
}

/// The AAD binds the envelope: suite, the sender agreement key the
/// first DH used, the ephemeral key and the prekey slot.
fn associated_data(
    suite: SuiteId,
    sender_agreement_pk: &[u8; KEY_LEN],
    eph_pk: &[u8; KEY_LEN],
    one_time_index: u8,
) -> [u8; 1 + 2 * KEY_LEN + 1] {
    let mut aad = [0_u8; 1 + 2 * KEY_LEN + 1];
    aad[0] = suite.byte();
    aad[1..1 + KEY_LEN].copy_from_slice(sender_agreement_pk);
    aad[1 + KEY_LEN..1 + 2 * KEY_LEN].copy_from_slice(eph_pk);
    aad[1 + 2 * KEY_LEN] = one_time_index;
    aad
}

/// HKDF-SHA-256 over the four X3DH shares, salted with the suite
/// byte and labelled `aoheyra/idn/v1/prekey` (ADR-0001). The output
/// length is the constant 32, so the expand step cannot fail for any
/// input - the same reasoning as `identity::hkdf_expand`.
fn derive_sk(suite: SuiteId, ikm: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(&[suite.byte()]), ikm);
    let mut okm = [0_u8; KEY_LEN];
    hk.expand(INFO_PREKEY.as_bytes(), &mut okm)
        .expect("32 bytes is always a valid HKDF-SHA-256 output length");
    okm
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
