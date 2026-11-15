//! Noise XX hop handshake (IDN-13).
//!
//! A three-message [Noise XX] exchange whose static keys are checked
//! against each neighbour's [`IdentityCard`], producing a
//! [`HopTransport`] for hop-level encryption (consumed by the mesh's
//! MSH-26 layer). Like the rest of this crate the handshake is sans-IO:
//! bytes leave through [`HopHandshake::write_message`] and arrive
//! through [`HopHandshake::read_message`]; there is no socket, no clock
//! and no hidden randomness - the ephemeral key is drawn from the
//! caller's RNG.
//!
//! With this suite (`Noise_XX_25519_ChaChaPoly_SHA256`) the three
//! messages are 32, 96 and 64 bytes, each well under the ~200-byte
//! fragment-friendly bound the issue asks for:
//!
//! ```text
//! initiator -> responder : e(32)
//! responder -> initiator : e(32) | enc_s(48) | enc_tag(16)
//! initiator -> responder : enc_s(48) | enc_tag(16)
//! ```
//!
//! Handshake messages never carry a payload; an input that does is
//! rejected as [`IdentError::HandshakeFailed`]. After the third
//! message [`HopHandshake::into_transport`] checks that the static key
//! proven in the handshake is the `agreement_pk` of the card the
//! caller pinned - an impostor's key fails with
//! [`IdentError::ImpostorCard`] *before* any transport key is handed
//! out, so nothing is ever sent under keys the card did not vouch for.
//! The card's self-signature is verified when the handshake is built,
//! before any message is exchanged.
//!
//! [Noise XX]: https://noiseprotocol.org/noise.html#the-xx-pattern

use core::fmt;

use rand_core::RngCore;
use snow::{
    Builder, Error as SnowError, HandshakeState, TransportState,
    params::{CipherChoice, DHChoice, HashChoice, NoiseParams},
    resolvers::{BoxedCryptoResolver, CryptoResolver, DefaultResolver, FallbackResolver},
    types::{Cipher, Dh, Hash, Random},
};

use crate::types::IdentError;
use crate::{Identity, IdentityCard};

/// The Noise suite: XX handshake over X25519 with ChaCha20-Poly1305
/// and SHA-256 (all three primitives are ADR-0001-listed; the suite
/// string itself is the standard Noise name).
const SUITE: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Bytes the ephemeral key generation draws: one X25519 key.
const EPHEMERAL_LEN: usize = 32;

/// Output buffer for one handshake message: the largest XX message
/// with an empty payload is 96 bytes (`e` + encrypted static + tag).
const MAX_HANDSHAKE_MSG: usize = 128;

/// The Noise Protocol Framework's per-message limit (snow's internal
/// `MAXMSGLEN`); a transport frame beyond it is [`IdentError::PayloadTooLarge`].
const MAX_NOISE_MSG: usize = 65535;

/// ChaCha20-Poly1305 tag appended to every sealed transport frame.
const TAG_LEN: usize = 16;

/// A Noise XX handshake in progress (IDN-13).
///
/// Drive it by alternately calling [`Self::write_message`] and
/// [`Self::read_message`] in the order the pattern dictates (the
/// initiator writes first), then finish with [`Self::into_transport`].
/// Out-of-order calls are [`IdentError::HandshakeFailed`].
pub struct HopHandshake {
    state: HandshakeState,
    /// The `agreement_pk` from the neighbour's card, checked against
    /// the static key the handshake proves.
    expected_remote: [u8; 32],
}

/// The transport phase of a completed hop handshake (IDN-13).
///
/// Frames are sealed with the Noise transport keys; the raw key bytes
/// are never exposed.
pub struct HopTransport {
    state: TransportState,
}

impl fmt::Debug for HopHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redacted: the handshake state holds key
        // material, so only the progress flag is printed.
        f.debug_struct("HopHandshake")
            .field("complete", &self.state.is_handshake_finished())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for HopTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redacted: the transport holds the session keys.
        f.debug_struct("HopTransport").finish_non_exhaustive()
    }
}

impl HopHandshake {
    /// Start a handshake as the side that writes the first message,
    /// pinning the neighbour's [`IdentityCard`]. `remote_card` is the
    /// card obtained out of band (QR, NFC): its self-signature is
    /// verified here and its `agreement_pk` must be the key the
    /// finished handshake proves.
    ///
    /// `rng` supplies the ephemeral key; this crate never reads an
    /// OS entropy source itself.
    pub fn initiator<R: RngCore + ?Sized>(
        local: &Identity,
        remote_card: &IdentityCard,
        rng: &mut R,
    ) -> Result<Self, IdentError> {
        Self::build(local, remote_card, rng, true)
    }

    /// Start a handshake as the side that reads the first message,
    /// pinning the neighbour's [`IdentityCard`]. See
    /// [`Self::initiator`] for the card and RNG semantics.
    pub fn responder<R: RngCore + ?Sized>(
        local: &Identity,
        remote_card: &IdentityCard,
        rng: &mut R,
    ) -> Result<Self, IdentError> {
        Self::build(local, remote_card, rng, false)
    }

    fn build<R: RngCore + ?Sized>(
        local: &Identity,
        remote_card: &IdentityCard,
        rng: &mut R,
        initiator: bool,
    ) -> Result<Self, IdentError> {
        // A forged or corrupted card fails before any handshake work.
        remote_card.verify()?;
        // snow's resolver must be `'static`, so a borrowed caller RNG
        // cannot be handed over: draw the ephemeral key's bytes here
        // and give snow a buffer-backed RNG instead.
        let mut drawn = [0_u8; EPHEMERAL_LEN];
        rng.fill_bytes(&mut drawn);
        let params: NoiseParams = SUITE
            .parse::<NoiseParams>()
            .map_err(|err| IdentError::HandshakeFailed(err.to_string()))?;
        let resolver: BoxedCryptoResolver = Box::new(FallbackResolver::new(
            Box::new(DrawnRngResolver { drawn }),
            Box::new(DefaultResolver),
        ));
        let builder = Builder::with_resolver(params, resolver)
            .local_private_key(local.secret().agreement_sk())
            .map_err(|err| IdentError::HandshakeFailed(err.to_string()))?;
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|err| IdentError::HandshakeFailed(err.to_string()))?;
        Ok(Self {
            state,
            expected_remote: *remote_card.agreement_pk(),
        })
    }

    /// The next handshake message for this side (XX message 1, 2 or
    /// 3), always with an empty payload. Writing out of turn, or after
    /// the handshake finished, is [`IdentError::HandshakeFailed`].
    pub fn write_message(&mut self) -> Result<Vec<u8>, IdentError> {
        let mut buf = [0_u8; MAX_HANDSHAKE_MSG];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|err| IdentError::HandshakeFailed(err.to_string()))?;
        Ok(buf[..len].to_vec())
    }

    /// Consume the next handshake message from the other side. The
    /// message must carry no payload (one that does fails), and
    /// malformed, truncated or out-of-order input is
    /// [`IdentError::HandshakeFailed`] - never a panic.
    pub fn read_message(&mut self, bytes: &[u8]) -> Result<(), IdentError> {
        let mut payload = [];
        self.state
            .read_message(bytes, &mut payload)
            .map_err(|err| IdentError::HandshakeFailed(err.to_string()))?;
        Ok(())
    }

    /// True once all three XX messages have been exchanged.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Finish the handshake and produce the transport.
    ///
    /// # Errors
    ///
    /// - [`IdentError::HandshakeNotComplete`] before the third message;
    /// - [`IdentError::ImpostorCard`] when the static key proven in the
    ///   handshake is not the `agreement_pk` of the pinned card: the
    ///   derived transport keys are discarded, so no frame is ever
    ///   sealed under keys an impostor could have contributed to.
    pub fn into_transport(self) -> Result<HopTransport, IdentError> {
        if !self.state.is_handshake_finished() {
            return Err(IdentError::HandshakeNotComplete);
        }
        let remote = self
            .state
            .get_remote_static()
            .ok_or_else(|| IdentError::HandshakeFailed("no remote static key".into()))?;
        if remote != self.expected_remote.as_slice() {
            return Err(IdentError::ImpostorCard);
        }
        let state = self
            .state
            .into_transport_mode()
            .map_err(|err| IdentError::HandshakeFailed(err.to_string()))?;
        Ok(HopTransport { state })
    }
}

impl HopTransport {
    /// Seal one hop frame. A plaintext over the Noise message limit
    /// is [`IdentError::PayloadTooLarge`], refused before anything is
    /// allocated.
    pub fn encrypt_msg(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, IdentError> {
        if plaintext.len() > MAX_NOISE_MSG - TAG_LEN {
            return Err(IdentError::PayloadTooLarge);
        }
        let mut buf = vec![0_u8; plaintext.len() + TAG_LEN];
        let len = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(map_transport_error)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Open one hop frame. Tampered or foreign ciphertext is
    /// [`IdentError::OpenFailed`]; a frame over the Noise message
    /// limit is [`IdentError::PayloadTooLarge`], refused before
    /// anything is allocated.
    pub fn decrypt_msg(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, IdentError> {
        if ciphertext.len() > MAX_NOISE_MSG {
            return Err(IdentError::PayloadTooLarge);
        }
        let mut buf = vec![0_u8; ciphertext.len()];
        let len = self
            .state
            .read_message(ciphertext, &mut buf)
            .map_err(map_transport_error)?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Map a transport-stage snow failure: an authentication failure is
/// [`IdentError::OpenFailed`], anything over the Noise message limit
/// is [`IdentError::PayloadTooLarge`], and anything else carries
/// snow's context in [`IdentError::HandshakeFailed`] (the remaining
/// variants - nonce exhaustion, a one-way pattern - cannot arise for
/// an XX transport built by this module).
fn map_transport_error(err: SnowError) -> IdentError {
    match err {
        SnowError::Decrypt => IdentError::OpenFailed,
        SnowError::Input => IdentError::PayloadTooLarge,
        other => IdentError::HandshakeFailed(other.to_string()),
    }
}

/// snow's resolver must be `'static`, so the caller's RNG cannot be
/// borrowed: this resolver hands out an RNG backed by bytes drawn from
/// the caller's RNG when the handshake was built. Only the RNG is
/// ours; DH, hash and cipher fall through to snow's pure-Rust default
/// resolver via [`FallbackResolver`].
struct DrawnRngResolver {
    drawn: [u8; EPHEMERAL_LEN],
}

impl CryptoResolver for DrawnRngResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(DrawnRandom {
            bytes: self.drawn,
            pos: 0,
        }))
    }

    fn resolve_dh(&self, _choice: &DHChoice) -> Option<Box<dyn Dh>> {
        None
    }

    fn resolve_hash(&self, _choice: &HashChoice) -> Option<Box<dyn Hash>> {
        None
    }

    fn resolve_cipher(&self, _choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        None
    }
}

/// The pre-drawn bytes handed to snow as its RNG. snow asks for the
/// 32-byte ephemeral key exactly once; asking for more than was drawn
/// is [`SnowError::Rng`], never a panic and never a silent reuse.
struct DrawnRandom {
    bytes: [u8; EPHEMERAL_LEN],
    pos: usize,
}

impl Random for DrawnRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SnowError> {
        let end = self.pos.checked_add(dest.len()).ok_or(SnowError::Rng)?;
        let src = self.bytes.get(self.pos..end).ok_or(SnowError::Rng)?;
        dest.copy_from_slice(src);
        self.pos = end;
        Ok(())
    }
}
