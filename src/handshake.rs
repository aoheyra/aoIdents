//! Noise XX hop handshake and host-side link sessions (IDN-13, IDN-14).
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
//! # Host ownership (IDN-14)
//!
//! aoMesh's sans-IO engine never holds a card, a handshake or a session
//! key. The **host** (aoheyra) owns all of them, outside the engine:
//!
//! - the neighbour's full [`IdentityCard`], obtained out of band; the
//!   engine carries only its 8-byte announcement hash in the signed
//!   `MeshHello` (MSH-07) and a capability bit;
//! - the in-flight [`HopHandshake`], driven in host code as Control
//!   frames arrive;
//! - the finished [`HopTransport`], installed into a [`HopSessions`]
//!   table kept beside the engine. The engine passes opaque Data frame
//!   bytes to the host, which calls [`HopSessions::seal_frame`] and
//!   [`HopSessions::open_frame`].
//!
//! Nothing is global or persisted: every piece of state is passed in
//! and drops when the host drops it. Closing a link marks its session
//! closed, so a late frame fails with a typed error rather than being
//! opened under a stale key.
//!
//! # Control and Data frame contract (IDN-14)
//!
//! Capability negotiation and aoMesh's own frame header live in aoMesh
//! (MSH-26); aoIdents owns the bytes inside the frames:
//!
//! ```text
//! Control body:  offset 0  1 byte   kind = 0x01 (Noise XX v1 handshake)
//!                offset 1  ..       Noise XX message (32, 96, 64 bytes, in order)
//! Data body:     raw HopTransport ciphertext; plaintext length + 16-byte tag
//! ```
//!
//! The kind byte lets a Control frame be demultiplexed before crypto;
//! the message index is deliberately not carried because the Noise
//! state machine already rejects out-of-order messages and an index
//! would be an unauthenticated field the peer could flip. Data frames
//! carry no aoIdents header: aoMesh decides which opaque bytes to
//! protect. A different Noise suite needs a new kind byte, an ADR and
//! a version bump; no signature domain is involved here.
//!
//! # Capability and cleartext fallback (IDN-14)
//!
//! - Both ends advertise the hop-encryption cap: run the three-message
//!   handshake over Control frames, verify the pinned card, then seal
//!   Data frames. A failed handshake never falls back silently: no
//!   session is installed and the host receives a typed error.
//! - Neither advertises it, or only one does: no handshake is run and
//!   Data frames stay in cleartext. End-to-end sealed content remains
//!   protected by aoIdents; link headers do not.
//!
//! The `MeshHello` carrying the cap is signed (MSH-07), so a third
//! party cannot strip it. A peer that genuinely lacks support can
//! still choose cleartext; that is an explicit limit, not a downgrade
//! of a peer that asked for encryption.
//!
//! # RNG seam (IDN-14)
//!
//! snow expects the `rand_core` 0.6 `RngCore`; aoMesh injects a 0.9
//! generator. Two options were considered: depend on both trait lines
//! and add a second blanket implementation, or inject a one-method
//! [`EntropySource`] implemented for this crate's existing 0.6
//! `RngCore` and for [`RngAdapter`], a closure newtype. The adapter is
//! chosen: 0.9's `fill_bytes(&mut [u8])` has the same shape, so a
//! closure bridges it with no second runtime dependency, no global
//! RNG and no I/O. Randomness remains an input, so seeded runs are
//! byte-identical.
//!
//! [Noise XX]: https://noiseprotocol.org/noise.html#the-xx-pattern

use core::fmt;
use std::collections::HashMap;

use rand_core::RngCore;
use snow::{
    Builder, Error as SnowError, HandshakeState, TransportState,
    params::{CipherChoice, DHChoice, HashChoice, NoiseParams},
    resolvers::{BoxedCryptoResolver, CryptoResolver, DefaultResolver, FallbackResolver},
    types::{Cipher, Dh, Hash, Random},
};

use crate::types::{IdentError, NodeId};
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

/// Host-side cap on simultaneous link sessions (IDN-14): twice aoMesh's
/// default neighbour table of 32, leaving room for in-flight rekeys
/// while keeping host memory bounded. A full table is a typed error,
/// never an eviction of a live session.
pub const MAX_HOP_SESSIONS: usize = 64;

/// The one randomness operation the handshake needs (IDN-14).
///
/// Its signature is the `fill_bytes(&mut [u8])` method shared by
/// `rand_core` 0.6 and 0.9. There is a blanket implementation for the
/// crate's 0.6 [`RngCore`], so existing callers keep working;
/// [`RngAdapter`] bridges a generator from another trait line through
/// a closure. No global RNG or I/O is involved.
pub trait EntropySource {
    /// Fill `dest` with fresh bytes, with the same semantics as
    /// [`RngCore::fill_bytes`].
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

impl<R: RngCore + ?Sized> EntropySource for R {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        RngCore::fill_bytes(self, dest);
    }
}

/// Bridge an injected generator that does not implement this crate's
/// `rand_core` 0.6 bound (IDN-14).
///
/// aoMesh's RNG is on `rand_core` 0.9: the host passes a closure that
/// calls its `fill_bytes`, and the closure becomes an [`EntropySource`]
/// without a second runtime dependency in this crate:
///
/// ```
/// use ao_idents::{HopHandshake, Identity, RngAdapter};
/// # use rand_core::{RngCore, CryptoRng};
/// # struct HostRng(u64);
/// # impl CryptoRng for HostRng {}
/// # impl RngCore for HostRng {
/// #     fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
/// #     fn next_u64(&mut self) -> u64 { self.0 += 1; self.0 }
/// #     fn fill_bytes(&mut self, dest: &mut [u8]) {
/// #         for chunk in dest.chunks_mut(8) {
/// #             let bytes = self.next_u64().to_le_bytes();
/// #             chunk.copy_from_slice(&bytes[..chunk.len()]);
/// #         }
/// #     }
/// #     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
/// #         self.fill_bytes(dest); Ok(())
/// #     }
/// # }
/// # let local = Identity::from_seed([1; 32]);
/// # let remote = Identity::from_seed([2; 32]);
/// # let card = remote.card(b"remote", 1_700_000_000).unwrap();
/// let mut host_rng = HostRng(7);
/// let mut bridge = RngAdapter::new(|dest: &mut [u8]| host_rng.fill_bytes(dest));
/// let _handshake = HopHandshake::initiator(&local, &card, &mut bridge);
/// ```
pub struct RngAdapter<F> {
    fill: F,
}

impl<F> RngAdapter<F> {
    /// Wrap a closure that fills a caller-provided buffer.
    #[must_use]
    pub const fn new(fill: F) -> Self {
        Self { fill }
    }
}

impl<F: FnMut(&mut [u8])> EntropySource for RngAdapter<F> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (self.fill)(dest);
    }
}

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
    /// pinning the neighbour's full [`IdentityCard`]. The card is
    /// obtained out of band (QR, NFC): its self-signature is verified
    /// here and its `agreement_pk` must be the key the finished
    /// handshake proves.
    ///
    /// `entropy` supplies the ephemeral key; this crate never reads an
    /// OS entropy source itself. The existing `rand_core` 0.6 callers
    /// keep working through [`EntropySource`]'s blanket
    /// implementation; [`RngAdapter`] bridges another trait line.
    pub fn initiator<S: EntropySource + ?Sized>(
        local: &Identity,
        remote_card: &IdentityCard,
        entropy: &mut S,
    ) -> Result<Self, IdentError> {
        Self::build(local, remote_card, None, entropy, true)
    }

    /// Start a handshake as the side that reads the first message,
    /// pinning the neighbour's full [`IdentityCard`]. See
    /// [`Self::initiator`] for the card and entropy semantics.
    pub fn responder<S: EntropySource + ?Sized>(
        local: &Identity,
        remote_card: &IdentityCard,
        entropy: &mut S,
    ) -> Result<Self, IdentError> {
        Self::build(local, remote_card, None, entropy, false)
    }

    /// Start as initiator when aoMesh knows only the neighbour's
    /// 8-byte card announcement hash (IDN-14). `remote_card` is the
    /// full card the host supplies out of band; both its self-signature
    /// and its [`IdentityCard::announcement_hash`] must match the
    /// pinned hash, or the handshake is refused before any bytes are
    /// exchanged ([`IdentError::CardHashMismatch`]).
    ///
    /// This is the path for hosts that carry a short hash in the
    /// signed `MeshHello` (MSH-07) and hold the card themselves; the
    /// full-card [`Self::initiator`] API remains available.
    pub fn initiator_pinned_by_hash<S: EntropySource + ?Sized>(
        local: &Identity,
        expected_card_hash: &[u8; 8],
        remote_card: &IdentityCard,
        entropy: &mut S,
    ) -> Result<Self, IdentError> {
        Self::build(local, remote_card, Some(expected_card_hash), entropy, true)
    }

    /// Start as responder with the card-hash pin (IDN-14). See
    /// [`Self::initiator_pinned_by_hash`] for the verification rules.
    pub fn responder_pinned_by_hash<S: EntropySource + ?Sized>(
        local: &Identity,
        expected_card_hash: &[u8; 8],
        remote_card: &IdentityCard,
        entropy: &mut S,
    ) -> Result<Self, IdentError> {
        Self::build(local, remote_card, Some(expected_card_hash), entropy, false)
    }

    fn build<S: EntropySource + ?Sized>(
        local: &Identity,
        remote_card: &IdentityCard,
        expected_hash: Option<&[u8; 8]>,
        entropy: &mut S,
        initiator: bool,
    ) -> Result<Self, IdentError> {
        // A forged card, or a card that is not the one the host pinned,
        // fails before any handshake work.
        match expected_hash {
            Some(hash) => remote_card.verify_pinned_by_hash(hash)?,
            None => remote_card.verify()?,
        }
        // snow's resolver must be `'static`, so a borrowed caller RNG
        // cannot be handed over: draw the ephemeral key's bytes here
        // and give snow a buffer-backed RNG instead.
        let mut drawn = [0_u8; EPHEMERAL_LEN];
        entropy.fill_bytes(&mut drawn);
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

/// Host-owned, bounded table of per-link hop sessions (IDN-14).
///
/// The host (aoheyra) creates this and keeps it **outside** aoMesh's
/// sans-IO engine: the engine only passes neighbour ids and opaque
/// frame bytes. Installing a transport after a successful handshake
/// makes that link encrypted; closing it on link-down makes later
/// frames fail as [`IdentError::HopSessionClosed`] instead of being
/// opened under stale keys. Keys never appear in [`fmt::Debug`].
///
/// There is no global state and no persistence: dropping the table
/// drops every session key with it.
pub struct HopSessions {
    entries: HashMap<NodeId, HopSessionEntry>,
}

enum HopSessionEntry {
    Open(HopTransport),
    Closed,
}

impl HopSessionEntry {
    fn state(&self) -> &'static str {
        match self {
            Self::Open(_) => "open",
            Self::Closed => "closed",
        }
    }
}

impl fmt::Debug for HopSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public neighbour ids and state only: the transports hold
        // session keys and must never be printed.
        let links: Vec<_> = self
            .entries
            .iter()
            .map(|(peer, entry)| (peer, entry.state()))
            .collect();
        f.debug_struct("HopSessions")
            .field("links", &links)
            .finish_non_exhaustive()
    }
}

impl Default for HopSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl HopSessions {
    /// Create an empty session table. Bounded to [`MAX_HOP_SESSIONS`]
    /// entries; no allocation happens until the first install.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Install (or replace, on rekey) the transport for `peer`.
    ///
    /// # Errors
    ///
    /// [`IdentError::HopSessionTableFull`] if the table already holds
    /// [`MAX_HOP_SESSIONS`] links and this peer has no entry. Live
    /// sessions are never evicted to make room.
    pub fn install(&mut self, peer: NodeId, transport: HopTransport) -> Result<(), IdentError> {
        if !self.entries.contains_key(&peer) && self.entries.len() >= MAX_HOP_SESSIONS {
            return Err(IdentError::HopSessionTableFull);
        }
        self.entries.insert(peer, HopSessionEntry::Open(transport));
        Ok(())
    }

    /// Mark a link's session closed, dropping its transport keys. A
    /// closed entry stays in the table so late frames are reported as
    /// [`IdentError::HopSessionClosed`], distinct from links that were
    /// never encrypted ([`IdentError::NoHopSession`]).
    ///
    /// Idempotent for an already closed link. Closing a link with no
    /// session is [`IdentError::NoHopSession`].
    pub fn close(&mut self, peer: NodeId) -> Result<(), IdentError> {
        match self.entries.get_mut(&peer) {
            Some(entry @ HopSessionEntry::Open(_)) => {
                *entry = HopSessionEntry::Closed;
                Ok(())
            }
            Some(HopSessionEntry::Closed) => Ok(()),
            None => Err(IdentError::NoHopSession(peer)),
        }
    }

    /// Remove a closed entry (or any entry) and free its slot. The
    /// host calls this when a link is gone for good; returns whether
    /// an entry was present.
    pub fn forget(&mut self, peer: NodeId) -> bool {
        self.entries.remove(&peer).is_some()
    }

    /// Number of entries, open and closed, currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Seal an opaque Data frame for `peer`. The plaintext is whatever
    /// bytes aoMesh hands to the host; the result is the raw
    /// [`HopTransport`] ciphertext carried in the Data frame body.
    ///
    /// # Errors
    ///
    /// - [`IdentError::NoHopSession`] when the link has no session;
    /// - [`IdentError::HopSessionClosed`] after link-down;
    /// - [`IdentError::PayloadTooLarge`] over the Noise message limit.
    pub fn seal_frame(&mut self, peer: NodeId, plaintext: &[u8]) -> Result<Vec<u8>, IdentError> {
        match self.entries.get_mut(&peer) {
            Some(HopSessionEntry::Open(transport)) => transport.encrypt_msg(plaintext),
            Some(HopSessionEntry::Closed) => Err(IdentError::HopSessionClosed(peer)),
            None => Err(IdentError::NoHopSession(peer)),
        }
    }

    /// Open an opaque Data frame from `peer`.
    ///
    /// # Errors
    ///
    /// - [`IdentError::NoHopSession`] or [`IdentError::HopSessionClosed`]
    ///   as for [`Self::seal_frame`];
    /// - [`IdentError::HopFrameInvalid`] for a malformed, tampered or
    ///   foreign frame (including a replay or the wrong direction);
    /// - [`IdentError::PayloadTooLarge`] over the Noise message limit.
    pub fn open_frame(&mut self, peer: NodeId, frame: &[u8]) -> Result<Vec<u8>, IdentError> {
        match self.entries.get_mut(&peer) {
            Some(HopSessionEntry::Open(transport)) => {
                transport.decrypt_msg(frame).map_err(|err| match err {
                    IdentError::OpenFailed => IdentError::HopFrameInvalid,
                    other => other,
                })
            }
            Some(HopSessionEntry::Closed) => Err(IdentError::HopSessionClosed(peer)),
            None => Err(IdentError::NoHopSession(peer)),
        }
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
