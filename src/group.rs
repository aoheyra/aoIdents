//! Sender-key group encryption for private channels (IDN-17).
//!
//! Larger channels encrypt to a per-sender *chain* instead of to
//! every recipient: each member draws a [`SenderChain`], distributes
//! it once per member as a [`SenderKeyDistribution`] (an ordinary
//! [`SealedMessage`](crate::seal::SealedMessage) whose payload is the
//! chain state), and then every message is a single AEAD under a key
//! derived from the chain - no per-recipient work on send, no
//! per-recipient key material on the wire.
//!
//! The chain ratchets once per message: `mk_n || ck_{n+1}` is an
//! HKDF expansion of `ck_n` under the ADR-0001 domain
//! `aoheyra/idn/v1/group-sender`. A member who joins receives the
//! chain at its current position, so they can derive keys only from
//! that point forward - earlier messages stay unreadable. That is
//! why the chain and not a static key.
//!
//! **Removal rekeys** (the done-when): a removed member holds the
//! old chain, so every remaining sender calls [`SenderChain::rotate`]
//! (fresh chain key, epoch + 1) and redistributes only to the members
//! that remain. The removed member's copy derives keys for the old
//! chain only; messages under the new chain fail to open. Membership
//! changes themselves are signed statements under the ADR-0001
//! domain `aoheyra/idn/v1/group-admin` ([`MembershipChange`]).
//!
//! Delivery in a mesh can reorder, so a receiver that jumps forward
//! stores the message keys it skipped (bounded by
//! [`MAX_COUNTER_JUMP`]) and a late message within the window still
//! opens; counters at or behind the last accepted one are rejected as
//! replays. Every buffer is bounded: [`MAX_SENDERS_PER_GROUP`]
//! senders per receiver, [`MAX_COUNTER_JUMP`] stored keys per sender.
//!
//! ```text
//! distribution payload: group_id(16) | epoch(4) | next_counter(4) | chain_key(32)
//!
//! group message:        suite(1) | group_id(16) | sender_node_id(16)
//!                       | counter(4) | nonce(24) | ciphertext_len(2) | ciphertext
//!
//! membership:           group_id(16) | epoch(4) | action(1)
//!                       | member_node_id(16) | signature(64)
//! ```
//!
//! The AEAD's associated data is `suite | group_id | sender |
//! counter`, so a message cannot be moved between channels, senders
//! or counters.

use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::Identity;
use crate::identity::compute_node_id;
use crate::seal::{MSG_ID_LEN, NONCE_LEN, SealedMessage, cipher_from};
use crate::sign::verify_signing_pk;
use crate::types::{IdentError, NodeId, PublicIdentity, Signature, SuiteId};

/// Signature domain for channel membership statements (ADR-0001
/// registry).
const DOMAIN_GROUP_ADMIN: &str = "aoheyra/idn/v1/group-admin";

/// HKDF info for the sender chain ratchet (ADR-0001 registry). One
/// expansion produces the message key (first half) and the next
/// chain key (second half).
const INFO_GROUP_SENDER: &str = "aoheyra/idn/v1/group-sender";

/// Channel identifier bytes.
const GROUP_ID_LEN: usize = 16;

/// Chain, message-key and node-key bytes.
const KEY_LEN: usize = 32;

/// AEAD tag bytes.
const TAG_LEN: usize = 16;

/// Counter and epoch bytes on the wire.
const COUNTER_LEN: usize = 4;
const EPOCH_LEN: usize = 4;

/// `NodeId` bytes (see [`NodeId`]).
const MEMBER_LEN: usize = 16;

/// Upper bound on how far a message counter may jump ahead of the
/// receiver's chain position: enough to absorb a burst of reordered
/// or lost messages, small enough that derivation work and the
/// skipped-key store stay bounded (at most this many stored keys of
/// 32 bytes per sender).
pub const MAX_COUNTER_JUMP: u32 = 256;

/// Upper bound on the senders one receiver tracks per channel. A
/// channel is a bounded private group; the cap keeps a hostile
/// stream of valid distributions from growing the map without
/// limit.
pub const MAX_SENDERS_PER_GROUP: usize = 64;

/// Group message header: suite(1) + group id(16) + sender(16) +
/// counter(4) + nonce(24) + length(2).
const MSG_HEADER_LEN: usize = 1 + GROUP_ID_LEN + MEMBER_LEN + COUNTER_LEN + NONCE_LEN + 2;

/// The ciphertext is at least the AEAD tag; the length field covers
/// it, so the largest plaintext is `65535 - tag`.
const MIN_CIPHERTEXT_LEN: usize = TAG_LEN;
const MAX_PLAINTEXT_LEN: usize = u16::MAX as usize - TAG_LEN;

/// Distribution payload: group id + epoch + next counter + chain
/// key.
const DISTRIBUTION_LEN: usize = GROUP_ID_LEN + EPOCH_LEN + COUNTER_LEN + KEY_LEN;

/// Membership statement body: group id + epoch + action + member;
/// the statement is the body plus a 64-byte signature.
const MEMBERSHIP_BODY_LEN: usize = GROUP_ID_LEN + EPOCH_LEN + 1 + MEMBER_LEN;
const MEMBERSHIP_LEN: usize = MEMBERSHIP_BODY_LEN + 64;

/// A channel identifier: 16 random bytes drawn once when the channel
/// is created, carried by every distribution and message so keys
/// never work across channels.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct GroupId([u8; GROUP_ID_LEN]);

impl GroupId {
    /// Draw a fresh identifier from the caller's RNG.
    #[must_use]
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut raw = [0_u8; GROUP_ID_LEN];
        rng.fill_bytes(&mut raw);
        Self(raw)
    }

    /// Wrap raw identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; GROUP_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; GROUP_ID_LEN] {
        &self.0
    }
}

/// Whether a membership statement adds or removes a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipAction {
    /// The member joins the channel.
    Add,
    /// The member leaves the channel and must stop being
    /// distributed to.
    Remove,
}

impl MembershipAction {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Add => 0,
            Self::Remove => 1,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, IdentError> {
        match byte {
            0 => Ok(Self::Add),
            1 => Ok(Self::Remove),
            // The statement is well-sized but the action byte is not
            // one this suite version defines.
            _ => Err(IdentError::MalformedGroup),
        }
    }
}

/// One sender's chain state in a channel (IDN-17).
///
/// The chain is bearer state: whoever holds it can send as this
/// sender in this channel. Distribute it only through
/// [`Self::distribution_to`], and persist it - losing it means the
/// receiver's stored position can never be superseded except by a
/// new channel.
pub struct SenderChain {
    group_id: GroupId,
    suite: SuiteId,
    epoch: u32,
    chain_key: Zeroizing<[u8; KEY_LEN]>,
    next_counter: u32,
}

impl core::fmt::Debug for SenderChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately redacted: the chain key would let anyone send
        // as this sender, so only the public position is printed.
        f.debug_struct("SenderChain")
            .field("group_id", &self.group_id)
            .field("epoch", &self.epoch)
            .field("next_counter", &self.next_counter)
            .finish_non_exhaustive()
    }
}

/// A distribution of one [`SenderChain`] to one member: an ordinary
/// sealed message carrying the chain state, transportable as a
/// single blob (the `msg_id` travels with it, as everywhere in
/// IDN-09).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SenderKeyDistribution {
    sealed: SealedMessage,
    msg_id: [u8; MSG_ID_LEN],
}

/// One group message: authenticated by possession of the sender's
/// chain, not by a per-recipient seal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GroupMessage {
    suite: SuiteId,
    group_id: GroupId,
    sender: NodeId,
    counter: u32,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// A signed channel membership change (IDN-17): the admin attests
/// that `member` joined or left `group_id` at roster `epoch`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipChange {
    group_id: GroupId,
    epoch: u32,
    action: MembershipAction,
    member: NodeId,
    signature: Signature,
}

/// Receiver state for one channel: an installed chain per sender,
/// each ratcheting independently.
pub struct GroupReceiver {
    group_id: GroupId,
    senders: BTreeMap<NodeId, ReceiverChain>,
}

impl core::fmt::Debug for GroupReceiver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Chain keys are redacted; the sender count is public bookkeeping.
        f.debug_struct("GroupReceiver")
            .field("group_id", &self.group_id)
            .field("senders", &self.senders.len())
            .finish_non_exhaustive()
    }
}

/// One sender's ratchet position as the receiver sees it.
struct ReceiverChain {
    epoch: u32,
    next_counter: u32,
    chain_key: Zeroizing<[u8; KEY_LEN]>,
    /// Message keys for counters jumped over while accepting a later
    /// message, so reordered delivery within [`MAX_COUNTER_JUMP`]
    /// still opens. Bounded: only counters below `next_counter` are
    /// stored, the oldest are evicted first, and the map never grows
    /// past [`MAX_COUNTER_JUMP`] entries.
    skipped: BTreeMap<u32, Zeroizing<[u8; KEY_LEN]>>,
}

impl SenderChain {
    /// Draw the channel's first chain for `group_id`: a fresh chain
    /// key at epoch 0, counter 0.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(group_id: GroupId, rng: &mut R) -> Self {
        Self {
            group_id,
            suite: SuiteId::V1,
            epoch: 0,
            chain_key: draw_key(rng),
            next_counter: 0,
        }
    }

    /// Rotate in place: fresh chain key, epoch + 1, counter back to
    /// 0. This is the rekey - everyone still holding the old chain
    /// stops being able to read what follows, so redistribute with
    /// [`Self::distribution_to`] to the members that remain.
    ///
    /// `rotate` is also applied automatically when the counter is
    /// exhausted; either way the new chain must be redistributed
    /// before members can read the next message.
    pub fn rotate<R: RngCore + CryptoRng + ?Sized>(&mut self, rng: &mut R) {
        self.chain_key = draw_key(rng);
        self.epoch = self.epoch.wrapping_add(1);
        self.next_counter = 0;
    }

    /// Seal this chain's state to `recipient`, signed by `sender`.
    /// A member who joins gets the chain at its *current* position:
    /// they can derive message keys only from `next_counter`
    /// forward, never for messages sent before they joined.
    ///
    /// # Errors
    ///
    /// The signing errors of `sender`, plus the errors of
    /// [`SealedMessage::seal`](crate::seal::SealedMessage::seal).
    pub fn distribution_to<R: RngCore + CryptoRng + ?Sized>(
        &self,
        sender: &Identity,
        recipient: &PublicIdentity,
        rng: &mut R,
    ) -> Result<SenderKeyDistribution, IdentError> {
        let mut payload = Zeroizing::new(Vec::with_capacity(DISTRIBUTION_LEN));
        payload.extend_from_slice(self.group_id.as_bytes());
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(&self.next_counter.to_be_bytes());
        payload.extend_from_slice(&self.chain_key[..]);

        let mut msg_id = [0_u8; MSG_ID_LEN];
        rng.fill_bytes(&mut msg_id);
        let sealed = SealedMessage::seal(sender, recipient, &msg_id, &payload, rng)?;
        Ok(SenderKeyDistribution { sealed, msg_id })
    }

    /// Encrypt `plaintext` as this sender's next message. One AEAD
    /// under the derived message key - recipients are not involved.
    ///
    /// `rng` supplies the nonce (`CryptoRng`: confidentiality
    /// depends on it) and the chain rotation if the counter is
    /// exhausted.
    ///
    /// # Errors
    ///
    /// [`IdentError::PayloadTooLarge`] when the plaintext is over
    /// the encoding limit, refused before allocation.
    pub fn encrypt<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        sender: &Identity,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<GroupMessage, IdentError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(IdentError::PayloadTooLarge);
        }
        if self.next_counter == u32::MAX {
            // The counter is exhausted; rotate in place. The next
            // message rides the new chain and needs a redistribution
            // to be readable.
            self.rotate(rng);
        }
        let counter = self.next_counter;
        let sender_node = sender.node_id();
        let aad = associated_data(self.suite, &self.group_id, &sender_node, counter);

        let (mk, next_key) = derive_step(self.suite, &self.chain_key);
        let mk = Zeroizing::new(mk);
        let mut nonce = [0_u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let cipher = cipher_from(*mk);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            // The plaintext was bounded above, so length is the only
            // possible cause.
            .map_err(|_| IdentError::PayloadTooLarge)?;

        self.chain_key = Zeroizing::new(next_key);
        self.next_counter += 1;

        Ok(GroupMessage {
            suite: self.suite,
            group_id: self.group_id,
            sender: sender_node,
            counter,
            nonce,
            ciphertext,
        })
    }

    /// The channel this chain belongs to.
    #[must_use]
    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// The chain's epoch: 0 at creation, +1 per [`Self::rotate`].
    /// Receivers accept only a higher epoch, so a replayed old
    /// distribution can never move a chain backward.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The counter the next message will use.
    #[must_use]
    pub fn next_counter(&self) -> u32 {
        self.next_counter
    }
}

impl GroupReceiver {
    /// Receiver state for one channel; no senders installed until
    /// distributions arrive.
    #[must_use]
    pub fn new(group_id: GroupId) -> Self {
        Self {
            group_id,
            senders: BTreeMap::new(),
        }
    }

    /// The channel this receiver accepts messages for.
    #[must_use]
    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Whether a chain is installed for `sender`.
    #[must_use]
    pub fn has_sender(&self, sender: &NodeId) -> bool {
        self.senders.contains_key(sender)
    }

    /// Forget `sender`'s chain - the receiver-side half of removing
    /// a member: their later messages fail with
    /// [`IdentError::UnknownSender`]. Returns whether a chain was
    /// actually installed.
    pub fn remove_sender(&mut self, sender: &NodeId) -> bool {
        self.senders.remove(sender).is_some()
    }

    /// Install (or supersede) the sender's chain from a
    /// distribution addressed to `me`.
    ///
    /// A distribution is accepted when no chain exists for its
    /// sender, or when its epoch is strictly higher than the stored
    /// one. A duplicate or superseded distribution is ignored: a
    /// chain never moves backward, so a replayed old distribution
    /// cannot reset the position and re-open messages already
    /// rejected.
    ///
    /// # Errors
    ///
    /// The errors of [`SealedMessage::open`](crate::seal::SealedMessage::open)
    /// (wrong recipient, tampered field), [`IdentError::MalformedGroup`]
    /// for a payload that does not parse, [`IdentError::WrongGroup`]
    /// for a distribution addressed to another channel, and
    /// [`IdentError::TooManySenders`] when the channel is at
    /// [`MAX_SENDERS_PER_GROUP`].
    pub fn accept_distribution(
        &mut self,
        distribution: &SenderKeyDistribution,
        me: &Identity,
    ) -> Result<(), IdentError> {
        let opened = distribution.sealed.open(me, &distribution.msg_id)?;
        let payload = Zeroizing::new(opened.plaintext().to_vec());
        if payload.len() != DISTRIBUTION_LEN {
            return Err(IdentError::MalformedGroup);
        }

        let mut group_raw = [0_u8; GROUP_ID_LEN];
        group_raw.copy_from_slice(&payload[..GROUP_ID_LEN]);
        if GroupId::from_bytes(group_raw) != self.group_id {
            return Err(IdentError::WrongGroup);
        }
        let mut epoch = [0_u8; EPOCH_LEN];
        epoch.copy_from_slice(&payload[GROUP_ID_LEN..GROUP_ID_LEN + EPOCH_LEN]);
        let epoch = u32::from_be_bytes(epoch);
        let counter_start = GROUP_ID_LEN + EPOCH_LEN;
        let mut next_counter = [0_u8; COUNTER_LEN];
        next_counter.copy_from_slice(&payload[counter_start..counter_start + COUNTER_LEN]);
        let next_counter = u32::from_be_bytes(next_counter);
        let mut chain_key = Zeroizing::new([0_u8; KEY_LEN]);
        chain_key.copy_from_slice(&payload[counter_start + COUNTER_LEN..]);

        // The sender is the identity that signed the distribution,
        // not a claim inside the payload.
        let sender = compute_node_id(opened.sender().signing_pk(), opened.sender().agreement_pk());

        if let Some(current) = self.senders.get(&sender) {
            if epoch <= current.epoch {
                // Duplicate or superseded: keep the newer position.
                return Ok(());
            }
        } else if self.senders.len() >= MAX_SENDERS_PER_GROUP {
            return Err(IdentError::TooManySenders);
        }

        self.senders.insert(
            sender,
            ReceiverChain {
                epoch,
                next_counter,
                chain_key,
                skipped: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Decrypt `message`. On success the sender's chain advances to
    /// the counter after this one and the keys of every counter
    /// jumped over are kept for late delivery (bounded by
    /// [`MAX_COUNTER_JUMP`]); on any failure no state changes, so a
    /// hostile message can never burn a counter or a stored key.
    ///
    /// # Errors
    ///
    /// [`IdentError::WrongGroup`] for another channel,
    /// [`IdentError::UnknownSender`] when no chain is installed,
    /// [`IdentError::CounterTooOld`] for a replay or a message from
    /// before the chain was installed, [`IdentError::CounterTooFarAhead`]
    /// for a jump over [`MAX_COUNTER_JUMP`], and
    /// [`IdentError::OpenFailed`] when the AEAD check fails (wrong
    /// chain, tampered field).
    pub fn decrypt(&mut self, message: &GroupMessage) -> Result<Vec<u8>, IdentError> {
        if message.group_id != self.group_id {
            return Err(IdentError::WrongGroup);
        }
        let chain = self
            .senders
            .get_mut(&message.sender)
            .ok_or(IdentError::UnknownSender)?;
        let target = message.counter;
        let aad = associated_data(message.suite, &message.group_id, &message.sender, target);

        // A counter the chain already jumped past may still hold its
        // cached key: reordered delivery within the window.
        if let Some(mk) = chain.skipped.get(&target) {
            let mk = Zeroizing::new(**mk);
            let cipher = cipher_from(*mk);
            let plaintext = cipher
                .decrypt(
                    &XNonce::from(message.nonce),
                    Payload {
                        msg: &message.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| IdentError::OpenFailed)?;
            chain.skipped.remove(&target);
            return Ok(plaintext);
        }

        let current = chain.next_counter;
        if target < current {
            return Err(IdentError::CounterTooOld);
        }
        let steps = target - current;
        if steps > MAX_COUNTER_JUMP {
            return Err(IdentError::CounterTooFarAhead);
        }

        let mut ck = Zeroizing::new(*chain.chain_key);
        let mut pending: Vec<Zeroizing<[u8; KEY_LEN]>> = Vec::with_capacity(steps as usize);
        for _ in 0..steps {
            let (mk, next) = derive_step(message.suite, &ck);
            pending.push(Zeroizing::new(mk));
            ck = Zeroizing::new(next);
        }
        let (mk, next_key) = derive_step(message.suite, &ck);
        let mk = Zeroizing::new(mk);
        let cipher = cipher_from(*mk);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(message.nonce),
                Payload {
                    msg: &message.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| IdentError::OpenFailed)?;

        // Authenticated: commit the chain and keep the skipped keys
        // for messages that may still arrive late.
        for (offset, key) in pending.into_iter().enumerate() {
            chain.skipped.insert(current + offset as u32, key);
        }
        while chain.skipped.len() > MAX_COUNTER_JUMP as usize {
            chain.skipped.pop_first();
        }
        chain.chain_key = Zeroizing::new(next_key);
        chain.next_counter = target.saturating_add(1);
        Ok(plaintext)
    }
}

impl GroupMessage {
    /// The canonical wire encoding (see the module docs for the
    /// layout).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MSG_HEADER_LEN + self.ciphertext.len());
        out.push(self.suite.byte());
        out.extend_from_slice(self.group_id.as_bytes());
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode the wire encoding. Every field is bounds-checked
    /// before it is read: a truncated or trailing input is
    /// [`IdentError::MalformedGroup`], an unknown suite byte is
    /// [`IdentError::UnknownSuite`]. Decryption decides validity,
    /// never this function.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < MSG_HEADER_LEN {
            return Err(IdentError::MalformedGroup);
        }
        let suite = SuiteId::try_from(bytes[0])?;
        let mut group_raw = [0_u8; GROUP_ID_LEN];
        group_raw.copy_from_slice(&bytes[1..1 + GROUP_ID_LEN]);
        let sender_start = 1 + GROUP_ID_LEN;
        let mut sender_raw = [0_u8; MEMBER_LEN];
        sender_raw.copy_from_slice(&bytes[sender_start..sender_start + MEMBER_LEN]);
        let counter_start = sender_start + MEMBER_LEN;
        let mut counter = [0_u8; COUNTER_LEN];
        counter.copy_from_slice(&bytes[counter_start..counter_start + COUNTER_LEN]);
        let nonce_start = counter_start + COUNTER_LEN;
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[nonce_start..nonce_start + NONCE_LEN]);
        let len_start = nonce_start + NONCE_LEN;
        let mut length = [0_u8; 2];
        length.copy_from_slice(&bytes[len_start..MSG_HEADER_LEN]);
        let ciphertext_len = usize::from(u16::from_be_bytes(length));
        if ciphertext_len < MIN_CIPHERTEXT_LEN || bytes.len() != MSG_HEADER_LEN + ciphertext_len {
            return Err(IdentError::MalformedGroup);
        }
        Ok(Self {
            suite,
            group_id: GroupId::from_bytes(group_raw),
            sender: NodeId::from_bytes(sender_raw),
            counter: u32::from_be_bytes(counter),
            nonce,
            ciphertext: bytes[MSG_HEADER_LEN..].to_vec(),
        })
    }

    /// The suite this message was sealed under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The channel this message belongs to.
    #[must_use]
    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// The sending member's [`NodeId`].
    #[must_use]
    pub fn sender(&self) -> NodeId {
        self.sender
    }

    /// The sender-chain counter this message was derived at.
    #[must_use]
    pub fn counter(&self) -> u32 {
        self.counter
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

impl SenderKeyDistribution {
    /// The canonical transport encoding: `msg_id` then the sealed
    /// message (see the module docs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MSG_ID_LEN);
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.sealed.encode());
        out
    }

    /// Decode a distribution blob. The `msg_id` prefix and the
    /// sealed message's own bounds are checked before anything is
    /// read; a truncated input is [`IdentError::MalformedGroup`].
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() <= MSG_ID_LEN {
            return Err(IdentError::MalformedGroup);
        }
        let mut msg_id = [0_u8; MSG_ID_LEN];
        msg_id.copy_from_slice(&bytes[..MSG_ID_LEN]);
        let sealed = SealedMessage::decode(&bytes[MSG_ID_LEN..])?;
        Ok(Self { sealed, msg_id })
    }
}

impl MembershipChange {
    /// Sign a membership change: `admin` attests that `member`
    /// joined or left `group_id` at roster `epoch`. Statements are
    /// ordered by epoch; a receiver applies only epochs above the
    /// last one it applied, so a stale "add" cannot resurrect a
    /// removed member.
    ///
    /// # Errors
    ///
    /// The signing errors of `admin`.
    pub fn sign(
        admin: &Identity,
        group_id: GroupId,
        epoch: u32,
        action: MembershipAction,
        member: NodeId,
    ) -> Result<Self, IdentError> {
        let body = Self::body_of(group_id, epoch, action, member);
        let signature = admin.sign(DOMAIN_GROUP_ADMIN, &body)?;
        Ok(Self {
            group_id,
            epoch,
            action,
            member,
            signature,
        })
    }

    /// Verify the statement against `admin`'s signing key.
    ///
    /// # Errors
    ///
    /// [`IdentError::InvalidPublicKey`] for a key the signature
    /// cannot be checked against, [`IdentError::InvalidSignature`]
    /// for a forged or tampered statement.
    pub fn verify(&self, admin: &PublicIdentity) -> Result<(), IdentError> {
        verify_signing_pk(
            admin.signing_pk(),
            DOMAIN_GROUP_ADMIN,
            &self.body(),
            &self.signature,
        )
    }

    /// The channel this statement is about.
    #[must_use]
    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// The roster epoch this statement advances to.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Whether the statement adds or removes the member.
    #[must_use]
    pub fn action(&self) -> MembershipAction {
        self.action
    }

    /// The member the statement is about.
    #[must_use]
    pub fn member(&self) -> NodeId {
        self.member
    }

    /// The canonical encoding: body plus signature (see the module
    /// docs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Decode a membership statement. Every field is bounds-checked
    /// before it is read: a truncated or trailing input, or an
    /// action byte this suite version does not define, is
    /// [`IdentError::MalformedGroup`]. Signature validity is decided
    /// by [`Self::verify`], never here.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() != MEMBERSHIP_LEN {
            return Err(IdentError::MalformedGroup);
        }
        let mut group_raw = [0_u8; GROUP_ID_LEN];
        group_raw.copy_from_slice(&bytes[..GROUP_ID_LEN]);
        let mut epoch = [0_u8; EPOCH_LEN];
        epoch.copy_from_slice(&bytes[GROUP_ID_LEN..GROUP_ID_LEN + EPOCH_LEN]);
        let action = MembershipAction::from_byte(bytes[GROUP_ID_LEN + EPOCH_LEN])?;
        let member_start = GROUP_ID_LEN + EPOCH_LEN + 1;
        let mut member_raw = [0_u8; MEMBER_LEN];
        member_raw.copy_from_slice(&bytes[member_start..MEMBERSHIP_BODY_LEN]);
        let mut sig_raw = [0_u8; 64];
        sig_raw.copy_from_slice(&bytes[MEMBERSHIP_BODY_LEN..]);
        Ok(Self {
            group_id: GroupId::from_bytes(group_raw),
            epoch: u32::from_be_bytes(epoch),
            action,
            member: NodeId::from_bytes(member_raw),
            signature: Signature::from_bytes(sig_raw),
        })
    }

    /// The signature covers: group id + epoch + action + member.
    fn body(&self) -> Vec<u8> {
        Self::body_of(self.group_id, self.epoch, self.action, self.member)
    }

    fn body_of(group_id: GroupId, epoch: u32, action: MembershipAction, member: NodeId) -> Vec<u8> {
        let mut body = Vec::with_capacity(MEMBERSHIP_BODY_LEN);
        body.extend_from_slice(group_id.as_bytes());
        body.extend_from_slice(&epoch.to_be_bytes());
        body.push(action.to_byte());
        body.extend_from_slice(member.as_bytes());
        body
    }
}

/// Draw an independent 32-byte chain key from the caller's RNG.
fn draw_key<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Zeroizing<[u8; KEY_LEN]> {
    let mut raw = Zeroizing::new([0_u8; KEY_LEN]);
    rng.fill_bytes(&mut *raw);
    raw
}

/// One ratchet step: expand the chain key under the ADR-0001
/// `group-sender` label into the message key (first half) and the
/// next chain key (second half). The 64-byte output is a constant
/// length, so the expand step cannot fail for any input - the same
/// reasoning as `identity::hkdf_expand`.
fn derive_step(suite: SuiteId, chain_key: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let hk = Hkdf::<Sha256>::new(Some(&[suite.byte()]), chain_key);
    let mut okm = Zeroizing::new([0_u8; 2 * KEY_LEN]);
    hk.expand(INFO_GROUP_SENDER.as_bytes(), &mut *okm)
        .expect("64 bytes is always a valid HKDF-SHA-256 output length");
    let mut mk = [0_u8; KEY_LEN];
    mk.copy_from_slice(&okm[..KEY_LEN]);
    let mut next = [0_u8; KEY_LEN];
    next.copy_from_slice(&okm[KEY_LEN..]);
    (mk, next)
}

/// The AEAD's associated data: suite, channel, sender and counter,
/// so a message cannot be moved between channels, senders or
/// counters.
fn associated_data(
    suite: SuiteId,
    group_id: &GroupId,
    sender: &NodeId,
    counter: u32,
) -> [u8; 1 + GROUP_ID_LEN + MEMBER_LEN + COUNTER_LEN] {
    let mut aad = [0_u8; 1 + GROUP_ID_LEN + MEMBER_LEN + COUNTER_LEN];
    aad[0] = suite.byte();
    aad[1..1 + GROUP_ID_LEN].copy_from_slice(group_id.as_bytes());
    let sender_start = 1 + GROUP_ID_LEN;
    aad[sender_start..sender_start + MEMBER_LEN].copy_from_slice(sender.as_bytes());
    aad[sender_start + MEMBER_LEN..].copy_from_slice(&counter.to_be_bytes());
    aad
}
