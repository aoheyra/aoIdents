//! Replay guard at the final recipient (IDN-14).
//!
//! A sealed message that opens proves nothing about *freshness*: anyone
//! who observed it can present it again. [`ReplayGuard::accept`] is the
//! second check, run at the recipient after
//! [`crate::SealedMessage::open`] succeeds: it records
//! `(sender, msg_id)` and refuses the same pair a second time.
//!
//! Two independent bounds keep a replay out:
//!
//! - **Sliding window.** Each sender keeps its last
//!   [`ReplayConfig::window`] message ids. A replay inside that window
//!   is [`IdentError::Replay`].
//! - **Timestamp tolerance.** A message whose authenticated timestamp
//!   is more than [`ReplayConfig::tolerance_ms`] away from `now` - in
//!   either direction - is [`IdentError::StaleTimestamp`], so a replay
//!   whose id has already left the window is still refused once it ages
//!   out, and a far-future timestamp cannot pin an entry forever.
//!
//! The timestamp is supplied by the caller from the authenticated
//! message header (aoMesh binds it into `msg_id`, MSH-04); this crate
//! never parses packets and cannot check that binding itself.
//!
//! **Bounds.** `window x max_senders` entries are the whole memory
//! cost: with the default config (`64 x 256` entries of 24 bytes) the
//! guard tops out near 400 KiB. A sender map at capacity first drops
//! senders with no message inside the tolerance window; if every
//! remaining sender is fresh, a *new* sender is
//! [`IdentError::GuardFull`] rather than evicting a live entry - an
//! eviction would reopen a replay hole, and availability is
//! explicitly not this crate's guarantee (`docs/threat-model.md`).
//!
//! This is deliberately not aoMesh's seen-cache: that one deduplicates
//! *forwarding* so a packet is not relayed twice; this one rejects
//! *delivery* of a message the recipient has already accepted. The two
//! are different questions and must not be merged.
//!
//! [`ReplayGuard::encode`] / [`ReplayGuard::decode`] persist the state
//! across a restart. The encoding carries no configuration: the caller
//! passes its [`ReplayConfig`] to `decode`, so a hostile file can never
//! raise the caps the process chose.

use std::collections::{BTreeMap, VecDeque};

use crate::seal::MSG_ID_LEN;
use crate::types::{IdentError, NodeId};

/// Encoding version of the serialized guard state.
const ENCODE_VERSION: u8 = 1;

/// File header: version (1) + sender count (2).
const HEADER_LEN: usize = 3;

/// Per-sender prefix: `node_id(16) | last_seen_ms(8) | entry_count(2)`.
const SENDER_PREFIX_LEN: usize = 16 + 8 + 2;

/// Per entry: `msg_id(16) | timestamp_ms(8)`.
const ENTRY_LEN: usize = MSG_ID_LEN + 8;

/// Largest per-sender window a config may request.
pub const MAX_WINDOW: usize = 1024;

/// Largest sender map a config may request.
pub const MAX_SENDERS: usize = 4096;

/// Largest timestamp tolerance a config may request (24 hours).
pub const MAX_TOLERANCE_MS: u64 = 86_400_000;

/// Largest `window x max_senders` product: bounds worst-case memory
/// for any accepted configuration (65 536 entries x 24 bytes, about
/// 1.5 MiB at the absolute ceiling; the default config is 400 KiB).
pub const MAX_ENTRIES: usize = 65_536;

// The encoders write these counts as `u16`; the config validator keeps
// every count at or below these constants, so the conversions below
// cannot truncate.
const _: () = assert!(MAX_WINDOW <= u16::MAX as usize);
const _: () = assert!(MAX_SENDERS <= u16::MAX as usize);

/// Tuning for a [`ReplayGuard`], validated at construction.
///
/// Errors: [`IdentError::InvalidGuardConfig`] for a zero or oversized
/// field, or for a `window x max_senders` product over
/// [`MAX_ENTRIES`]. A config is never silently clamped - the caller
/// learns its request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReplayConfig {
    window: usize,
    tolerance_ms: u64,
    max_senders: usize,
}

impl ReplayConfig {
    /// Validate a configuration. Every bound is tested; see the
    /// constants for the supported ranges.
    pub fn new(window: usize, tolerance_ms: u64, max_senders: usize) -> Result<Self, IdentError> {
        if window == 0 || window > MAX_WINDOW {
            return Err(IdentError::InvalidGuardConfig);
        }
        if tolerance_ms == 0 || tolerance_ms > MAX_TOLERANCE_MS {
            return Err(IdentError::InvalidGuardConfig);
        }
        if max_senders == 0 || max_senders > MAX_SENDERS {
            return Err(IdentError::InvalidGuardConfig);
        }
        let entries = window
            .checked_mul(max_senders)
            .ok_or(IdentError::InvalidGuardConfig)?;
        if entries > MAX_ENTRIES {
            return Err(IdentError::InvalidGuardConfig);
        }
        Ok(Self {
            window,
            tolerance_ms,
            max_senders,
        })
    }

    /// Message ids remembered per sender (sliding window size).
    #[must_use]
    pub fn window(&self) -> usize {
        self.window
    }

    /// Timestamp tolerance in milliseconds, applied in both
    /// directions around `now`.
    #[must_use]
    pub fn tolerance_ms(&self) -> u64 {
        self.tolerance_ms
    }

    /// Distinct senders the guard tracks at once.
    #[must_use]
    pub fn max_senders(&self) -> usize {
        self.max_senders
    }
}

impl Default for ReplayConfig {
    /// 64 message ids per sender, 5-minute tolerance, 256 senders:
    /// about 400 KiB at full occupancy, far more than a conversation
    /// needs and small enough for a phone.
    fn default() -> Self {
        // Invariants hold by construction; `expect` is unreachable.
        Self::new(64, 300_000, 256).expect("default replay config is within bounds")
    }
}

/// One sender's remembered messages.
#[derive(Clone, PartialEq, Eq)]
struct SenderState {
    /// `now` at the last accepted message; drives expiry of the
    /// whole entry when the map is at capacity.
    last_seen_ms: u64,
    /// `(msg_id, message timestamp)` in arrival order, front oldest.
    window: VecDeque<([u8; MSG_ID_LEN], u64)>,
}

/// Per-sender replay state, bounded by [`ReplayConfig`]. See the
/// module docs for the two-bound design and the fail-closed rule.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayGuard {
    config: ReplayConfig,
    senders: BTreeMap<NodeId, SenderState>,
}

impl core::fmt::Debug for ReplayGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReplayGuard")
            .field("config", &self.config)
            .field("senders", &self.senders.len())
            .finish()
    }
}

impl ReplayGuard {
    /// An empty guard under `config`.
    #[must_use]
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            config,
            senders: BTreeMap::new(),
        }
    }

    /// The configuration this guard enforces.
    #[must_use]
    pub fn config(&self) -> &ReplayConfig {
        &self.config
    }

    /// Distinct senders currently remembered (a memory observation,
    /// never above `config.max_senders`).
    #[must_use]
    pub fn sender_count(&self) -> usize {
        self.senders.len()
    }

    /// Accept `msg_id` from `sender` unless it is a replay.
    ///
    /// `msg_timestamp_ms` is the message's authenticated timestamp and
    /// `now_ms` the local clock; both are parameters - this crate
    /// reads no clock. Runs, in order:
    ///
    /// 1. the timestamp must sit within `tolerance_ms` of `now` in
    ///    both directions ([`IdentError::StaleTimestamp`]);
    /// 2. an id already in the sender's window is
    ///    [`IdentError::Replay`];
    /// 3. a full window after expiring stale entries is
    ///    [`IdentError::GuardFull`];
    /// 4. a new sender at map capacity first expires senders silent
    ///    for longer than the tolerance, and otherwise fails with
    ///    [`IdentError::GuardFull`] rather than evicting a live entry.
    ///
    /// On success the message is recorded and later replays are
    /// refused; out-of-order messages with fresh timestamps are
    /// accepted, which is the done-when of IDN-14.
    pub fn accept(
        &mut self,
        sender: NodeId,
        msg_id: &[u8; MSG_ID_LEN],
        msg_timestamp_ms: u64,
        now_ms: u64,
    ) -> Result<(), IdentError> {
        let tolerance = self.config.tolerance_ms;
        if now_ms.saturating_sub(msg_timestamp_ms) > tolerance
            || msg_timestamp_ms.saturating_sub(now_ms) > tolerance
        {
            return Err(IdentError::StaleTimestamp);
        }

        if let Some(state) = self.senders.get_mut(&sender) {
            // Drop entries the timestamp bound would refuse today, so
            // a quiet sender's window frees itself.
            state
                .window
                .retain(|&(_, ts)| now_ms.saturating_sub(ts) <= tolerance);
            if state.window.iter().any(|&(id, _)| id == *msg_id) {
                return Err(IdentError::Replay);
            }
            if state.window.len() >= self.config.window {
                return Err(IdentError::GuardFull);
            }
            state.window.push_back((*msg_id, msg_timestamp_ms));
            state.last_seen_ms = now_ms;
            return Ok(());
        }

        if self.senders.len() >= self.config.max_senders {
            // Free only entries that carry no fresh message: evicting
            // a live sender would let its replayed messages back in.
            self.senders
                .retain(|_, state| now_ms.saturating_sub(state.last_seen_ms) <= tolerance);
            if self.senders.len() >= self.config.max_senders {
                return Err(IdentError::GuardFull);
            }
        }

        let mut window = VecDeque::new();
        window.push_back((*msg_id, msg_timestamp_ms));
        self.senders.insert(
            sender,
            SenderState {
                last_seen_ms: now_ms,
                window,
            },
        );
        Ok(())
    }

    /// The canonical encoding of the guard's state (no configuration
    /// is embedded; see [`ReplayGuard::decode`]):
    ///
    /// ```text
    /// version(1) | sender_count(2)
    ///   | node_id(16) | last_seen_ms(8) | entry_count(2)
    ///   | (msg_id(16) | timestamp_ms(8)) x entry_count
    /// ```
    ///
    /// Counts come from validated state, so they always fit their
    /// fields; `sender_count` is sorted by `NodeId` (`BTreeMap`
    /// order), making the encoding deterministic.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let entries: usize = self.senders.values().map(|s| s.window.len()).sum();
        let mut out = Vec::with_capacity(
            HEADER_LEN + self.senders.len() * SENDER_PREFIX_LEN + entries * ENTRY_LEN,
        );
        out.push(ENCODE_VERSION);
        let sender_count = u16::try_from(self.senders.len())
            .expect("max_senders is const-asserted below u16::MAX");
        out.extend_from_slice(&sender_count.to_be_bytes());
        for (node_id, state) in &self.senders {
            out.extend_from_slice(node_id.as_bytes());
            out.extend_from_slice(&state.last_seen_ms.to_be_bytes());
            let entry_count =
                u16::try_from(state.window.len()).expect("window is const-asserted below u16::MAX");
            out.extend_from_slice(&entry_count.to_be_bytes());
            for (msg_id, timestamp_ms) in &state.window {
                out.extend_from_slice(msg_id);
                out.extend_from_slice(&timestamp_ms.to_be_bytes());
            }
        }
        out
    }

    /// Restore a guard from [`ReplayGuard::encode`] under `config`.
    ///
    /// `config` comes from the caller, never from the bytes: a
    /// hostile file cannot raise the process's caps. Every length is
    /// bounds-checked before it is read or allocated, and the total
    /// must match exactly - truncation, trailing bytes, an unknown
    /// version, a count over `config`, a duplicate entry or a
    /// duplicate sender are all [`IdentError::MalformedGuard`], never
    /// a panic and never a partial state.
    pub fn decode(bytes: &[u8], config: ReplayConfig) -> Result<Self, IdentError> {
        if bytes.len() < HEADER_LEN || bytes[0] != ENCODE_VERSION {
            return Err(IdentError::MalformedGuard);
        }
        let sender_count = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        if sender_count > config.max_senders {
            return Err(IdentError::MalformedGuard);
        }

        let mut offset = HEADER_LEN;
        let mut senders = BTreeMap::new();
        for _ in 0..sender_count {
            if bytes.len() < offset + SENDER_PREFIX_LEN {
                return Err(IdentError::MalformedGuard);
            }
            let mut node_id = [0u8; 16];
            node_id.copy_from_slice(&bytes[offset..offset + 16]);
            let mut last_seen = [0u8; 8];
            last_seen.copy_from_slice(&bytes[offset + 16..offset + 24]);
            let entry_count =
                usize::from(u16::from_be_bytes([bytes[offset + 24], bytes[offset + 25]]));
            offset += SENDER_PREFIX_LEN;

            // `entry_count <= config.window <= MAX_WINDOW`, so the
            // product below cannot overflow.
            if entry_count == 0 || entry_count > config.window {
                return Err(IdentError::MalformedGuard);
            }
            let entries_len = entry_count * ENTRY_LEN;
            if bytes.len() < offset + entries_len {
                return Err(IdentError::MalformedGuard);
            }

            let mut window = VecDeque::with_capacity(entry_count);
            for _ in 0..entry_count {
                let mut msg_id = [0u8; MSG_ID_LEN];
                msg_id.copy_from_slice(&bytes[offset..offset + MSG_ID_LEN]);
                let mut timestamp = [0u8; 8];
                timestamp.copy_from_slice(&bytes[offset + MSG_ID_LEN..offset + ENTRY_LEN]);
                if window.iter().any(|&(id, _)| id == msg_id) {
                    // `accept` never records an id twice, so a
                    // duplicate is a non-canonical file.
                    return Err(IdentError::MalformedGuard);
                }
                window.push_back((msg_id, u64::from_be_bytes(timestamp)));
                offset += ENTRY_LEN;
            }

            let state = SenderState {
                last_seen_ms: u64::from_be_bytes(last_seen),
                window,
            };
            if senders.insert(NodeId::from_bytes(node_id), state).is_some() {
                return Err(IdentError::MalformedGuard);
            }
        }

        if offset != bytes.len() {
            return Err(IdentError::MalformedGuard);
        }

        Ok(Self { config, senders })
    }
}
