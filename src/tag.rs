//! Rotating link tags and beacon hints (IDN-12).
//!
//! A device advertises a short tag that changes over time: relays and
//! beacons see the tag, never the `NodeId`. Two modes:
//!
//! - **Baseline** ([`RotatingTag::random`]): derived from a secret
//!   random seed drawn from the injected RNG at construction. The seed
//!   is independent of the identity, so tags are unlinkable to the
//!   `NodeId` and to other devices. The epoch length is drawn within
//!   10-15 minutes with a random phase offset, so devices do not
//!   rotate in lockstep.
//! - **Pairwise** ([`RotatingTag::pairwise`]): derived from a shared
//!   pairwise secret (ADR-0001 `pairwise-tag`), so a contact holding
//!   the same secret recomputes the same tag from the same wall-clock
//!   time. Optional: the app enables it behind a setting (feeds
//!   MSH-25). Both sides must configure the same epoch length, so
//!   rotation is a pure function of time - no phase jitter here.

use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::identity::hkdf_expand;
use crate::types::IdentError;

/// HKDF info label for the baseline per-epoch tag (ADR-0001 registry),
/// suffixed with the big-endian epoch index.
const INFO_EPOCH_TAG: &str = "aoheyra/idn/v1/epoch-tag";

/// HKDF info label for the contact-recognisable tag (ADR-0001
/// registry), suffixed with the big-endian epoch index.
const INFO_PAIRWISE_TAG: &str = "aoheyra/idn/v1/pairwise-tag";

/// Shortest allowed epoch: 10 minutes, in milliseconds.
pub const EPOCH_MIN_MS: u64 = 10 * 60 * 1000;

/// Longest allowed epoch: 15 minutes, in milliseconds.
pub const EPOCH_MAX_MS: u64 = 15 * 60 * 1000;

/// Where a tag comes from. Both variants hold secret material and
/// zeroize on drop.
enum Mode {
    /// Secret random seed, independent of the identity.
    Baseline(Zeroizing<[u8; 32]>),
    /// Shared pairwise secret; both holders derive the same tag.
    Pairwise(Zeroizing<[u8; 32]>),
}

/// A time-rotating 16-byte link tag and its 8-byte beacon hint.
///
/// `Debug` prints the parameters, never the secret seed.
pub struct RotatingTag {
    mode: Mode,
    epoch_len_ms: u64,
    /// Phase offset of the epoch boundaries: baseline devices rotate
    /// at different instants even with the same epoch length.
    offset_ms: u64,
}

impl core::fmt::Debug for RotatingTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RotatingTag")
            .field(
                "mode",
                &match self.mode {
                    Mode::Baseline(_) => "baseline",
                    Mode::Pairwise(_) => "pairwise",
                },
            )
            .field("epoch_len_ms", &self.epoch_len_ms)
            .field("offset_ms", &self.offset_ms)
            .finish()
    }
}

impl RotatingTag {
    /// Baseline mode: draw an epoch length within 10-15 minutes, a
    /// phase offset and a 32-byte secret seed from the injected RNG.
    /// Nothing here is derived from the identity.
    pub fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let span = EPOCH_MAX_MS - EPOCH_MIN_MS + 1;
        let epoch_len_ms = EPOCH_MIN_MS + rng.next_u64() % span;
        let offset_ms = rng.next_u64() % epoch_len_ms;
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        Self {
            mode: Mode::Baseline(Zeroizing::new(seed_bytes)),
            epoch_len_ms,
            offset_ms,
        }
    }

    /// Pairwise mode: derive tags from a secret shared with a contact
    /// so both sides recompute the same tag at the same time.
    /// `epoch_len_ms` must be within [`EPOCH_MIN_MS`]..=
    /// [`EPOCH_MAX_MS`] (both sides configure the same value);
    /// otherwise [`IdentError::InvalidEpochLength`].
    pub fn pairwise(secret: [u8; 32], epoch_len_ms: u64) -> Result<Self, IdentError> {
        if !(EPOCH_MIN_MS..=EPOCH_MAX_MS).contains(&epoch_len_ms) {
            return Err(IdentError::InvalidEpochLength);
        }
        Ok(Self {
            mode: Mode::Pairwise(Zeroizing::new(secret)),
            epoch_len_ms,
            offset_ms: 0,
        })
    }

    /// The rotation period in milliseconds.
    #[must_use]
    pub fn epoch_len_ms(&self) -> u64 {
        self.epoch_len_ms
    }

    /// Which epoch `now_ms` falls in. Successive calls across a
    /// boundary return consecutive indices.
    #[must_use]
    pub fn epoch_index(&self, now_ms: u64) -> u64 {
        match self.mode {
            // Saturating: hostile or far-future `now` must not panic.
            Mode::Baseline(_) => now_ms.saturating_add(self.offset_ms) / self.epoch_len_ms,
            Mode::Pairwise(_) => now_ms / self.epoch_len_ms,
        }
    }

    /// The instant the epoch containing `now_ms` started (milliseconds,
    /// same clock the caller passed to [`Self::tag`]).
    #[must_use]
    pub fn epoch_start(&self, now_ms: u64) -> u64 {
        let boundary = self.epoch_index(now_ms) * self.epoch_len_ms;
        boundary.saturating_sub(self.offset_ms)
    }

    /// The 16-byte link tag for the epoch containing `now_ms`.
    ///
    /// Stable within an epoch, fresh (HKDF output under the registered
    /// info label and epoch index) in the next one. Baseline tags are
    /// unlinkable to the `NodeId`: the seed never touches the
    /// identity's keys.
    #[must_use]
    pub fn tag(&self, now_ms: u64) -> [u8; 16] {
        let epoch = self.epoch_index(now_ms);
        let (ikm, label): (&[u8; 32], &str) = match &self.mode {
            Mode::Baseline(seed) => (seed, INFO_EPOCH_TAG),
            Mode::Pairwise(secret) => (secret, INFO_PAIRWISE_TAG),
        };
        let mut info = Vec::with_capacity(label.len() + 8);
        info.extend_from_slice(label.as_bytes());
        info.extend_from_slice(&epoch.to_be_bytes());
        let okm = hkdf_expand(ikm, &info);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&okm[..16]);
        tag
    }

    /// The 8-byte beacon hint for the epoch containing `now_ms`: the
    /// first 8 bytes of the tag, so a receiver that sees the hint can
    /// check it against the full tag without a second derivation.
    #[must_use]
    pub fn hint(&self, now_ms: u64) -> [u8; 8] {
        let tag = self.tag(now_ms);
        let mut hint = [0u8; 8];
        hint.copy_from_slice(&tag[..8]);
        hint
    }
}
