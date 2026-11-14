//! Signed public blobs (IDN-11): presence announcements and public
//! channel payloads - sign only, no encryption.
//!
//! A [`SignedBlob`] is broadcast as-is: anyone holding the origin's
//! [`PublicIdentity`] can verify it. Freshness is caller-owned: this
//! crate has no clock, so [`SignedBlob::verify`] takes the highest
//! `seq` accepted so far and rejects anything not strictly newer with
//! a different error than a forged blob.

use crate::Identity;
use crate::types::{IdentError, NodeId, PublicIdentity, Signature, SuiteId};

/// Signature domain for signed blobs (ADR-0001 registry).
const DOMAIN_BLOB: &str = "aoheyra/idn/v1/blob";

/// Fixed bytes before the payload: suite(1) + origin(16) + seq(8) +
/// timestamp(8) + payload length(2).
const HEADER_LEN: usize = 1 + 16 + 8 + 8 + 2;

/// Signature bytes appended to every encoded blob.
const SIG_LEN: usize = 64;

/// One signed, public piece of data: who published it, its monotonic
/// sequence number, a caller-owned timestamp and an opaque payload.
///
/// The signature covers the canonical encoding of every field except
/// the signature itself (ADR-0001 canonical encoding), so a tampered
/// origin, seq, timestamp or payload never verifies.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedBlob {
    suite: SuiteId,
    origin: NodeId,
    seq: u64,
    timestamp: u64,
    payload: Vec<u8>,
    signature: Signature,
}

impl core::fmt::Debug for SignedBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlob")
            .field("suite", &self.suite)
            .field("origin", &self.origin)
            .field("seq", &self.seq)
            .field("timestamp", &self.timestamp)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl SignedBlob {
    /// Sign `payload` under the origin's identity with the given `seq`
    /// and `timestamp`.
    ///
    /// `timestamp` is opaque to this crate (no clock here): the caller
    /// decides what it means and whether to compare it. `payload` is
    /// capped at 65535 bytes because the canonical encoding prefixes it
    /// with a `u16` length; a longer payload is
    /// [`IdentError::PayloadTooLarge`], never truncated.
    pub fn sign(
        identity: &Identity,
        seq: u64,
        timestamp: u64,
        payload: Vec<u8>,
    ) -> Result<Self, IdentError> {
        if payload.len() > u16::MAX as usize {
            return Err(IdentError::PayloadTooLarge);
        }
        let body = body_bytes(
            identity.suite(),
            identity.node_id(),
            seq,
            timestamp,
            &payload,
        );
        let signature = identity.sign(DOMAIN_BLOB, &body)?;
        Ok(Self {
            suite: identity.suite(),
            origin: identity.node_id(),
            seq,
            timestamp,
            payload,
            signature,
        })
    }

    /// Verify this blob against the origin's public identity, then
    /// freshness.
    ///
    /// The signature is checked first: a forged blob always reports
    /// [`IdentError::InvalidSignature`], a valid blob that is not newer
    /// than `latest_seq` reports [`IdentError::StaleBlob`] - stale and
    /// forged are distinguishable. Pass `latest_seq = None` to skip
    /// the freshness check (e.g. when syncing history).
    pub fn verify(
        &self,
        origin: &PublicIdentity,
        latest_seq: Option<u64>,
    ) -> Result<(), IdentError> {
        let body = body_bytes(
            self.suite,
            self.origin,
            self.seq,
            self.timestamp,
            &self.payload,
        );
        origin.verify(DOMAIN_BLOB, &body, &self.signature)?;
        if let Some(latest) = latest_seq {
            if self.seq <= latest {
                return Err(IdentError::StaleBlob);
            }
        }
        Ok(())
    }

    /// The canonical encoding: body bytes followed by the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = body_bytes(
            self.suite,
            self.origin,
            self.seq,
            self.timestamp,
            &self.payload,
        );
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Decode an encoded blob. Every field is bounds-checked before it
    /// is read: truncated, over-long or trailing bytes are
    /// [`IdentError::MalformedBlob`], an unknown suite byte is
    /// [`IdentError::UnknownSuite`]. Never panics on any input.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentError> {
        if bytes.len() < HEADER_LEN + SIG_LEN {
            return Err(IdentError::MalformedBlob);
        }
        let suite = SuiteId::try_from(bytes[0])?;

        let mut origin = [0u8; 16];
        origin.copy_from_slice(&bytes[1..17]);
        let seq = u64::from_be_bytes(
            bytes[17..25]
                .try_into()
                .map_err(|_| IdentError::MalformedBlob)?,
        );
        let timestamp = u64::from_be_bytes(
            bytes[25..33]
                .try_into()
                .map_err(|_| IdentError::MalformedBlob)?,
        );
        let payload_len = u16::from_be_bytes(
            bytes[33..35]
                .try_into()
                .map_err(|_| IdentError::MalformedBlob)?,
        ) as usize;

        // Exact length catches both a truncated payload and trailing bytes.
        if bytes.len() != HEADER_LEN + payload_len + SIG_LEN {
            return Err(IdentError::MalformedBlob);
        }

        let payload = bytes[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[HEADER_LEN + payload_len..]);
        Ok(Self {
            suite,
            origin: NodeId::from_bytes(origin),
            seq,
            timestamp,
            payload,
            signature: Signature::from_bytes(sig),
        })
    }

    /// The suite this blob was signed under (always v1 today).
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The publishing node's `NodeId`.
    #[must_use]
    pub fn origin(&self) -> NodeId {
        self.origin
    }

    /// The monotonic sequence number; higher wins ("latest-wins").
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The caller-owned timestamp (seconds or milliseconds - the
    /// caller's choice, this crate never reads a clock).
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// The opaque payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The signature over the canonical body.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Canonical body of a blob: `suite ‖ origin ‖ seq ‖ timestamp ‖
/// payload_len ‖ payload` (ADR-0001 rules: big-endian fixed-width
/// integers, `u16`-length-prefixed byte string).
fn body_bytes(suite: SuiteId, origin: NodeId, seq: u64, timestamp: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(suite.byte());
    out.extend_from_slice(origin.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
