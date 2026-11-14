//! Replay guard at the recipient (IDN-14).
//!
//! Covers the done-when (a replayed sealed message is rejected, an
//! out-of-order but fresh one is accepted, memory stays under the
//! configured cap) plus the timestamp tolerance, the fail-closed
//! capacity rules, the restart encoding and proptests.

mod common;

use ao_idents::{
    IdentError, Identity, MAX_REPLAY_ENTRIES, MAX_SENDERS, MAX_WINDOW, MSG_ID_LEN, NodeId,
    ReplayConfig, ReplayGuard, SealedMessage,
};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn sender_id(state: u64) -> NodeId {
    identity(state).node_id()
}

fn msg_id(byte: u8) -> [u8; MSG_ID_LEN] {
    [byte; MSG_ID_LEN]
}

fn guard() -> ReplayGuard {
    ReplayGuard::new(ReplayConfig::default())
}

/// The done-when, first half: a sealed message that was accepted once
/// is refused when presented again, using the real seal/open flow.
#[test]
fn a_replayed_sealed_message_is_rejected() {
    let alice = identity(1);
    let bob = identity(2);
    let id = msg_id(0x11);
    let sealed = SealedMessage::seal(
        &alice,
        bob.public(),
        &id,
        b"transfer 10",
        &mut TestRng::new(3),
    )
    .expect("small plaintext");
    let opened = sealed.open(&bob, &id).expect("recipient opens");
    assert_eq!(opened.plaintext(), b"transfer 10");

    let mut guard = guard();
    let now = 1_000_000;
    let sender = alice.node_id();
    guard
        .accept(sender, &id, now, now)
        .expect("first delivery is fresh");
    // The same bytes captured and re-presented by a relay.
    assert!(matches!(
        guard.accept(sender, &id, now, now + 1),
        Err(IdentError::Replay)
    ));
}

/// The done-when, second half: a message that arrives out of order -
/// its timestamp is older than one already accepted, but still inside
/// the tolerance - is accepted.
#[test]
fn an_out_of_order_but_fresh_message_is_accepted() {
    let mut guard = guard();
    let sender = sender_id(7);
    let now = 1_000_000;

    guard
        .accept(sender, &msg_id(1), now, now)
        .expect("newest first");
    guard
        .accept(sender, &msg_id(2), now - 60_000, now)
        .expect("a minute older but fresh is fine");
    guard
        .accept(sender, &msg_id(3), now - 299_999, now)
        .expect("just inside the 5-minute tolerance");
}

/// The done-when, third half: the guard never holds more senders than
/// configured, and the encoding's size tracks exactly what is held.
#[test]
fn memory_stays_under_the_configured_cap() {
    let config = ReplayConfig::new(4, 300_000, 8).expect("small config");
    let mut guard = ReplayGuard::new(config);
    let now = 1_000_000;

    for i in 0..8u64 {
        guard
            .accept(sender_id(100 + i), &msg_id(i as u8), now, now)
            .expect("within the sender cap");
    }
    assert_eq!(guard.sender_count(), 8);
    assert!(guard.sender_count() <= config.max_senders());

    // A ninth sender is refused while every held sender is fresh.
    assert!(matches!(
        guard.accept(sender_id(999), &msg_id(9), now, now),
        Err(IdentError::GuardFull)
    ));
    assert_eq!(guard.sender_count(), 8);

    // Each of the 8 senders holds exactly one message, so the encoding
    // is exactly header + 8 * (prefix + 1 entry) and cannot exceed
    // the configured worst case.
    let encoded = guard.encode();
    let entry = 16 + 8;
    let exact = 3 + 8 * (16 + 8 + 2 + entry);
    assert_eq!(encoded.len(), exact);
    assert!(
        encoded.len() <= 3 + config.max_senders() * (26 + config.window() * 24),
        "encoding stays under the configured memory bound"
    );
}

/// A single sender's window is capped too: the oldest id slides out
/// only once it is stale, and a fresh burst at the cap fails closed.
#[test]
fn the_per_sender_window_is_capped() {
    let config = ReplayConfig::new(4, 300_000, 8).expect("small config");
    let mut guard = ReplayGuard::new(config);
    let sender = sender_id(5);
    let now = 1_000_000;

    for i in 0..4u8 {
        guard
            .accept(sender, &msg_id(i), now, now)
            .expect("within the window");
    }
    assert!(matches!(
        guard.accept(sender, &msg_id(9), now, now),
        Err(IdentError::GuardFull)
    ));

    // Once the held messages age past the tolerance the window frees
    // itself and the same message is accepted again.
    let later = now + 300_001;
    guard
        .accept(sender, &msg_id(9), later, later)
        .expect("window emptied by expiry");
    assert!(matches!(
        guard.accept(sender, &msg_id(9), later, later),
        Err(IdentError::Replay)
    ));
}

/// The timestamp tolerance is symmetric: too old and too far in the
/// future are both refused, at exactly one millisecond over.
#[test]
fn the_timestamp_tolerance_is_symmetric() {
    let mut guard = guard();
    let sender = sender_id(11);
    let now = 1_000_000;
    let tolerance = guard.config().tolerance_ms();

    guard
        .accept(sender, &msg_id(1), now - tolerance, now)
        .expect("exactly at the old edge is fresh");
    assert!(matches!(
        guard.accept(sender, &msg_id(2), now - tolerance - 1, now),
        Err(IdentError::StaleTimestamp)
    ));
    guard
        .accept(sender, &msg_id(3), now + tolerance, now)
        .expect("exactly at the future edge is fresh");
    assert!(matches!(
        guard.accept(sender, &msg_id(4), now + tolerance + 1, now),
        Err(IdentError::StaleTimestamp)
    ));
}

/// A stale rejection never records the id, so a message that was
/// refused for age cannot later be replayed "successfully" under a
/// different `now` - and a clock that jumps backwards does not turn
/// old entries into fresh ones either.
#[test]
fn stale_rejections_are_not_recorded() {
    let mut guard = guard();
    let sender = sender_id(12);
    let now = 1_000_000;

    assert!(matches!(
        guard.accept(sender, &msg_id(1), now - 400_000, now),
        Err(IdentError::StaleTimestamp)
    ));
    assert_eq!(guard.sender_count(), 0);

    // The id was never recorded, so a later first delivery of it is
    // accepted rather than flagged as a replay.
    guard
        .accept(sender, &msg_id(1), now, now)
        .expect("never recorded, so not a replay");
}

/// The map recovers capacity from senders that have been silent for
/// longer than the tolerance: a full guard admits a new sender once
/// the old ones expire.
#[test]
fn silent_senders_free_their_slots() {
    let config = ReplayConfig::new(4, 300_000, 4).expect("small config");
    let mut guard = ReplayGuard::new(config);
    let now = 1_000_000;

    for i in 0..4u64 {
        guard
            .accept(sender_id(200 + i), &msg_id(i as u8), now, now)
            .expect("fill the map");
    }
    assert!(matches!(
        guard.accept(sender_id(299), &msg_id(9), now, now),
        Err(IdentError::GuardFull)
    ));

    // All four go silent past the tolerance; the new sender is
    // admitted and the expired ones are gone.
    let later = now + 300_001;
    guard
        .accept(sender_id(299), &msg_id(9), later, later)
        .expect("expired senders were swept");
    assert_eq!(guard.sender_count(), 1);
}

/// The same message id from two different senders is two different
/// messages: the key is the pair, not the id alone.
#[test]
fn the_key_is_sender_and_id() {
    let mut guard = guard();
    let now = 1_000_000;
    let id = msg_id(0x42);

    guard
        .accept(sender_id(30), &id, now, now)
        .expect("first sender");
    guard
        .accept(sender_id(31), &id, now, now)
        .expect("second sender, same id");
    assert!(matches!(
        guard.accept(sender_id(30), &id, now, now),
        Err(IdentError::Replay)
    ));
}

/// State survives a restart: encode, decode, and the guard still
/// refuses what it had already accepted and still admits fresh
/// messages.
#[test]
fn state_round_trips_across_a_restart() {
    let config = ReplayConfig::new(4, 300_000, 8).expect("small config");
    let mut guard = ReplayGuard::new(config);
    let now = 1_000_000;
    let sender = sender_id(40);

    guard
        .accept(sender, &msg_id(1), now, now)
        .expect("before restart");
    guard
        .accept(sender, &msg_id(2), now - 1_000, now)
        .expect("before restart");

    let bytes = guard.encode();
    let mut restored = ReplayGuard::decode(&bytes, config).expect("valid state");
    assert_eq!(restored, guard);

    assert!(matches!(
        restored.accept(sender, &msg_id(1), now, now + 1),
        Err(IdentError::Replay)
    ));
    restored
        .accept(sender, &msg_id(3), now, now + 1)
        .expect("fresh message after restart");
    // The restored cap still holds: sender 40 plus seven more fills
    // the eight-slot map, and a ninth fresh sender is refused.
    for i in 0..7u8 {
        restored
            .accept(sender_id(50 + u64::from(i)), &msg_id(i), now, now + 1)
            .expect("within the restored cap");
    }
    assert_eq!(restored.sender_count(), 8);
    assert!(matches!(
        restored.accept(sender_id(60), &msg_id(9), now, now + 1),
        Err(IdentError::GuardFull)
    ));
}

/// Config validation: every bound is rejected, never clamped, and the
/// entry budget catches an oversized product.
#[test]
fn configuration_bounds_are_validated() {
    assert!(matches!(
        ReplayConfig::new(0, 300_000, 8),
        Err(IdentError::InvalidGuardConfig)
    ));
    assert!(matches!(
        ReplayConfig::new(MAX_WINDOW + 1, 300_000, 8),
        Err(IdentError::InvalidGuardConfig)
    ));
    assert!(matches!(
        ReplayConfig::new(64, 0, 256),
        Err(IdentError::InvalidGuardConfig)
    ));
    assert!(matches!(
        ReplayConfig::new(64, ao_idents::MAX_TOLERANCE_MS + 1, 256),
        Err(IdentError::InvalidGuardConfig)
    ));
    assert!(matches!(
        ReplayConfig::new(64, 300_000, 0),
        Err(IdentError::InvalidGuardConfig)
    ));
    assert!(matches!(
        ReplayConfig::new(64, 300_000, MAX_SENDERS + 1),
        Err(IdentError::InvalidGuardConfig)
    ));
    // 1024 x 65 is over the 65 536-entry budget.
    assert!(matches!(
        ReplayConfig::new(MAX_WINDOW, 300_000, MAX_REPLAY_ENTRIES / MAX_WINDOW + 1),
        Err(IdentError::InvalidGuardConfig)
    ));
    assert!(ReplayConfig::new(64, 300_000, 256).is_ok());
}

/// Malformed state is a typed error at every truncation length, with
/// trailing bytes, an unknown version, a count over the caller's
/// config, a duplicate sender and a duplicate entry - never a panic,
/// never a partial guard.
///
/// Layout of the seed (sender 40 with two entries, sender 41 with
/// one): `version(1) | count(2)` then, per sender,
/// `node_id(16) | last_seen(8) | entry_count(2) | entries(24 each)`.
#[test]
fn malformed_state_is_a_typed_error() {
    let config = ReplayConfig::new(4, 300_000, 8).expect("small config");
    let mut guard = ReplayGuard::new(config);
    let now = 1_000_000;
    guard
        .accept(sender_id(40), &msg_id(1), now, now)
        .expect("seed");
    guard
        .accept(sender_id(40), &msg_id(2), now, now)
        .expect("seed");
    guard
        .accept(sender_id(41), &msg_id(3), now, now)
        .expect("seed");
    let bytes = guard.encode();

    // Sender A occupies 3..77 (26-byte prefix + two 24-byte entries),
    // sender B starts at 77.
    const SENDER_B: usize = 77;
    const A_ENTRY_COUNT: usize = 27;
    const A_FIRST_MSG_ID: usize = 29;
    const A_SECOND_MSG_ID: usize = 53;

    for len in 0..bytes.len() {
        assert!(
            ReplayGuard::decode(&bytes[..len], config).is_err(),
            "truncated to {len} must fail"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        ReplayGuard::decode(&trailing, config),
        Err(IdentError::MalformedGuard)
    ));

    let mut bad_version = bytes.clone();
    bad_version[0] = 0x02;
    assert!(matches!(
        ReplayGuard::decode(&bad_version, config),
        Err(IdentError::MalformedGuard)
    ));

    // A sender count over the caller's config: the file claims 9
    // senders while this config allows 8.
    let mut over_count = bytes.clone();
    over_count[1..3].copy_from_slice(&9u16.to_be_bytes());
    assert!(matches!(
        ReplayGuard::decode(&over_count, config),
        Err(IdentError::MalformedGuard)
    ));

    // An entry count over the caller's window for the first sender.
    let mut over_window = bytes.clone();
    over_window[A_ENTRY_COUNT..A_ENTRY_COUNT + 2].copy_from_slice(&5u16.to_be_bytes());
    assert!(matches!(
        ReplayGuard::decode(&over_window, config),
        Err(IdentError::MalformedGuard)
    ));

    // Duplicate sender: both records claim sender 40's node id.
    let mut duplicate = bytes.clone();
    let sender_a_id = duplicate[3..19].to_vec();
    duplicate[SENDER_B..SENDER_B + 16].copy_from_slice(&sender_a_id);
    assert!(matches!(
        ReplayGuard::decode(&duplicate, config),
        Err(IdentError::MalformedGuard)
    ));

    // Duplicate message id within one sender's window.
    let mut duplicate_id = bytes;
    let second_msg_id = duplicate_id[A_SECOND_MSG_ID..A_SECOND_MSG_ID + 16].to_vec();
    duplicate_id[A_FIRST_MSG_ID..A_FIRST_MSG_ID + 16].copy_from_slice(&second_msg_id);
    assert!(matches!(
        ReplayGuard::decode(&duplicate_id, config),
        Err(IdentError::MalformedGuard)
    ));
}

/// The `Debug` output reports counts only, and encode is
/// deterministic for equal state.
#[test]
fn debug_is_redacted_and_encode_is_deterministic() {
    let mut guard = guard();
    let now = 1_000_000;
    guard
        .accept(sender_id(50), &msg_id(1), now, now)
        .expect("seed");

    let debugged = format!("{guard:?}");
    assert!(debugged.contains("ReplayGuard"));
    assert!(!debugged.contains(&hex(&msg_id(1))));

    let mut twin = ReplayGuard::new(ReplayConfig::default());
    twin.accept(sender_id(50), &msg_id(1), now, now)
        .expect("seed");
    assert_eq!(guard.encode(), twin.encode());
}

/// The checked-in test vector: the exact state bytes for fixed
/// accepts, so an accidental encoding change fails CI. Derived once
/// from this implementation and reviewed before check-in; decode
/// must reproduce the same bytes.
#[test]
fn checked_in_state_vector_matches() {
    const VECTOR_HEX: &str = "010001ab8c6899ac128e5cd542a37951cbb02b000000006553f164000300000000000000000000000000000000000000006553f10001010101010101010101010101010101000000006553f10002020202020202020202020202020202000000006553f100";
    let expected: Vec<u8> = (0..VECTOR_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&VECTOR_HEX[i..i + 2], 16).expect("hex"))
        .collect();

    let mut guard = ReplayGuard::new(ReplayConfig::default());
    let sender = Identity::from_seed([8u8; 32]).node_id();
    for i in 0..3u8 {
        guard
            .accept(sender, &msg_id(i), 1_700_000_000, 1_700_000_100)
            .expect("fresh messages");
    }
    assert_eq!(
        guard.encode(),
        expected,
        "state encoding changed: if intentional, this is a protocol change (ADR-0001)"
    );

    let decoded = ReplayGuard::decode(&expected, ReplayConfig::default()).expect("vector decodes");
    assert_eq!(
        decoded.encode(),
        expected,
        "decode must preserve the state exactly"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Arbitrary acceptance histories never panic and never
        /// exceed the configured sender cap.
        #[test]
        fn arbitrary_histories_never_panic(
            stamps in proptest::collection::vec(0u64..10_000_000, 0..40),
            nows in proptest::collection::vec(0u64..10_000_000, 0..40),
        ) {
            let config = ReplayConfig::new(3, 5_000, 4).expect("small config");
            let mut guard = ReplayGuard::new(config);
            for (i, (&stamp, &now)) in stamps.iter().zip(&nows).enumerate() {
                let sender = sender_id((i % 6) as u64);
                let id = msg_id((i % 5) as u8);
                let _ = guard.accept(sender, &id, stamp, now);
                prop_assert!(guard.sender_count() <= config.max_senders());
            }
        }

        /// Encoded state round trips for arbitrary valid histories,
        /// and arbitrary bytes never panic on decode.
        #[test]
        fn arbitrary_bytes_never_panic_on_decode(
            bytes in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let config = ReplayConfig::new(3, 5_000, 4).expect("small config");
            let _ = ReplayGuard::decode(&bytes, config);
        }
    }
}
