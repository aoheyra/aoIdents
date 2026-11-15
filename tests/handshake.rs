//! The Noise XX hop handshake (IDN-13).
//!
//! Covers the done-when: two in-memory peers complete the handshake,
//! an impostor card fails, and the handshake messages stay under about
//! 200 bytes each. Plus the sans-IO properties: injected-RNG
//! reproducibility, typed errors for every wrong-turn and malformed
//! input, and the transport that falls out of the finished handshake.

mod common;

use ao_idents::{HopHandshake, IdentError, Identity, IdentityCard};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn card(id: &Identity, name: &[u8]) -> IdentityCard {
    id.card(name, 1_700_000_000)
        .expect("name fits the card limit")
}

/// Exchange the three XX messages in order, returning them.
fn drive(initiator: &mut HopHandshake, responder: &mut HopHandshake) -> [Vec<u8>; 3] {
    let msg1 = initiator.write_message().expect("initiator writes first");
    responder.read_message(&msg1).expect("responder reads msg1");

    let msg2 = responder.write_message().expect("responder replies");
    initiator.read_message(&msg2).expect("initiator reads msg2");

    let msg3 = initiator.write_message().expect("initiator closes");
    responder.read_message(&msg3).expect("responder reads msg3");

    [msg1, msg2, msg3]
}

/// The done-when, happy path: both in-memory peers finish the
/// handshake, notice it, and derive transports that open each other's
/// frames in both directions.
#[test]
fn two_in_memory_peers_complete_the_handshake() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    let mut initiator =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let mut responder =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");

    assert!(!initiator.is_complete(), "nothing exchanged yet");
    assert!(!responder.is_complete(), "nothing exchanged yet");

    drive(&mut initiator, &mut responder);

    assert!(initiator.is_complete(), "initiator wrote the third message");
    assert!(responder.is_complete(), "responder read the third message");

    let mut alice_transport = initiator.into_transport().expect("genuine card");
    let mut bob_transport = responder.into_transport().expect("genuine card");

    let frame = alice_transport.encrypt_msg(b"hop frame").expect("seals");
    assert_eq!(
        bob_transport.decrypt_msg(&frame).expect("opens"),
        b"hop frame",
        "initiator to responder"
    );

    let reply = bob_transport.encrypt_msg(b"reply").expect("seals");
    assert_eq!(
        alice_transport.decrypt_msg(&reply).expect("opens"),
        b"reply",
        "responder to initiator"
    );
}

/// The done-when, size bound: with this suite the three messages are
/// 32, 80 and 64 bytes - each under the ~200-byte fragment-friendly
/// bound the issue asks for. The exact figures pin the suite; a
/// change to the Noise parameters must fail here.
#[test]
fn handshake_messages_fit_one_fragment() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    let mut initiator =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let mut responder =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");

    let [msg1, msg2, msg3] = drive(&mut initiator, &mut responder);

    assert_eq!(msg1.len(), 32, "msg1 is the initiator's e");
    assert_eq!(msg2.len(), 96, "msg2 is e + encrypted s + payload tag");
    assert_eq!(msg3.len(), 64, "msg3 is encrypted s + payload tag");
    for (i, msg) in [&msg1, &msg2, &msg3].into_iter().enumerate() {
        assert!(
            msg.len() <= 200,
            "message {} is {} bytes, over the fragment bound",
            i + 1,
            msg.len()
        );
    }
}

/// The done-when, impostor: whoever presents a card that does not own
/// the static key proven in the handshake is rejected on both sides,
/// before any transport key leaves the handshake.
#[test]
fn an_impostor_card_fails_on_both_sides() {
    let alice = identity(1);
    let bob = identity(2);
    let mallory = identity(3);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    // Alice pins Bob's card; Mallory answers with her own key.
    let mut alice_hs =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let mut mallory_hs =
        HopHandshake::responder(&mallory, &alice_card, &mut TestRng::new(11)).expect("builds");
    drive(&mut alice_hs, &mut mallory_hs);
    assert!(
        matches!(alice_hs.into_transport(), Err(IdentError::ImpostorCard)),
        "the honest side must refuse the impostor"
    );
    // The impostor's own check passes - she pinned Alice's real card -
    // so only the honest side detects the mismatch.
    mallory_hs.into_transport().expect("attacker sees no error");

    // Mirrored: Mallory pins Bob's card while initiating; Bob pinned
    // Alice's card out of band and must refuse the third party.
    let mut mallory_hs =
        HopHandshake::initiator(&mallory, &bob_card, &mut TestRng::new(12)).expect("builds");
    let mut bob_hs =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(13)).expect("builds");
    drive(&mut mallory_hs, &mut bob_hs);
    assert!(
        matches!(bob_hs.into_transport(), Err(IdentError::ImpostorCard)),
        "the responder must refuse the impostor"
    );
}

/// A card whose self-signature does not verify is refused when the
/// handshake is built - before a single byte is exchanged.
#[test]
fn a_tampered_card_is_rejected_before_any_message() {
    let alice = identity(1);
    let bob = identity(2);
    let bob_card = card(&bob, b"bob");

    let mut encoded = bob_card.encode();
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let tampered = IdentityCard::decode(&encoded).expect("structure is intact");

    let err = HopHandshake::initiator(&alice, &tampered, &mut TestRng::new(10))
        .expect_err("forged signature");
    assert!(
        matches!(err, IdentError::InvalidSignature),
        "wrong error: {err}"
    );
}

/// Finishing early is typed, not a panic.
#[test]
fn transport_before_completion_is_a_typed_error() {
    let alice = identity(1);
    let bob = identity(2);
    let bob_card = card(&bob, b"bob");

    let handshake =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    assert!(
        matches!(
            handshake.into_transport(),
            Err(IdentError::HandshakeNotComplete)
        ),
        "no transport before the third message"
    );
}

/// The XX pattern fixes who writes when: acting out of turn is a
/// typed error from snow, surfaced with context.
#[test]
fn writing_out_of_turn_is_a_typed_error() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    // The responder must read before it writes.
    let mut responder =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
    let err = responder.write_message().expect_err("read comes first");
    assert!(
        matches!(err, IdentError::HandshakeFailed(_)),
        "wrong error: {err}"
    );

    // The initiator must write before it reads.
    let mut initiator =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let err = initiator
        .read_message(&[0_u8; 32])
        .expect_err("write comes first");
    assert!(
        matches!(err, IdentError::HandshakeFailed(_)),
        "wrong error: {err}"
    );
}

/// Every malformed, truncated or piggybacking input is a typed error
/// with no panic: empty reads, short reads, a message1 that carries a
/// payload the handshake does not accept, and random bytes at the
/// message-2 position where the tag must verify.
#[test]
fn garbage_truncated_and_extra_messages_are_typed_errors() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    let mut responder =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");

    for garbage in [&[][..], &[0_u8; 10][..], &[0_u8; 31][..]] {
        let err = responder.read_message(garbage).expect_err("too short");
        assert!(
            matches!(err, IdentError::HandshakeFailed(_)),
            "wrong error for {} bytes: {err}",
            garbage.len()
        );
    }

    // A valid message1 that appends a payload: the handshake carries
    // none, so the extra byte is refused. The failed read restores
    // the state, so the responder is still waiting for message 1.
    let mut initiator =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let msg1 = initiator.write_message().expect("msg1");
    let mut with_payload = msg1.clone();
    with_payload.push(0xAA);
    let err = responder
        .read_message(&with_payload)
        .expect_err("no payloads");
    assert!(
        matches!(err, IdentError::HandshakeFailed(_)),
        "wrong error: {err}"
    );

    // The unmodified message1 advances the responder to the
    // message-2 position, where 80 zeros parse structurally - the
    // right lengths for e and the encrypted static - but the
    // static's authentication tag fails.
    responder.read_message(&msg1).expect("valid msg1");
    let err = responder
        .read_message(&[0_u8; 80])
        .expect_err("tag must fail");
    assert!(
        matches!(err, IdentError::HandshakeFailed(_)),
        "wrong error: {err}"
    );
}

/// The ephemeral key comes from the caller's RNG, so two runs over the
/// same seed produce byte-identical handshakes - the sans-IO property
/// a seeded simulator depends on.
#[test]
fn the_handshake_is_reproducible_from_the_rng() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    let run = || {
        let mut initiator =
            HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
        let mut responder =
            HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
        drive(&mut initiator, &mut responder)
    };

    assert_eq!(run(), run(), "same seeds, same bytes");
}

/// A completed transport seals and opens arbitrary frames, and any
/// single flipped byte is refused - nothing but the exact frame opens.
#[test]
fn transport_round_trip_and_tamper_detection() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    let mut initiator =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let mut responder =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
    drive(&mut initiator, &mut responder);

    let mut sender = initiator.into_transport().expect("genuine");
    let mut receiver = responder.into_transport().expect("genuine");

    let frame = sender.encrypt_msg(b"frame").expect("seals");
    let mut tampered = frame.clone();
    tampered[0] ^= 0x01;
    let err = receiver.decrypt_msg(&tampered).expect_err("tag must fail");
    assert!(matches!(err, IdentError::OpenFailed), "wrong error: {err}");

    let err = sender.decrypt_msg(&frame).expect_err("wrong direction");
    assert!(matches!(err, IdentError::OpenFailed), "wrong error: {err}");

    assert_eq!(
        receiver.decrypt_msg(&frame).expect("untouched frame opens"),
        b"frame"
    );
}

/// Frames past the Noise message limit are refused with a typed error
/// before anything is allocated, on both sides of the transport.
#[test]
fn oversize_transport_frames_are_refused_before_allocation() {
    let alice = identity(1);
    let bob = identity(2);
    let alice_card = card(&alice, b"alice");
    let bob_card = card(&bob, b"bob");

    let mut initiator =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let mut responder =
        HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
    drive(&mut initiator, &mut responder);

    let mut transport = initiator.into_transport().expect("genuine");

    // 65519 bytes of plaintext plus the 16-byte tag is exactly the
    // 65535-byte Noise limit and must still seal...
    let largest = vec![0_u8; 65535 - 16];
    transport.encrypt_msg(&largest).expect("at the limit");

    // ...one byte more is refused before the buffer is allocated.
    let err = transport
        .encrypt_msg(&vec![0_u8; 65535 - 15])
        .expect_err("over the limit");
    assert!(
        matches!(err, IdentError::PayloadTooLarge),
        "wrong error: {err}"
    );

    // The same bound applies to hostile inbound frames.
    let err = transport
        .decrypt_msg(&vec![0_u8; 65536])
        .expect_err("over the limit");
    assert!(
        matches!(err, IdentError::PayloadTooLarge),
        "wrong error: {err}"
    );
}

/// Debug prints progress, never key material.
#[test]
fn debug_shows_progress_without_key_material() {
    let alice = identity(1);
    let bob = identity(2);
    let bob_card = card(&bob, b"bob");

    let handshake =
        HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
    let printed = format!("{handshake:?}");
    assert!(
        printed.contains("HopHandshake"),
        "names the type: {printed}"
    );
    assert!(
        printed.contains("complete: false"),
        "shows progress: {printed}"
    );
    assert!(!printed.contains("0x"), "no key bytes: {printed}");
}

mod proptests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{Config, FileFailurePersistence};

    fn proptest_config_for_runtime(cases: u32) -> Config {
        let default = Config::default();
        // Regression files need the process CWD, which Miri's isolation forbids.
        // Keep file persistence natively, skip it under Miri.
        Config {
            failure_persistence: if cfg!(miri) {
                None
            } else {
                Some(Box::new(FileFailurePersistence::default()))
            },
            // Keep Miri CI runtime bounded while still exercising each property.
            cases: if cfg!(miri) { cases.min(8) } else { cases },
            ..default
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(64))]

        /// Arbitrary bytes at any position never panic: every input is
        /// either consumed as a well-formed message or refused with a
        /// typed error.
        #[test]
        fn read_message_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let alice = identity(1);
            let bob = identity(2);
            let alice_card = card(&alice, b"alice");
            let mut responder =
                HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
            let _ = responder.read_message(&bytes);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(16))]

        /// Any plaintext round-trips through a fresh transport pair,
        /// twice: the frames differ by nonce while both open.
        #[test]
        fn transport_round_trips_arbitrary_plaintext(
            plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let alice = identity(1);
            let bob = identity(2);
            let alice_card = card(&alice, b"alice");
            let bob_card = card(&bob, b"bob");

            let mut initiator =
                HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
            let mut responder =
                HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
            drive(&mut initiator, &mut responder);

            let mut sender = initiator.into_transport().expect("genuine");
            let mut receiver = responder.into_transport().expect("genuine");

            let frame = sender.encrypt_msg(&plaintext).expect("seals");
            prop_assert_eq!(
                receiver.decrypt_msg(&frame).expect("opens"),
                plaintext.clone()
            );

            // The frame is bound to its position: replaying it after
            // another frame opened fails the nonce, not just the tag.
            let again = sender.encrypt_msg(&plaintext).expect("second seal");
            prop_assert_eq!(receiver.decrypt_msg(&again).expect("second open"), plaintext);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(32))]

        /// No flipped byte of a frame ever opens.
        #[test]
        fn tampered_frames_never_open(
            plaintext in proptest::collection::vec(any::<u8>(), 0..64),
            index in any::<usize>(),
        ) {
            let alice = identity(1);
            let bob = identity(2);
            let alice_card = card(&alice, b"alice");
            let bob_card = card(&bob, b"bob");

            let mut initiator =
                HopHandshake::initiator(&alice, &bob_card, &mut TestRng::new(10)).expect("builds");
            let mut responder =
                HopHandshake::responder(&bob, &alice_card, &mut TestRng::new(11)).expect("builds");
            drive(&mut initiator, &mut responder);

            let mut sender = initiator.into_transport().expect("genuine");
            let mut receiver = responder.into_transport().expect("genuine");

            let frame = sender.encrypt_msg(&plaintext).expect("seals");
            let mut tampered = frame.clone();
            let at = index % tampered.len();
            tampered[at] ^= 0x01;
            prop_assert!(
                matches!(receiver.decrypt_msg(&tampered), Err(IdentError::OpenFailed)),
                "a flipped byte at {at} must not open"
            );
        }
    }
}
