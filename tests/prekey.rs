//! Signed prekey bundles and X3DH initial agreement (IDN-15).
//!
//! Covers the done-when: a message to an offline recipient survives
//! compromise of the recipient's long-term key after prekey
//! deletion. Plus the happy path, one-time slot burning, tampered
//! envelopes, forged bundles, wrong recipients, both decode bounds
//! and the payload limit.

mod common;

use ao_idents::{
    IdentError, Identity, MAX_ONE_TIME_PREKEYS, PrekeyBundle, PrekeySealedMessage, PrekeySecrets,
};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

/// A bundle plus its secrets for `state`'s identity, four one-time
/// slots.
fn bundle_for(state: u64) -> (PrekeyBundle, PrekeySecrets) {
    PrekeyBundle::generate(&identity(state), 4, &mut TestRng::new(100 + state))
        .expect("four slots is within the cap")
}

/// The sealed message's header: suite(1) + sender agreement key(32)
/// + ephemeral key(32) + one-time index(1) + nonce(24) + length(2).
const MSG_HEADER_LEN: usize = 92;

/// A bundle verifies, round-trips through its encoding, and its
/// derived id and keys are the identity it was generated from.
#[test]
fn bundle_round_trips_and_verifies() {
    let bob = identity(3);
    let (bundle, _secrets) = bundle_for(3);
    bundle.verify().expect("self-signed at generation");

    assert_eq!(bundle.node_id(), bob.node_id());
    assert_eq!(bundle.signing_pk(), bob.public().signing_pk());
    assert_eq!(bundle.agreement_pk(), bob.public().agreement_pk());
    assert_eq!(bundle.one_time_count(), 4);

    let encoded = bundle.encode();
    // prefix (suite + three keys + count) + four keys + signature.
    assert_eq!(encoded.len(), 98 + 4 * 32 + 64, "fixed layout");
    let decoded = PrekeyBundle::decode(&encoded).expect("round trip");
    assert_eq!(decoded, bundle);
    decoded.verify().expect("survives the encoding");
}

/// The happy path: the message waits while the recipient is offline,
/// opens with the bundle's secrets, authenticates the sender, and
/// burns the one-time slot it used - reopening the very same bytes
/// is then refused.
#[test]
fn seal_and_open_deliver_to_an_offline_recipient() {
    let alice = identity(1);
    let (bundle, mut secrets) = bundle_for(3);

    let message = PrekeySealedMessage::seal(
        &alice,
        &bundle,
        b"queued while offline",
        &mut TestRng::new(11),
    )
    .expect("seals");
    assert!(message.one_time_index() < bundle.one_time_count() as u8);

    let opened = message.open(&identity(3), &mut secrets).expect("opens");
    assert_eq!(opened.plaintext(), b"queued while offline");
    assert_eq!(opened.sender().signing_pk(), alice.public().signing_pk());
    assert_eq!(
        opened.sender().agreement_pk(),
        alice.public().agreement_pk()
    );

    // Opening consumed the slot: the same ciphertext cannot be
    // presented again against the same secrets.
    let err = message
        .open(&identity(3), &mut secrets)
        .expect_err("slot burned");
    assert!(matches!(err, IdentError::PrekeyUnavailable), "wrong: {err}");
}

/// The done-when: the message is sealed to the offline recipient's
/// published bundle; the recipient opens it and the prekeys it used
/// are deleted; then the recipient's long-term key is compromised -
/// the attacker holds the whole Identity, seed included, plus every
/// public byte (message and bundle). Without the prekey secrets
/// three of the four DH shares are unreachable, so the attacker
/// cannot rebuild the session key, and the recipient's opened copy
/// is untouched.
#[test]
fn a_message_survives_long_term_key_compromise_after_prekey_deletion() {
    let bob = identity(3);
    let (bundle, mut secrets) = PrekeyBundle::generate(&bob, 4, &mut TestRng::new(10))
        .expect("four slots is within the cap");
    let alice = identity(1);

    // Bob is offline; the message waits as ciphertext.
    let message = PrekeySealedMessage::seal(
        &alice,
        &bundle,
        b"for bob's eyes only",
        &mut TestRng::new(11),
    )
    .expect("seals");

    // Bob comes online, opens it, and the prekeys he used are gone:
    // the one-time slot was burned by the open itself and the signed
    // prekey is rotated away.
    let opened = message.open(&bob, &mut secrets).expect("opens");
    assert_eq!(opened.plaintext(), b"for bob's eyes only");
    secrets.delete_signed_prekey();

    // Compromise: this same Identity - the long-term key, seed and
    // all - is now in the attacker's hands, together with the public
    // message and bundle. It is not enough.
    let attacker_holds = &bob;
    let err = message
        .open(attacker_holds, &mut secrets)
        .expect_err("prekeys are deleted");
    assert!(
        matches!(err, IdentError::PrekeyUnavailable),
        "wrong error: {err}"
    );

    // The recipient's opened copy survives the compromise unchanged.
    assert_eq!(opened.plaintext(), b"for bob's eyes only");
}

/// The signed prekey is load-bearing on its own: with every
/// one-time slot still present, deleting it alone stops opens.
#[test]
fn a_deleted_signed_prekey_stops_opens() {
    let alice = identity(1);
    let (bundle, mut secrets) = bundle_for(3);
    let message =
        PrekeySealedMessage::seal(&alice, &bundle, b"before rotation", &mut TestRng::new(11))
            .expect("seals");

    secrets.delete_signed_prekey();
    let err = message
        .open(&identity(3), &mut secrets)
        .expect_err("rotated away");
    assert!(matches!(err, IdentError::PrekeyUnavailable), "wrong: {err}");

    // Idempotent: deleting again changes nothing.
    secrets.delete_signed_prekey();
}

/// Two senders that seal against the same published bundle with the
/// same random stream pick the same slot: the second message finds
/// it already burned. One-time means one time, per slot.
#[test]
fn a_second_message_to_a_consumed_slot_is_refused() {
    let alice = identity(1);
    let (bundle, mut secrets) = bundle_for(3);

    let first =
        PrekeySealedMessage::seal(&alice, &bundle, b"first", &mut TestRng::new(11)).expect("seals");
    let second = PrekeySealedMessage::seal(&alice, &bundle, b"second", &mut TestRng::new(11))
        .expect("seals");
    assert_eq!(
        first.one_time_index(),
        second.one_time_index(),
        "the same rng stream picks the same slot"
    );

    first.open(&identity(3), &mut secrets).expect("opens");
    let err = second
        .open(&identity(3), &mut secrets)
        .expect_err("slot already burned");
    assert!(matches!(err, IdentError::PrekeyUnavailable), "wrong: {err}");
}

/// Every envelope field is authenticated: suite, sender agreement
/// key, ephemeral key, slot index, nonce and ciphertext each fail
/// the open when a single byte is flipped.
#[test]
fn tampered_fields_fail_the_open() {
    let alice = identity(1);
    let (bundle, mut secrets) = bundle_for(3);
    let message = PrekeySealedMessage::seal(&alice, &bundle, b"payload", &mut TestRng::new(11))
        .expect("seals");
    let encoded = message.encode();

    let positions = [
        ("sender agreement key", 1),
        ("ephemeral key", 33),
        ("slot index", 65),
        ("nonce", 66),
        ("first ciphertext byte", MSG_HEADER_LEN),
        ("last byte", encoded.len() - 1),
    ];
    for (label, at) in positions {
        let mut tampered = encoded.clone();
        tampered[at] ^= 0x01;
        let decoded = PrekeySealedMessage::decode(&tampered).expect("structure intact");
        let err = decoded.open(&identity(3), &mut secrets).expect_err(label);
        assert!(matches!(err, IdentError::OpenFailed), "{label}: {err}");
    }

    // The suite byte never gets that far: it fails at decode.
    let mut tampered = encoded;
    tampered[0] ^= 0x01;
    assert!(matches!(
        PrekeySealedMessage::decode(&tampered),
        Err(IdentError::UnknownSuite(0))
    ));
}

/// A bundle that is not signed by the identity it claims never
/// reaches the DH: both a flipped signature and a flipped key are
/// refused before anything is sealed.
#[test]
fn a_forged_bundle_is_rejected() {
    let alice = identity(1);
    let (bundle, _secrets) = bundle_for(3);
    let encoded = bundle.encode();

    let mut forged = encoded.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let decoded = PrekeyBundle::decode(&forged).expect("structure intact");
    let err = PrekeySealedMessage::seal(&alice, &decoded, b"x", &mut TestRng::new(11))
        .expect_err("forged signature");
    assert!(matches!(err, IdentError::InvalidSignature), "wrong: {err}");

    // A flipped public key is covered by the same signature; the key
    // itself may also stop parsing as a curve point, so either typed
    // refusal proves the bundle never reached the DH.
    let mut forged = encoded;
    forged[1] ^= 0x01;
    let decoded = PrekeyBundle::decode(&forged).expect("structure intact");
    let err = PrekeySealedMessage::seal(&alice, &decoded, b"x", &mut TestRng::new(11))
        .expect_err("forged key");
    assert!(
        matches!(
            err,
            IdentError::InvalidSignature | IdentError::InvalidPublicKey
        ),
        "wrong: {err}"
    );
}

/// A different recipient with different prekeys derives a different
/// session key: the AEAD says no.
#[test]
fn a_wrong_recipient_cannot_open() {
    let alice = identity(1);
    let (bundle, _secrets) = bundle_for(3);
    let message =
        PrekeySealedMessage::seal(&alice, &bundle, b"bob's", &mut TestRng::new(11)).expect("seals");

    let (mallory_bundle, mut mallory_secrets) = bundle_for(9);
    assert_ne!(mallory_bundle.node_id(), bundle.node_id());
    let err = message
        .open(&identity(9), &mut mallory_secrets)
        .expect_err("wrong keys");
    assert!(matches!(err, IdentError::OpenFailed), "wrong: {err}");
}

/// Fixed-length decodes reject anything that is not exactly the
/// layout - truncated, trailing, unknown suite, or a count outside
/// the cap - and the count is refused before the key list would be
/// allocated.
#[test]
fn decodings_reject_malformed_input() {
    let (bundle, _secrets) = bundle_for(3);
    let encoded = bundle.encode();

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        PrekeyBundle::decode(&truncated),
        Err(IdentError::MalformedPrekeyBundle)
    ));

    let mut overlong = encoded.clone();
    overlong.push(0);
    assert!(matches!(
        PrekeyBundle::decode(&overlong),
        Err(IdentError::MalformedPrekeyBundle)
    ));

    let mut wrong_suite = encoded.clone();
    wrong_suite[0] = 0x02;
    assert!(matches!(
        PrekeyBundle::decode(&wrong_suite),
        Err(IdentError::UnknownSuite(0x02))
    ));

    let mut zero_count = encoded.clone();
    zero_count[97] = 0;
    assert!(matches!(
        PrekeyBundle::decode(&zero_count),
        Err(IdentError::InvalidPrekeyCount)
    ));

    let mut huge_count = encoded.clone();
    huge_count[97] = (MAX_ONE_TIME_PREKEYS + 1) as u8;
    assert!(matches!(
        PrekeyBundle::decode(&huge_count),
        Err(IdentError::InvalidPrekeyCount)
    ));

    let mut short_count = encoded;
    short_count[97] = 1;
    assert!(matches!(
        PrekeyBundle::decode(&short_count),
        Err(IdentError::MalformedPrekeyBundle)
    ));

    let alice = identity(1);
    let message = PrekeySealedMessage::seal(&alice, &bundle, b"payload", &mut TestRng::new(11))
        .expect("seals");
    let encoded = message.encode();

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        PrekeySealedMessage::decode(&truncated),
        Err(IdentError::MalformedPrekeyMessage)
    ));

    let mut overlong = encoded.clone();
    overlong.push(0);
    assert!(matches!(
        PrekeySealedMessage::decode(&overlong),
        Err(IdentError::MalformedPrekeyMessage)
    ));

    let mut wrong_suite = encoded.clone();
    wrong_suite[0] = 0x02;
    assert!(matches!(
        PrekeySealedMessage::decode(&wrong_suite),
        Err(IdentError::UnknownSuite(0x02))
    ));

    // A length field below the inner framing is refused before the
    // slice is taken.
    let mut short_length = encoded;
    short_length[90..92].copy_from_slice(&0_u16.to_be_bytes());
    assert!(matches!(
        PrekeySealedMessage::decode(&short_length),
        Err(IdentError::MalformedPrekeyMessage)
    ));
}

/// Generation enforces the same count cap the decoder enforces.
#[test]
fn generate_rejects_out_of_range_counts() {
    let bob = identity(3);
    for count in [0_u8, (MAX_ONE_TIME_PREKEYS + 1) as u8] {
        let err = PrekeyBundle::generate(&bob, count, &mut TestRng::new(10))
            .expect_err("count outside 1..=cap");
        assert!(
            matches!(err, IdentError::InvalidPrekeyCount),
            "wrong: {err}"
        );
    }
    PrekeyBundle::generate(&bob, MAX_ONE_TIME_PREKEYS as u8, &mut TestRng::new(10))
        .expect("the cap itself is allowed");
}

/// The payload limit: exactly `65535 - (inner 160 + tag 16)` seals,
/// one byte more is refused before the buffer is allocated.
#[test]
fn oversize_payload_is_refused_before_allocation() {
    let alice = identity(1);
    let (bundle, _secrets) = bundle_for(3);

    let largest = vec![0_u8; 65535 - (160 + 16)];
    PrekeySealedMessage::seal(&alice, &bundle, &largest, &mut TestRng::new(11))
        .expect("at the limit");

    let over = vec![0_u8; 65535 - (160 + 16) + 1];
    let err = PrekeySealedMessage::seal(&alice, &bundle, &over, &mut TestRng::new(11))
        .expect_err("over the limit");
    assert!(matches!(err, IdentError::PayloadTooLarge), "wrong: {err}");
}

/// The secrets' Debug prints slot counts, never key bytes.
#[test]
fn debug_of_secrets_redacts_key_material() {
    let (_bundle, secrets) = bundle_for(3);
    let printed = format!("{secrets:?}");
    assert!(printed.contains("PrekeySecrets"), "names the type");
    assert!(printed.contains("4/4"), "shows slot counts: {printed}");
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

        /// Arbitrary bytes never panic: every input is a typed error
        /// or a structure that then verifies or fails on its own
        /// merits.
        #[test]
        fn decoding_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..320),
        ) {
            let _ = PrekeyBundle::decode(&bytes);
            let _ = PrekeySealedMessage::decode(&bytes);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(16))]

        /// Any payload round-trips: seal to a fresh bundle, open with
        /// its secrets, get the same bytes back and the sender
        /// authenticated.
        #[test]
        fn seal_open_round_trips_arbitrary_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let alice = identity(1);
            let (bundle, mut secrets) = bundle_for(3);
            let message = PrekeySealedMessage::seal(
                &alice,
                &bundle,
                &payload,
                &mut TestRng::new(11),
            )
            .expect("within the payload limit");
            let opened = message.open(&identity(3), &mut secrets).expect("opens");
            prop_assert_eq!(opened.plaintext(), payload.as_slice());
            prop_assert_eq!(opened.sender().signing_pk(), alice.public().signing_pk());
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(8))]

        /// Every single-byte corruption of a sealed message fails to
        /// open: the flipped byte is either outside the layout, breaks
        /// the suite or length, or is covered by the DH and the AEAD.
        #[test]
        fn every_single_byte_tamper_fails_to_open(
            bob_state in any::<u64>(),
        ) {
            let alice = identity(1);
            let bob = identity(bob_state);
            let (bundle, mut secrets) = PrekeyBundle::generate(&bob, 4, &mut TestRng::new(100))
                .expect("four slots is within the cap");
            let payload = [0_u8; 8];
            let message = PrekeySealedMessage::seal(
                &alice,
                &bundle,
                &payload,
                &mut TestRng::new(11),
            )
            .expect("seals");
            let encoded = message.encode();

            for index in 0..encoded.len() {
                let mut tampered = encoded.clone();
                tampered[index] ^= 0x01;
                let rejected = PrekeySealedMessage::decode(&tampered).map_or(true, |decoded| {
                    decoded.open(&bob, &mut secrets).is_err()
                });
                prop_assert!(
                    rejected,
                    "byte {index} survived: decode and open both passed"
                );
            }
        }
    }
}
