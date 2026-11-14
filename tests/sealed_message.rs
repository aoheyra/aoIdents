//! Sealed messages: one-to-one, offline-friendly encryption (IDN-09).
//!
//! Covers the done-when (any tampered field fails to open, wrong
//! recipient fails, checked-in test vectors) plus the message-ID
//! binding, the size limit, malformed encodings and proptests.

mod common;

use ao_idents::{IdentError, Identity, MSG_ID_LEN, PublicIdentity, SealedMessage};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn msg_id() -> [u8; MSG_ID_LEN] {
    *b"vector-msg-id-01"
}

/// The fixed inputs of the checked-in test vector: two identities, a
/// message ID and a plaintext, all deterministic under `TestRng`.
fn vector_inputs() -> (Identity, Identity, [u8; MSG_ID_LEN], &'static [u8]) {
    let sender = identity(101);
    let recipient = identity(202);
    (
        sender,
        recipient,
        msg_id(),
        b"aoheyra sealed message v1 test vector",
    )
}

fn seal_vector() -> SealedMessage {
    let (sender, recipient, id, plaintext) = vector_inputs();
    SealedMessage::seal(
        &sender,
        recipient.public(),
        &id,
        plaintext,
        &mut TestRng::new(303),
    )
    .expect("vector plaintext fits")
}

/// The done-when, happy path: a sealed message survives encode and
/// decode, opens for the recipient, and reports the authenticated
/// sender.
#[test]
fn round_trip_returns_plaintext_and_authenticated_sender() {
    let sender = identity(1);
    let recipient = identity(2);
    let id = msg_id();
    let plaintext = b"offline-friendly: the recipient was not present when this was sealed";

    let sealed = SealedMessage::seal(
        &sender,
        recipient.public(),
        &id,
        plaintext,
        &mut TestRng::new(7),
    )
    .expect("fits");
    let decoded = SealedMessage::decode(&sealed.encode()).expect("round trip");
    let opened = decoded.open(&recipient, &id).expect("recipient opens");

    assert_eq!(opened.plaintext(), plaintext);
    assert_eq!(opened.sender(), sender.public());
}

/// The done-when: flipping any single byte of the encoded message
/// makes decode or open fail - header, ephemeral key, nonce, length
/// and ciphertext are all covered.
#[test]
fn every_single_byte_corruption_fails_to_open() {
    let (_, recipient, id, _) = vector_inputs();
    let bytes = seal_vector().encode();
    let mut corrupted = bytes.clone();
    for index in 0..corrupted.len() {
        corrupted[index] ^= 0x01;
        let result =
            SealedMessage::decode(&corrupted).and_then(|sealed| sealed.open(&recipient, &id));
        assert!(result.is_err(), "byte {index} must be rejected");
        corrupted[index] ^= 0x01;
    }
    assert_eq!(corrupted, bytes, "untouched copy still opens");
}

/// The done-when: a message sealed to someone else does not open,
/// even with the correct message ID.
#[test]
fn wrong_recipient_cannot_open() {
    let (sender, _, id, plaintext) = vector_inputs();
    let real = identity(202);
    let intruder = identity(3);

    let sealed = SealedMessage::seal(&sender, real.public(), &id, plaintext, &mut TestRng::new(9))
        .expect("fits");
    assert!(matches!(
        sealed.open(&intruder, &id),
        Err(IdentError::OpenFailed)
    ));
    assert!(sealed.open(&real, &id).is_ok());
}

/// The associated data binds the message ID: the same ciphertext at
/// a different message ID does not open.
#[test]
fn wrong_message_id_cannot_open() {
    let (sender, recipient, id, plaintext) = vector_inputs();
    let sealed = SealedMessage::seal(
        &sender,
        recipient.public(),
        &id,
        plaintext,
        &mut TestRng::new(11),
    )
    .expect("fits");
    let other_id = [0xFF; MSG_ID_LEN];
    assert!(matches!(
        sealed.open(&recipient, &other_id),
        Err(IdentError::OpenFailed)
    ));
}

/// An empty message is a valid message.
#[test]
fn empty_plaintext_round_trips() {
    let sender = identity(4);
    let recipient = identity(5);
    let id = msg_id();
    let sealed = SealedMessage::seal(&sender, recipient.public(), &id, b"", &mut TestRng::new(13))
        .expect("empty fits");
    let opened = sealed.open(&recipient, &id).expect("opens");
    assert_eq!(opened.plaintext(), b"");
}

/// The largest plaintext that fits the u16 length field still opens;
/// one byte more is [`IdentError::PayloadTooLarge`] - rejected, never
/// truncated.
#[test]
fn plaintext_size_limit_is_exact() {
    let sender = identity(6);
    let recipient = identity(7);
    let id = msg_id();
    // 65535 - (sender identity 192 + tag 16).
    let max = 65_535 - 192 - 16;

    let sealed = SealedMessage::seal(
        &sender,
        recipient.public(),
        &id,
        &vec![0x42; max],
        &mut TestRng::new(17),
    )
    .expect("exact limit fits");
    let opened = sealed.open(&recipient, &id).expect("opens");
    assert_eq!(opened.plaintext().len(), max);

    assert!(matches!(
        SealedMessage::seal(
            &sender,
            recipient.public(),
            &id,
            &vec![0x42; max + 1],
            &mut TestRng::new(17),
        ),
        Err(IdentError::PayloadTooLarge)
    ));
}

/// A low-order recipient key cannot pin the shared secret: sealing
/// refuses it up front instead of producing a message everyone can
/// derive the key for.
#[test]
fn low_order_recipient_key_is_rejected() {
    let sender = identity(8);
    let recipient = identity(9);
    let low_order = PublicIdentity::new(
        *recipient.public().signing_pk(),
        [0u8; 32],
        *recipient.public().agreement_binding(),
    );
    assert!(matches!(
        SealedMessage::seal(
            &sender,
            &low_order,
            &msg_id(),
            b"payload",
            &mut TestRng::new(19),
        ),
        Err(IdentError::InvalidPublicKey)
    ));
}

/// Hostile encodings: cut header, cut ciphertext, trailing byte,
/// wrong length field, unknown suite - each a typed error, never a
/// panic.
#[test]
fn malformed_encodings_are_typed_errors() {
    let bytes = seal_vector().encode();

    for cut in [0, 20, 58] {
        assert!(
            matches!(
                SealedMessage::decode(&bytes[..cut]),
                Err(IdentError::MalformedSealed)
            ),
            "cut at {cut} must be malformed"
        );
    }

    // Header announces more ciphertext than the buffer carries.
    assert!(matches!(
        SealedMessage::decode(&bytes[..59 + 10]),
        Err(IdentError::MalformedSealed)
    ));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        SealedMessage::decode(&trailing),
        Err(IdentError::MalformedSealed)
    ));

    let mut wrong_length = bytes.clone();
    wrong_length[57..59].copy_from_slice(&[0xFF, 0xFF]);
    assert!(matches!(
        SealedMessage::decode(&wrong_length),
        Err(IdentError::MalformedSealed)
    ));

    let mut unknown = bytes;
    unknown[0] = 0x99;
    assert!(matches!(
        SealedMessage::decode(&unknown),
        Err(IdentError::UnknownSuite(_))
    ));
}

/// The checked-in test vector: the exact bytes this construction
/// produces for fixed inputs, so an accidental wire or derivation
/// change fails CI. The vector must open and report its sender.
#[test]
fn checked_in_test_vector_matches_and_opens() {
    const VECTOR_HEX: &str = "01c3ec400bd4d19156399cd6a8163d243ceba8f68b3754ea2ce7a59e62ec95f500a84ccd8f2a9c7b6acf577dd62e5e33bc4640ea5a6e69f30a00f59074b55c66dcd7179eee1a28e8b9b079381bbd473f16736c8152324a78d6f7156d37b798e2918ea447626d6bae1634170d7c4f0ebd840014c3b893c760accc88a0755bf7227463ba75bbeb01f536ca2b4f37358fd1acef1e68197b9941b6167a4ac19d03391dc0c485e5944d531df309df9cc4ed58767578fc1fe42f36a21c03155c665a344990fd35fe49b620cdef73f422550144aed7749eec8f43f682f999487a32e991d27a6c69b6d9ac74f986a3271cb2f76d02836f8aa26df7bdb9829e7d35a31c06a38f35bb20b5d84771d5fde050bb8e393db5e8e7b559fe559dad7b028297dc6edec5a4a864161b209f97f6734c18683e";
    let expected: Vec<u8> = (0..VECTOR_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&VECTOR_HEX[i..i + 2], 16).expect("hex"))
        .collect();

    let (sender, recipient, id, plaintext) = vector_inputs();
    let actual = seal_vector().encode();
    assert_eq!(
        actual, expected,
        "sealed output changed: if intentional, this is a protocol change (ADR-0001)"
    );

    let opened = SealedMessage::decode(&actual)
        .expect("vector decodes")
        .open(&recipient, &id)
        .expect("vector opens");
    assert_eq!(opened.plaintext(), plaintext);
    assert_eq!(opened.sender(), sender.public());

    // A single flipped byte of the checked-in vector fails to open.
    let mut corrupted = actual;
    corrupted[100] ^= 0x01;
    let corrupted = SealedMessage::decode(&corrupted).expect("structure intact");
    assert!(matches!(
        corrupted.open(&recipient, &id),
        Err(IdentError::OpenFailed)
    ));
}

mod proptests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{Config, FileFailurePersistence};

    fn proptest_config_for_runtime() -> Config {
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
            cases: if cfg!(miri) { 8 } else { default.cases },
            ..default
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime())]

        /// Every plaintext and every message ID survives seal, encode,
        /// decode and open unchanged, with the right sender.
        #[test]
        fn arbitrary_plaintext_round_trips(
            plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
            id in any::<[u8; MSG_ID_LEN]>(),
            seed in any::<u64>(),
        ) {
            let sender = identity(seed | 1);
            let recipient = identity(seed.rotate_left(32) | 1);
            let sealed = SealedMessage::seal(
                &sender,
                recipient.public(),
                &id,
                &plaintext,
                &mut TestRng::new(seed ^ 0x5EED_5EED_5EED_5EED),
            )
            .expect("within the size limit");
            let decoded = SealedMessage::decode(&sealed.encode()).expect("round trip");
            let opened = decoded.open(&recipient, &id).expect("opens");
            prop_assert_eq!(opened.plaintext(), &plaintext[..]);
            prop_assert_eq!(opened.sender(), sender.public());
        }

        /// Arbitrary bytes never panic decode, and never open as a
        /// genuine message: only a holder of the content key produces
        /// a valid tag.
        #[test]
        fn arbitrary_bytes_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            id in any::<[u8; MSG_ID_LEN]>(),
        ) {
            if let Ok(sealed) = SealedMessage::decode(&bytes) {
                let recipient = identity(43);
                prop_assert!(
                    sealed.open(&recipient, &id).is_err(),
                    "random bytes must not open"
                );
            }
        }
    }
}
