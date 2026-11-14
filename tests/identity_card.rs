//! Identity cards and the QR string (IDN-07).
//!
//! Covers the done-when (a card survives encode, decode, verify; a
//! tampered byte or bad checksum is rejected with a typed error) plus
//! the display-name limit, the QR format rules and the announcement
//! hash.

mod common;

use ao_idents::{IdentError, Identity, IdentityCard};
use common::TestRng;

const QR_PREFIX: &str = "aoheyra:id:";
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn card() -> IdentityCard {
    identity(1)
        .card(b"alice", 1_700_000_000)
        .expect("five bytes fits the name limit")
}

/// The done-when, happy path: sign, encode, decode and verify all
/// survive, and every field reads back unchanged.
#[test]
fn card_round_trips_sign_encode_decode_verify() {
    let id = identity(1);
    let card = id.card(b"alice", 1_700_000_000).expect("five bytes fits");
    card.verify().expect("self-signed at creation");

    let decoded = IdentityCard::decode(&card.encode()).expect("round trip");
    decoded.verify().expect("survives encode and decode");
    assert_eq!(decoded, card);
    assert_eq!(decoded.suite(), id.suite());
    assert_eq!(decoded.signing_pk(), id.public().signing_pk());
    assert_eq!(decoded.agreement_pk(), id.public().agreement_pk());
    assert_eq!(decoded.display_name(), b"alice");
    assert_eq!(decoded.created_at(), 1_700_000_000);
    assert_eq!(decoded.self_signature(), card.self_signature());
}

/// The QR form carries the card across and back: prefix, uppercase
/// base32 only, and a re-parse equals the original.
#[test]
fn qr_string_round_trips() {
    let card = card();
    let qr = card.to_qr_string();
    assert!(qr.starts_with(QR_PREFIX), "prefix is fixed: {qr}");
    let payload = &qr[QR_PREFIX.len()..];
    assert!(
        payload
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
        "payload is uppercase base32: {payload}"
    );

    let parsed = IdentityCard::from_qr_string(&qr).expect("parse and verify");
    assert_eq!(parsed, card);
    parsed.verify().expect("signature still valid");
}

/// The done-when: flipping any single byte of the encoded card makes
/// decode or verify fail - structure errors, unknown suite, bad keys
/// and bad signatures are all typed errors.
#[test]
fn every_single_byte_corruption_is_rejected() {
    let bytes = card().encode();
    let mut corrupted = bytes.clone();
    for index in 0..corrupted.len() {
        corrupted[index] ^= 0x01;
        let result = IdentityCard::decode(&corrupted).and_then(|card| card.verify());
        assert!(result.is_err(), "byte {index} must be rejected");
        corrupted[index] ^= 0x01;
    }
    assert_eq!(corrupted, bytes, "untouched copy still round trips");
}

/// A structure-preserving tamper (creation time) still fails the
/// self-signature: the signature covers every field, not the layout.
#[test]
fn self_signature_covers_the_creation_time() {
    let mut bytes = card().encode();
    // created_at sits after suite, both keys and the 5-byte name.
    bytes[75] ^= 0x01;
    let tampered = IdentityCard::decode(&bytes).expect("structure unchanged");
    assert!(matches!(
        tampered.verify(),
        Err(IdentError::InvalidSignature)
    ));
}

/// A typo in the QR payload is caught by the checksum before any
/// signature work.
#[test]
fn tampered_qr_payload_fails_the_checksum() {
    let qr = card().to_qr_string();
    let mut bytes = qr.into_bytes();
    let index = QR_PREFIX.len() + 10;
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).expect("ascii");
    assert!(matches!(
        IdentityCard::from_qr_string(&tampered),
        Err(IdentError::ChecksumMismatch)
    ));
}

/// Base32 padding bits must be zero: setting one yields the same
/// card bytes in a second spelling, which the parser refuses.
#[test]
fn non_canonical_base32_padding_is_rejected() {
    let card = card();
    let qr = card.to_qr_string();
    let payload_len = qr.len() - QR_PREFIX.len();
    let data_bits = (card.encode().len() + 4) * 8;
    let padding_bits = payload_len * 5 - data_bits;
    assert!(padding_bits >= 1, "test needs at least one padding bit");

    let mut bytes = qr.into_bytes();
    let last = bytes.len() - 1;
    let position = B32_ALPHABET
        .iter()
        .position(|&alphabet| alphabet == bytes[last])
        .expect("payload is base32");
    bytes[last] = B32_ALPHABET[position | 1]; // set the low padding bit
    let tampered = String::from_utf8(bytes).expect("ascii");
    assert!(matches!(
        IdentityCard::from_qr_string(&tampered),
        Err(IdentError::InvalidQr)
    ));
}

/// Format violations are typed errors: no prefix, a character outside
/// the alphabet, lowercase payload, and an empty payload.
#[test]
fn qr_format_violations_are_typed_errors() {
    let qr = card().to_qr_string();
    let payload = &qr[QR_PREFIX.len()..];

    assert!(matches!(
        IdentityCard::from_qr_string(payload),
        Err(IdentError::InvalidQr)
    ));
    assert!(matches!(
        IdentityCard::from_qr_string("aoheyra:id:0NOTBASE32"),
        Err(IdentError::InvalidQr)
    ));
    let lowercase = format!("{QR_PREFIX}{}", payload.to_ascii_lowercase());
    assert!(matches!(
        IdentityCard::from_qr_string(&lowercase),
        Err(IdentError::InvalidQr)
    ));
    assert!(matches!(
        IdentityCard::from_qr_string(QR_PREFIX),
        Err(IdentError::MalformedCard)
    ));
}

/// The 24-byte display-name limit, both sides of it.
#[test]
fn display_name_over_24_bytes_is_rejected() {
    let id = identity(2);
    assert!(matches!(
        id.card(&[b'x'; 25], 0),
        Err(IdentError::NameTooLong)
    ));
    assert!(id.card(&[b'x'; 24], 0).is_ok());
    assert!(id.card(b"", 0).is_ok());
}

/// Hostile card encodings: truncated, trailing byte, over-long name
/// field, unknown suite - each a typed error, never a panic.
#[test]
fn malformed_card_encodings_are_typed_errors() {
    let bytes = card().encode();

    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(matches!(
        IdentityCard::decode(&truncated),
        Err(IdentError::MalformedCard)
    ));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        IdentityCard::decode(&trailing),
        Err(IdentError::MalformedCard)
    ));

    let mut long_name = bytes.clone();
    long_name[65] = 25;
    assert!(matches!(
        IdentityCard::decode(&long_name),
        Err(IdentError::MalformedCard)
    ));

    let mut unknown = bytes;
    unknown[0] = 0x99;
    assert!(matches!(
        IdentityCard::decode(&unknown),
        Err(IdentError::UnknownSuite(_))
    ));
}

/// The announcement hash: 8 bytes, deterministic for the card,
/// different for a different name.
#[test]
fn announcement_hash_is_short_stable_and_distinct() {
    let card = card();
    let hash = card.announcement_hash();
    let again = IdentityCard::decode(&card.encode())
        .expect("round trip")
        .announcement_hash();
    assert_eq!(hash, again, "same card, same hash");

    let other = identity(1)
        .card(b"bob", 1_700_000_000)
        .expect("three bytes fits");
    assert_ne!(hash, other.announcement_hash(), "name is covered");
}

/// The checked-in test vector: the exact card bytes and QR string
/// for fixed inputs, so an accidental encoding or base32 change
/// fails CI. Derived once from this implementation and reviewed
/// before check-in; the primitives underneath are pinned by their
/// own crates' test suites.
#[test]
fn checked_in_test_vector_matches_and_parses() {
    const VECTOR_HEX: &str = "0136f960c0fbef20e5c8fb68dcaf23d84ad074e34638c2dcc32a2961ac80aee74c08b10522c5f3757bfad11b9f39028b56fb6212f4e6ded4f4bf23e798b2e5754f05616c696365000000006553f100be5bb2250cdff697aa8ccea1b1f49dee74cf26feaa15785500eea8c6a27c13a858d5ab7ffa092fead6ed693e6b627e0cb2105b0a2b84e1fa8aba1b9e41643708";
    const VECTOR_QR: &str = "aoheyra:id:AE3PSYGA7PXSBZOI7NUNZLZD3BFNA5HDIY4MFXGDFIUWDLEAV3TUYCFRAURML43VPP5NCG47HEBIWVX3MIJPJZW62T2L6I7HTCZOK5KPAVQWY2LDMUAAAAAAMVJ7CAF6LOZCKDG762L2VDGOUGY7JHPOOTHSN7VKCV4FKAHOVDDKE7ATVBMNLK377IES72WW5VUT423CPYGLEEC3BIVYJYP2RK5BXHSBMQ3QQ56WUDIQ";
    let expected: Vec<u8> = (0..VECTOR_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&VECTOR_HEX[i..i + 2], 16).expect("hex"))
        .collect();

    let card = Identity::from_seed([5u8; 32])
        .card(b"alice", 1_700_000_000)
        .expect("five bytes fits the name limit");
    let actual = card.encode();
    assert_eq!(
        actual, expected,
        "card encoding changed: if intentional, this is a protocol change (ADR-0001)"
    );
    assert_eq!(
        card.to_qr_string(),
        VECTOR_QR,
        "QR string changed: if intentional, this is a protocol change (ADR-0001)"
    );

    let parsed = IdentityCard::from_qr_string(VECTOR_QR).expect("vector parses and verifies");
    assert_eq!(parsed.encode(), expected);
}

/// The done-when's size bound: even the worst case (24-byte name)
/// stays inside one QR code - 162 card bytes + 4 checksum = 266
/// base32 characters plus the 11-character prefix. Version 11 in
/// byte mode holds 321 data bytes at error-correction level L.
#[test]
fn worst_case_qr_string_fits_one_code() {
    let id = identity(3);
    let worst = id.card(&[b'x'; 24], u64::MAX).expect("exactly 24");
    let qr = worst.to_qr_string();
    assert!(qr.len() <= 300, "worst case is {} characters", qr.len());
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

        /// Arbitrary bytes never panic the parser, and never forge a
        /// card: decode or QR-parse failure is the only outcome that
        /// can hold for input nobody signed.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Ok(card) = IdentityCard::decode(&bytes) {
                prop_assert!(
                    card.verify().is_err(),
                    "random bytes must not form a valid signature"
                );
            }
            let text = String::from_utf8_lossy(&bytes);
            prop_assert!(
                IdentityCard::from_qr_string(&text).is_err(),
                "random text must not parse into a verified card"
            );
        }

        /// Every name within the limit and every timestamp survives
        /// both round trips unchanged.
        #[test]
        fn card_survives_encode_decode_and_qr_roundtrip(
            name in proptest::collection::vec(any::<u8>(), 0..24),
            created_at in any::<u64>(),
        ) {
            let id = identity(21);
            let card = id.card(&name, created_at).expect("within the name limit");
            prop_assert_eq!(
                &IdentityCard::decode(&card.encode()).expect("round trip"),
                &card
            );
            let parsed =
                IdentityCard::from_qr_string(&card.to_qr_string()).expect("qr round trip");
            prop_assert_eq!(&parsed, &card);
            prop_assert!(parsed.verify().is_ok());
        }
    }
}
