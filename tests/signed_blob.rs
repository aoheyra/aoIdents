//! Signed public blobs (IDN-11).
//!
//! Covers the done-when (verification covers every field; a stale seq
//! is distinguishable from a forged one) plus every new `IdentError`
//! variant and the class of hostile inputs: truncation, trailing
//! bytes, length lies and arbitrary bytes.

mod common;

use ao_idents::{IdentError, Identity, SignedBlob};
use common::TestRng;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn blob(state: u64) -> SignedBlob {
    SignedBlob::sign(&identity(state), 7, 1_700_000_000, b"hello blob".to_vec())
        .expect("registered domain and small payload")
}

/// The done-when: a blob survives sign -> encode -> decode -> verify.
#[test]
fn blob_round_trips_and_verifies() {
    let id = identity(1);
    let signed = SignedBlob::sign(&id, 7, 1_700_000_000, b"hello blob".to_vec())
        .expect("registered domain and small payload");
    assert_eq!(signed.origin(), id.node_id());
    assert_eq!(signed.seq(), 7);
    assert_eq!(signed.timestamp(), 1_700_000_000);
    assert_eq!(signed.payload(), b"hello blob");

    let decoded = SignedBlob::decode(&signed.encode()).expect("round-trips");
    assert_eq!(&decoded, &signed);
    decoded.verify(id.public(), None).expect("verifies");
}

/// The done-when: verification covers every field. Flipping any single
/// byte of the encoding must be rejected - either the decode fails or
/// the signature no longer matches.
#[test]
fn every_single_byte_corruption_is_rejected() {
    let id = identity(2);
    let bytes = blob(2).encode();
    for index in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 0x01;
        let outcome = SignedBlob::decode(&corrupted).and_then(|b| b.verify(id.public(), None));
        assert!(outcome.is_err(), "corrupting byte {index} must be rejected");
    }
}

/// The done-when: stale and forged are distinguishable. A forged blob
/// (bad signature) reports `InvalidSignature` regardless of seq; a
/// valid blob that is not strictly newer reports `StaleBlob`.
#[test]
fn stale_seq_is_distinguishable_from_forged() {
    let id = identity(3);
    let signed =
        SignedBlob::sign(&id, 10, 1_700_000_000, b"payload".to_vec()).expect("registered domain");

    // Freshness: strictly newer passes, equal or older is stale.
    signed.verify(id.public(), Some(9)).expect("seq 10 > 9");
    assert_eq!(
        signed.verify(id.public(), Some(10)),
        Err(IdentError::StaleBlob),
        "seq equal to the latest accepted must be stale, not newer"
    );
    assert_eq!(
        signed.verify(id.public(), Some(11)),
        Err(IdentError::StaleBlob)
    );

    // Forged: one flipped payload byte, but with a seq that would be
    // stale if the signature were checked after freshness - the
    // signature check must win and report InvalidSignature.
    let bytes = signed.encode();
    let mut corrupted = bytes.clone();
    corrupted[35] ^= 0x01; // first payload byte
    let forged = SignedBlob::decode(&corrupted).expect("lengths unchanged");
    assert_eq!(
        forged.verify(id.public(), Some(10)),
        Err(IdentError::InvalidSignature)
    );
}

/// A payload over the `u16` canonical encoding limit is a typed error,
/// never a silent truncation.
#[test]
fn oversized_payload_is_a_typed_error() {
    let id = identity(4);
    let payload = vec![0u8; u16::MAX as usize + 1];
    assert_eq!(
        SignedBlob::sign(&id, 1, 0, payload),
        Err(IdentError::PayloadTooLarge)
    );
    // The documented limit itself is accepted.
    let ok = SignedBlob::sign(&id, 1, 0, vec![0u8; u16::MAX as usize]);
    assert!(ok.is_ok(), "exactly 65535 bytes must be accepted");
}

/// Truncated, over-long, trailing-byte and bad-suite inputs are typed
/// errors, never panics.
#[test]
fn malformed_encodings_are_typed_errors() {
    let bytes = blob(5).encode();

    assert_eq!(SignedBlob::decode(&[]), Err(IdentError::MalformedBlob));
    assert_eq!(
        SignedBlob::decode(&bytes[..20]),
        Err(IdentError::MalformedBlob)
    );
    // Just short of the full length: payload length disagrees.
    assert_eq!(
        SignedBlob::decode(&bytes[..bytes.len() - 1]),
        Err(IdentError::MalformedBlob)
    );
    // Trailing bytes after the signature.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SignedBlob::decode(&trailing),
        Err(IdentError::MalformedBlob)
    );
    // Unknown suite byte.
    let mut bad_suite = bytes.clone();
    bad_suite[0] = 0x02;
    assert_eq!(
        SignedBlob::decode(&bad_suite),
        Err(IdentError::UnknownSuite(0x02))
    );
}

/// Hostile input class: arbitrary bytes never panic, and anything that
/// decodes must round-trip through encode.
fn proptest_config_for_runtime() -> proptest::test_runner::Config {
    let default = proptest::test_runner::Config::default();
    // Regression files need the process CWD, which Miri's isolation forbids.
    // Keep file persistence natively, skip it under Miri.
    proptest::test_runner::Config {
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

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(decoded) = SignedBlob::decode(&bytes) {
            prop_assert_eq!(&SignedBlob::decode(&decoded.encode()).expect("re-encodes"), &decoded);
        }
    }

    #[test]
    fn sign_encode_decode_round_trips(
        seq in any::<u64>(),
        timestamp in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let id = identity(6);
        let signed = SignedBlob::sign(&id, seq, timestamp, payload).expect("small payload");
        prop_assert_eq!(&SignedBlob::decode(&signed.encode()).expect("round-trips"), &signed);
        prop_assert!(signed.verify(id.public(), None).is_ok());
    }
}
