//! IDN-02: core types and errors.
//!
//! Covers the done-when directly: no secret type prints contents, `Clone`
//! is explicit and correct, zeroization is observable, equality is right,
//! and every `IdentError` variant has a test that triggers it.

use std::collections::HashSet;

use ao_idents::{IdentError, NodeId, PublicIdentity, SecretIdentity, Signature, SuiteId};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use zeroize::Zeroize;

// --- SuiteId -------------------------------------------------------------

#[test]
fn suite_v1_is_byte_0x01() {
    assert_eq!(SuiteId::V1.byte(), 0x01);
    assert_eq!(SuiteId::try_from(0x01), Ok(SuiteId::V1));
}

#[test]
fn unknown_suite_is_a_typed_error_with_context() {
    let err = SuiteId::try_from(0x42).unwrap_err();
    assert_eq!(err, IdentError::UnknownSuite(0x42));
    // The variant carries the offending byte and Display names it.
    assert_eq!(err.to_string(), "unknown crypto suite byte 0x42");
    // And the enum is usable as a std error.
    let _: &dyn std::error::Error = &err;
}

// --- NodeId --------------------------------------------------------------

#[test]
fn node_id_roundtrips_and_displays_as_hex() {
    let bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ];
    let id = NodeId::from_bytes(bytes);
    assert_eq!(id.as_bytes(), &bytes);
    assert_eq!(id.to_string(), "0123456789abcdef1032547698badcfe");
    assert_eq!(
        format!("{id:?}"),
        "NodeId(0123456789abcdef1032547698badcfe)"
    );
}

#[test]
fn node_id_equality_hashing_and_ordering() {
    let a = NodeId::from_bytes([1; 16]);
    let b = NodeId::from_bytes([1; 16]);
    let c = NodeId::from_bytes([2; 16]);

    assert_eq!(a, b);
    assert_ne!(a, c);

    let mut set = HashSet::new();
    set.insert(a);
    set.insert(b);
    set.insert(c);
    assert_eq!(set.len(), 2, "equal ids must hash to the same bucket");

    assert!(a < c, "ids are ordered by their bytes");
}

// --- Signature -----------------------------------------------------------

#[test]
fn signature_roundtrips_and_displays_as_hex() {
    let bytes = [0xab; 64];
    let sig = Signature::from_bytes(bytes);
    assert_eq!(sig.as_bytes(), &bytes);
    assert_eq!(sig.to_string(), "ab".repeat(64));
    assert_eq!(sig, Signature::from_bytes(bytes));
    assert_ne!(sig, Signature::from_bytes([0xaa; 64]));
}

// --- PublicIdentity ------------------------------------------------------

#[test]
fn public_identity_exposes_all_three_parts() {
    let signing = [0x11; 32];
    let agreement = [0x22; 32];
    let binding = Signature::from_bytes([0x33; 64]);
    let public = PublicIdentity::new(signing, agreement, binding);

    assert_eq!(public.signing_pk(), &signing);
    assert_eq!(public.agreement_pk(), &agreement);
    assert_eq!(public.agreement_binding(), &binding);

    // Public data: Debug shows it (unlike SecretIdentity).
    let debug = format!("{public:?}");
    assert!(
        debug.contains(&"11".repeat(32)),
        "signing key visible: {debug}"
    );
    assert!(
        debug.contains(&"22".repeat(32)),
        "agreement key visible: {debug}"
    );

    // Equality covers all three parts.
    assert_eq!(public, PublicIdentity::new(signing, agreement, binding));
    assert_ne!(
        public,
        PublicIdentity::new(signing, [0x23; 32], binding),
        "a substituted agreement key must not compare equal"
    );
}

// --- SecretIdentity ------------------------------------------------------

#[test]
fn secret_identity_debug_is_redacted() {
    let secret = SecretIdentity::from_parts([0xab; 32], [0xcd; 32]);
    let debug = format!("{secret:?}");

    assert!(debug.contains("<redacted>"), "marker missing: {debug}");
    // No key material, in any encoding, may appear in Debug output.
    assert!(!debug.contains("ab"), "signing key leaked: {debug}");
    assert!(
        !debug.contains("171"),
        "signing key leaked as decimal: {debug}"
    );
    assert!(!debug.contains("cd"), "agreement key leaked: {debug}");
    assert!(
        !debug.contains("205"),
        "agreement key leaked as decimal: {debug}"
    );
}

#[test]
fn secret_identity_clone_is_explicit_and_correct() {
    let secret = SecretIdentity::from_parts([0x42; 32], [0x43; 32]);
    // The type is Clone (deliberately) and clones compare equal.
    let cloned = secret.clone();
    assert_eq!(secret, cloned);
    // The original still works after the clone dropped (no shared state).
    drop(cloned);
    assert_eq!(secret, SecretIdentity::from_parts([0x42; 32], [0x43; 32]));
}

#[test]
fn secret_identity_zeroizes_on_explicit_zeroize() {
    let mut secret = SecretIdentity::from_parts([0xaa; 32], [0xbb; 32]);
    assert_ne!(secret, SecretIdentity::from_parts([0; 32], [0; 32]));

    secret.zeroize();

    // Observable through the constant-time PartialEq against the zero value:
    // both fields are gone, not just one.
    assert_eq!(secret, SecretIdentity::from_parts([0; 32], [0; 32]));
}

#[test]
fn secret_identity_equality_checks_both_fields() {
    let base = SecretIdentity::from_parts([1; 32], [2; 32]);

    assert_eq!(base, SecretIdentity::from_parts([1; 32], [2; 32]));
    assert_ne!(
        base,
        SecretIdentity::from_parts([9; 32], [2; 32]),
        "differing signing key must differ"
    );
    assert_ne!(
        base,
        SecretIdentity::from_parts([1; 32], [9; 32]),
        "differing agreement key must differ"
    );
    assert_ne!(
        base,
        SecretIdentity::from_parts([9; 32], [9; 32]),
        "differing in both must differ"
    );
}

#[test]
fn secret_identity_debug_is_redacted_in_collections() {
    // Regression guard for the done-when: the Debug of a *collection* of
    // secrets must not print contents either. (No `Hash` impl on purpose:
    // hashing secret material in a map is exactly the habit to avoid.)
    let secrets = vec![SecretIdentity::from_parts([7; 32], [8; 32])];
    let debug = format!("{secrets:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("07"));
    assert!(!debug.contains("08"));
}

// --- Properties ----------------------------------------------------------

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
    fn node_id_from_arbitrary_bytes_roundtrips(bytes in prop::array::uniform16(any::<u8>())) {
        let id = NodeId::from_bytes(bytes);
        prop_assert_eq!(id.as_bytes(), &bytes);
        prop_assert_eq!(NodeId::from_bytes(*id.as_bytes()), id);
        prop_assert_eq!(id.to_string().len(), 32);
    }

    #[test]
    fn signature_from_arbitrary_bytes_roundtrips(
        bytes in proptest::collection::vec(any::<u8>(), 64..=64),
    ) {
        let bytes: [u8; 64] = bytes.try_into().expect("strategy yields exactly 64 bytes");
        let sig = Signature::from_bytes(bytes);
        prop_assert_eq!(sig.as_bytes(), &bytes);
        prop_assert_eq!(sig.to_string().len(), 128);
    }

    #[test]
    fn every_suite_byte_decodes_or_is_rejected(byte in any::<u8>()) {
        match SuiteId::try_from(byte) {
            Ok(suite) => prop_assert_eq!(suite.byte(), byte),
            Err(err) => prop_assert_eq!(err, IdentError::UnknownSuite(byte)),
        }
    }

    #[test]
    fn secret_identity_zeroizes_arbitrary_keys(
        signing in prop::array::uniform32(any::<u8>()),
        agreement in prop::array::uniform32(any::<u8>()),
    ) {
        let mut secret = SecretIdentity::from_parts(signing, agreement);
        prop_assert!(secret != SecretIdentity::from_parts([0; 32], [0; 32]));
        secret.zeroize();
        prop_assert!(secret == SecretIdentity::from_parts([0; 32], [0; 32]));
    }

    #[test]
    fn secret_identity_equality_matches_byte_equality(
        a1 in prop::array::uniform32(any::<u8>()),
        a2 in prop::array::uniform32(any::<u8>()),
        b1 in prop::array::uniform32(any::<u8>()),
        b2 in prop::array::uniform32(any::<u8>()),
    ) {
        let s1 = SecretIdentity::from_parts(a1, a2);
        let s2 = SecretIdentity::from_parts(b1, b2);
        prop_assert_eq!(s1 == s2, (a1, a2) == (b1, b2));
    }
}
