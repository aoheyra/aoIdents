//! IDN-20: ADR-0002 handle document and derivation vector.
//!
//! This issue ships a decision document, not production code, so the tests
//! do two jobs: they pin the ADR's exact rules (a silent rule edit fails
//! here until the tests are updated deliberately), and they recompute the
//! ADR's worked example from the documented formula, which is what a later
//! implementation must reproduce.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// The full ADR text, compiled in.
const ADR: &str = include_str!("../docs/adr/0002-username-handle-and-unique-number.md");

/// ADR-0001's domain registry, for the cross-document check.
const ADR_0001: &str = include_str!("../docs/adr/0001-crypto-suite-and-encodings.md");

/// Domain string from ADR-0002 (registered in ADR-0001's domain table).
const DOMAIN: &str = "aoheyra/idn/v1/handle";

/// The worked-example NodeId from ADR-0002: bytes `0x00`..`0x0f`.
const EXAMPLE_NODE_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// The modulus: `10^12`, the 12-digit space.
const MODULUS: u128 = 1_000_000_000_000;

/// Derive the handle number exactly as ADR-0002 specifies:
/// `D = BLAKE3(NodeId || domain)`, `D[0..16]` big-endian `u128`,
/// `value mod 10^12`.
fn handle_number(node_id: &[u8; 16]) -> u128 {
    let mut input = Vec::with_capacity(16 + DOMAIN.len());
    input.extend_from_slice(node_id);
    input.extend_from_slice(DOMAIN.as_bytes());

    let digest = blake3::hash(&input);
    let mut head = [0u8; 16];
    head.copy_from_slice(&digest.as_bytes()[..16]);

    u128::from_be_bytes(head) % MODULUS
}

/// Zero-padded 12-digit rendering of the number.
fn handle_number_str(node_id: &[u8; 16]) -> String {
    format!("{:012}", handle_number(node_id))
}

// --- The ADR pins these rules --------------------------------------------

#[test]
fn adr_specifies_the_format_and_charset() {
    assert!(
        ADR.contains("`username#NNNNNNNNNNNN`"),
        "handle format must be documented"
    );
    assert!(ADR.contains("charset `[a-z0-9_]`"), "charset must be exact");
    assert!(ADR.contains("3..20 characters"), "username length rule");
    assert!(
        ADR.contains("exactly 12 decimal digits, zero-padded"),
        "number rule"
    );
    assert!(
        ADR.contains("must start with a letter"),
        "first-character rule"
    );
}

#[test]
fn adr_specifies_the_derivation_input_exactly() {
    assert!(
        ADR.contains(r#"D = BLAKE3(NodeId || "aoheyra/idn/v1/handle")"#),
        "derivation formula must be byte-exact"
    );
    assert!(
        ADR.contains("raw 16-byte value"),
        "NodeId enters as bytes, not hex"
    );
    assert!(ADR.contains("big-endian"), "byte order must be pinned");
    assert!(ADR.contains("value mod 10^12"), "modulus must be pinned");
}

#[test]
fn adr_domain_is_registered_in_adr_0001() {
    // Cross-document sync: the derivation domain must exist in the
    // ADR-0001 registry, not only here.
    assert!(
        ADR_0001.contains(DOMAIN),
        "ADR-0001's domain table must list {DOMAIN}"
    );
}

#[test]
fn adr_specifies_pair_uniqueness_and_the_three_search_modes() {
    assert!(
        ADR.contains("unique key is the pair `(username, number)`"),
        "pair is the unique key"
    );
    assert!(ADR.contains("by username only"), "search mode 1");
    assert!(ADR.contains("by number only"), "search mode 2");
    assert!(
        ADR.contains("by the combination"),
        "search mode 3: username + number"
    );
    assert!(
        ADR.contains("Three search modes only"),
        "no further modes may be added silently"
    );
    assert!(
        ADR.contains("birthday bound"),
        "the number-only limitation must stay documented"
    );
}

#[test]
fn adr_specifies_reserved_names_case_rules_and_length_floor() {
    for reserved in ["admin", "root", "system", "official", "aoheyra"] {
        assert!(ADR.contains(reserved), "reserved name {reserved} listed");
    }
    assert!(ADR.contains("canonical username is lowercase"), "case rule");
    assert!(
        ADR.contains("rejects uppercase rather than folding"),
        "no silent folding"
    );
    assert!(
        ADR.contains("Minimum length 3"),
        "length floor with rationale"
    );
}

#[test]
fn adr_specifies_where_the_handle_appears() {
    assert!(
        ADR.contains("signed **IdentityCard** payload"),
        "handle inside the signed card"
    );
    assert!(ADR.contains("QR card"), "handle on the QR card");
    assert!(ADR.contains("**in-app**"), "handle in the app");
    assert!(
        ADR.contains("Never a security boundary"),
        "display-level caveat stays"
    );
}

// --- Worked example -------------------------------------------------------

#[test]
fn worked_example_matches_the_documented_formula() {
    let handle = format!("alice#{}", handle_number_str(&EXAMPLE_NODE_ID));
    assert!(
        ADR.contains(&handle),
        "ADR-0002's worked example must be the documented formula's output; \
         expected the document to contain {handle}"
    );
}

// --- Properties of the derivation ----------------------------------------

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
    fn number_is_exactly_12_digits_for_arbitrary_node_ids(
        node_id in prop::array::uniform16(any::<u8>()),
    ) {
        let number = handle_number(&node_id);
        prop_assert!(number < MODULUS, "must be inside the 10^12 space");
        let rendered = handle_number_str(&node_id);
        prop_assert_eq!(rendered.len(), 12);
        prop_assert!(rendered.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn derivation_is_deterministic(node_id in prop::array::uniform16(any::<u8>())) {
        prop_assert_eq!(handle_number(&node_id), handle_number(&node_id));
        prop_assert_eq!(handle_number_str(&node_id), handle_number_str(&node_id));
    }

    #[test]
    fn number_is_sensitive_to_the_node_id(
        node_id in prop::array::uniform16(any::<u8>()),
        index in 0usize..16,
        bit in 0u8..8,
    ) {
        // Guards against a future implementation hashing nothing (or the
        // wrong input): a one-bit NodeId flip must move the number. A
        // random collision inside 10^12 has probability 10^-12 per case.
        let mut flipped = node_id;
        flipped[index] ^= 1 << bit;
        prop_assert_ne!(handle_number(&node_id), handle_number(&flipped));
    }
}
