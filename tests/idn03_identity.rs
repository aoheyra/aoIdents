//! IDN-03: identity generation and derivation.
//!
//! The done-when is known-answer tests: a fixed seed must reproduce
//! identical keys and `NodeId`. The key and signature vectors were derived
//! independently with Python's `cryptography` library (HKDF-SHA-256
//! hand-implemented per RFC 5869), so they validate this crate's
//! implementation rather than merely pinning it. The `NodeId` formula is
//! re-derived inside the tests through the `blake3` crate directly, on a
//! path separate from `src/identity.rs`.

mod common;

use ao_idents::{Identity, PublicIdentity, SuiteId};
use common::TestRng;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// ADR-0001 bind-agreement domain (registry in `docs/adr/0001`).
const DOMAIN_BIND_AGREEMENT: &str = "aoheyra/idn/v1/bind-agreement";
/// ADR-0001 NodeId domain (registry in `docs/adr/0001`).
const DOMAIN_NODE_ID: &str = "aoheyra/idn/v1/node-id";
/// ADR-0001 suite byte.
const SUITE_BYTE: u8 = 0x01;

/// Independently built signature preimage: `u8 len ‖ domain ‖ msg`.
fn preimage(domain: &str, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(domain.len() as u8);
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(msg);
    out
}

/// Recompute `NodeId` from the ADR-0001 formula, independent of the crate.
fn node_id_formula(signing_pk: &[u8; 32], agreement_pk: &[u8; 32]) -> [u8; 16] {
    let mut input = Vec::new();
    input.extend_from_slice(DOMAIN_NODE_ID.as_bytes());
    input.push(SUITE_BYTE);
    input.extend_from_slice(signing_pk);
    input.extend_from_slice(agreement_pk);
    let digest = blake3::hash(&input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

/// Verify the bind-agreement binding with `verify_strict`, independently.
fn binding_verifies(public: &PublicIdentity) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public.signing_pk()) else {
        return false;
    };
    let sig = DalekSignature::from_bytes(public.agreement_binding().as_bytes());
    let msg = preimage(DOMAIN_BIND_AGREEMENT, public.agreement_pk());
    vk.verify_strict(&msg, &sig).is_ok()
}

// --- Known-answer vectors ------------------------------------------------
//
// Provenance: derived once with Python 3 (`cryptography` 50.0.2) from the
// ADR-0001 formulas - HKDF-SHA-256 per RFC 5869 with salt = 0x01, Ed25519
// and X25519 via `cryptography` - independent of this crate's code. The
// crate must reproduce them byte for byte.

#[test]
fn known_answer_vector_seed_00_to_1f() {
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8); // 00..1f
    let id = Identity::from_seed(seed);

    let public = id.public();
    assert_eq!(
        hex(public.signing_pk()),
        "c540b0e73e947743a01644396f5850ff721d69f6bd1102c0fc10009843cd1364",
        "Ed25519 public key must match the independent derivation"
    );
    assert_eq!(
        hex(public.agreement_pk()),
        "bee2107e38fb71bac12f862883c49f6481218150c079c1a15988be585e991d31",
        "X25519 public key must match the independent derivation"
    );
    assert_eq!(
        hex(public.agreement_binding().as_bytes()),
        "f7b8cca6143e0e83bd49d8b5d5982d79f67e478bd90a02ef8b1d4587854c25c8\
         621ac83a7cee6435dc8f3a1397c559d11d8d1d9b46ef652414f6f473a5ac1a0a",
        "bind-agreement signature must match the independent derivation"
    );
    assert!(binding_verifies(public), "binding must verify");

    // NodeId: formula re-derived here, plus a pinned regression value.
    assert_eq!(
        id.node_id().as_bytes(),
        &node_id_formula(public.signing_pk(), public.agreement_pk()),
        "NodeId must follow the ADR-0001 formula"
    );
    assert_eq!(
        id.node_id().to_string(),
        "c654a1bff55e8463e41348176bd99b8d",
        "NodeId regression value"
    );
    assert_eq!(id.suite(), SuiteId::V1);
}

#[test]
fn known_answer_vector_seed_42() {
    let id = Identity::from_seed([0x42; 32]);
    let public = id.public();

    assert_eq!(
        hex(public.signing_pk()),
        "e93b52b201281b555f808b0f4315cc1f4e2a97dc17398d99271e7ed7965f03b5"
    );
    assert_eq!(
        hex(public.agreement_pk()),
        "26aca711046544f1c3d47fba51cd947624cd7414e7ed8d6dd3646b8ac3d63c0f"
    );
    assert_eq!(
        hex(public.agreement_binding().as_bytes()),
        "89667b95b2ee08040d7da5a4a654453fb8249d530b91af78cd614a7c404152c5\
         f56b608e00cc03420f0812b61c4f253341c0cd73fd0e4434a247c2261aee3209"
    );
    assert!(binding_verifies(public));
    assert_eq!(
        id.node_id().as_bytes(),
        &node_id_formula(public.signing_pk(), public.agreement_pk())
    );
}

// --- Derivation properties ------------------------------------------------

#[test]
fn from_seed_is_deterministic() {
    let a = Identity::from_seed([7; 32]);
    let b = Identity::from_seed([7; 32]);

    assert_eq!(a.node_id(), b.node_id());
    assert_eq!(a.public(), b.public());
}

#[test]
fn single_bit_seed_change_changes_the_whole_identity() {
    let mut seed = [7u8; 32];
    let a = Identity::from_seed(seed);
    seed[0] ^= 0x01;
    let b = Identity::from_seed(seed);

    assert_ne!(a.node_id(), b.node_id());
    assert_ne!(a.public().signing_pk(), b.public().signing_pk());
    assert_ne!(a.public().agreement_pk(), b.public().agreement_pk());
}

#[test]
fn distinct_hkdf_labels_produce_distinct_keys() {
    // If the two HKDF labels ever collided, the known-answer vectors
    // above would already fail (they pin each key against an independent
    // derivation). This adds the direct property: the two public keys of
    // one identity are never equal.
    let id = Identity::from_seed([9; 32]);
    assert_ne!(id.public().signing_pk(), id.public().agreement_pk());
}

#[test]
fn node_id_hashes_both_public_keys() {
    // Two identities sharing a signing key but differing in the agreement
    // key must still get different NodeIds: both keys feed the hash.
    let a = Identity::from_seed([1; 32]);
    let mut seed_b = [1u8; 32];
    seed_b[31] ^= 0x01;
    let b = Identity::from_seed(seed_b);

    assert_ne!(
        a.node_id().as_bytes(),
        &node_id_formula(a.public().signing_pk(), b.public().agreement_pk()),
        "a NodeId must not be reinterpretable under different key material"
    );
    assert_ne!(a.node_id(), b.node_id());
}

#[test]
fn binding_detects_a_substituted_agreement_key() {
    let id = Identity::from_seed([3; 32]);
    let substituted = PublicIdentity::new(
        *id.public().signing_pk(),
        [0xEE; 32], // attacker-swapped agreement key
        *id.public().agreement_binding(),
    );

    assert!(
        !binding_verifies(&substituted),
        "a substituted agreement key must fail the bind-agreement check"
    );
}

#[test]
fn binding_fails_for_a_foreign_signing_key() {
    let id = Identity::from_seed([3; 32]);
    let other = Identity::from_seed([4; 32]);
    let swapped = PublicIdentity::new(
        *other.public().signing_pk(),
        *id.public().agreement_pk(),
        *id.public().agreement_binding(),
    );

    assert!(!binding_verifies(&swapped));
}

#[test]
fn identity_debug_redacts_the_secret_but_shows_public_parts() {
    let id = Identity::from_seed([0xAB; 32]);
    let debug = format!("{id:?}");

    assert!(
        debug.contains("secret: SecretIdentity(<redacted>)"),
        "secret must be redacted: {debug}"
    );
    // Public material stays visible for debugging.
    assert!(debug.contains(&hex(id.public().signing_pk())));
    assert!(debug.contains(&id.node_id().to_string()));
}

// --- generate ------------------------------------------------------------

#[test]
fn generate_is_deterministic_for_the_same_rng_state() {
    let a = Identity::generate(&mut TestRng::new(0xDEAD));
    let b = Identity::generate(&mut TestRng::new(0xDEAD));

    assert_eq!(a.node_id(), b.node_id());
    assert_eq!(a.public(), b.public());
}

#[test]
fn generate_differs_for_different_rng_states() {
    let a = Identity::generate(&mut TestRng::new(1));
    let b = Identity::generate(&mut TestRng::new(2));

    assert_ne!(a.node_id(), b.node_id());
}

#[test]
fn generate_consumes_exactly_the_replayable_seed() {
    // generate(rng) must be exactly from_seed(seed) for the bytes the rng
    // produced - no hidden entropy, no reordering.
    let state = 0xCAFE;
    let generated = Identity::generate(&mut TestRng::new(state));

    let seed = common::seed_of(state, 32);
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let replayed = Identity::from_seed(seed_arr);

    assert_eq!(generated.node_id(), replayed.node_id());
    assert_eq!(generated.public(), replayed.public());
}

// --- Properties ----------------------------------------------------------

fn proptest_config_for_runtime() -> proptest::test_runner::Config {
    let default = proptest::test_runner::Config::default();
    proptest::test_runner::Config {
        // Miri isolation disallows cwd access used by proptest's default
        // file-backed persistence, so disable persistence there.
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
    fn arbitrary_seed_never_panics_and_is_deterministic(seed in prop::array::uniform32(any::<u8>())) {
        let a = Identity::from_seed(seed);
        let b = Identity::from_seed(seed);
        prop_assert_eq!(a.node_id(), b.node_id());
        prop_assert_eq!(a.public(), b.public());
        prop_assert_eq!(a.node_id().to_string().len(), 32);
    }

    #[test]
    fn node_id_formula_holds_for_arbitrary_seeds(seed in prop::array::uniform32(any::<u8>())) {
        let id = Identity::from_seed(seed);
        let node_id = id.node_id();
        prop_assert_eq!(
            node_id.as_bytes(),
            &node_id_formula(id.public().signing_pk(), id.public().agreement_pk())
        );
    }

    #[test]
    fn single_bit_seed_flip_always_changes_node_id(
        seed in prop::array::uniform32(any::<u8>()),
        index in 0usize..32,
        bit in 0u8..8,
    ) {
        let mut flipped = seed;
        flipped[index] ^= 1 << bit;
        prop_assert_ne!(Identity::from_seed(seed).node_id(), Identity::from_seed(flipped).node_id());
    }

    #[test]
    fn binding_verifies_for_every_generated_identity(state in any::<u64>()) {
        let id = Identity::generate(&mut TestRng::new(state));
        prop_assert!(binding_verifies(id.public()));
        prop_assert_eq!(id.suite(), SuiteId::V1);
    }

    #[test]
    fn binding_fails_for_any_bit_flip_in_the_binding(state in any::<u64>(), index in 0usize..64, bit in 0u8..8) {
        let id = Identity::generate(&mut TestRng::new(state));
        let mut bytes = *id.public().agreement_binding().as_bytes();
        bytes[index] ^= 1 << bit;
        let tampered = PublicIdentity::new(
            *id.public().signing_pk(),
            *id.public().agreement_pk(),
            ao_idents::Signature::from_bytes(bytes),
        );
        prop_assert!(!binding_verifies(&tampered));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
