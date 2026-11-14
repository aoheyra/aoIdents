//! Context-separated sign and verify (IDN-04).
//!
//! Covers the done-when (a signature under one context never verifies
//! under another; malleability cases) plus every new `IdentError` variant
//! and the class of hostile inputs: bad domains, weak keys, tampered
//! signatures and messages, and the classic `s + L` malleation.

mod common;

use ao_idents::{IdentError, Identity, PublicIdentity, Signature};
use common::TestRng;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// Registered ADR-0001 domains, used as distinct contexts here.
const CTX: &str = "aoheyra/idn/v1/msg";
const OTHER_CTX: &str = "aoheyra/idn/v1/blob";
const BIND_CTX: &str = "aoheyra/idn/v1/bind-agreement";

/// Group order `L` of Ed25519, little-endian bytes. `s + L` is a valid
/// group element encoding-wise but non-canonical: strict verification
/// must reject it (RFC 8032, section 5.1.7).
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

/// `s += L` over the little-endian 32 bytes of a signature's `s`.
fn add_l(s: &mut [u8]) {
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(s[i]) + u16::from(L_LE[i]) + carry;
        s[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "canonical s + L fits in 32 bytes");
}

/// Does `domain` satisfy the crate's validation rule?
fn domain_valid(domain: &str) -> bool {
    !domain.is_empty() && domain.len() <= 255 && domain.is_ascii() && !domain.contains('\0')
}

// --- Round trip ----------------------------------------------------------

#[test]
fn sign_and_verify_roundtrip() {
    let id = identity(1);
    let sig = id.sign(CTX, b"hello mesh").expect("registered domain");
    assert!(id.public().verify(CTX, b"hello mesh", &sig).is_ok());
}

#[test]
fn sign_is_deterministic() {
    let id = identity(2);
    let a = id.sign(CTX, b"same input").expect("registered domain");
    let b = id.sign(CTX, b"same input").expect("registered domain");
    assert_eq!(a, b, "Ed25519 signing is deterministic");
}

#[test]
fn empty_message_roundtrips() {
    let id = identity(3);
    let sig = id.sign(CTX, b"").expect("registered domain");
    assert!(id.public().verify(CTX, b"", &sig).is_ok());
    assert_eq!(
        id.public().verify(OTHER_CTX, b"", &sig),
        Err(IdentError::InvalidSignature)
    );
}

#[test]
fn sign_reproduces_the_bind_agreement_binding() {
    // sign() and the from_seed binding must use the same key and the same
    // preimage, byte for byte.
    let id = Identity::from_seed([5; 32]);
    let mine = id
        .sign(BIND_CTX, id.public().agreement_pk())
        .expect("registered domain");
    assert_eq!(mine, *id.public().agreement_binding());
}

/// Known-answer vector, independently derived with Python 3
/// (`cryptography` 50.0.2) from the ADR-0001 formulas: HKDF-SHA-256
/// (RFC 5869, salt `0x01`) for the signing key from seed `07` x32,
/// then Ed25519 over the length-prefixed preimage. Independent of this
/// crate's code; the crate must reproduce it byte for byte.
#[test]
fn known_answer_signature_vector() {
    let id = Identity::from_seed([7u8; 32]);
    let msg = b"aoheyra known-answer message";
    let sig = id.sign(CTX, msg).expect("registered domain");
    assert_eq!(
        hex(sig.as_bytes()),
        "335ba8bf3c6a350ebb3581700e901f0200f389801a36e238a112e15586989786\
         2947af55621a861164fc735a6ca01474abc57681b2e2cb1128a3532f0911bb09",
        "signature must match the independent derivation"
    );
    assert!(id.public().verify(CTX, msg, &sig).is_ok());
    assert_eq!(
        id.public().verify(OTHER_CTX, msg, &sig),
        Err(IdentError::InvalidSignature)
    );
}

/// `hex` for the known-answer vectors above.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- Context separation (the done-when) ----------------------------------

#[test]
fn signature_under_one_context_never_verifies_under_another() {
    let id = identity(4);
    let sig = id.sign(CTX, b"payload").expect("registered domain");

    assert_eq!(
        id.public().verify(OTHER_CTX, b"payload", &sig),
        Err(IdentError::InvalidSignature),
        "a msg-domain signature must not verify as a blob-domain signature"
    );
}

#[test]
fn domain_length_prefix_prevents_prefix_confusion() {
    // preimage("ab", M) = [2, 'a', 'b', M] and preimage("a", 'b'‖M) =
    // [1, 'a', 'b', M]: the length byte keeps them distinct even though
    // the tails are identical.
    let id = identity(5);
    let sig = id.sign("ab", b"MESSAGE").expect("valid domain");

    assert_eq!(
        id.public().verify("a", b"bMESSAGE", &sig),
        Err(IdentError::InvalidSignature),
        "a shorter domain plus a shifted message must not collide"
    );
    assert!(id.public().verify("ab", b"MESSAGE", &sig).is_ok());
}

#[test]
fn binding_verifies_through_the_public_api() {
    let id = identity(6);
    assert!(id.public().verify_binding().is_ok());

    let substituted = PublicIdentity::new(
        *id.public().signing_pk(),
        [0xEE; 32],
        *id.public().agreement_binding(),
    );
    assert_eq!(
        substituted.verify_binding(),
        Err(IdentError::InvalidSignature),
        "a substituted agreement key must fail verify_binding"
    );
}

// --- Tampering and malleability ------------------------------------------

#[test]
fn tampered_message_is_rejected() {
    let id = identity(7);
    let sig = id.sign(CTX, b"original").expect("registered domain");

    let mut msg = *b"original";
    msg[0] ^= 0x01;
    assert_eq!(
        id.public().verify(CTX, &msg, &sig),
        Err(IdentError::InvalidSignature)
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let id = identity(8);
    let sig = id.sign(CTX, b"payload").expect("registered domain");

    // Every region of the signature: R half, s half, first and last byte.
    for index in [0usize, 31, 32, 63] {
        let mut bytes = *sig.as_bytes();
        bytes[index] ^= 0x01;
        assert_eq!(
            id.public()
                .verify(CTX, b"payload", &Signature::from_bytes(bytes)),
            Err(IdentError::InvalidSignature),
            "flip at byte {index} must be rejected"
        );
    }
}

#[test]
fn malleable_s_plus_l_is_rejected() {
    // Same R, s' = s + L: valid group arithmetic, non-canonical encoding.
    // Accepting it would break signature uniqueness (RFC 8032).
    let id = identity(9);
    let sig = id.sign(CTX, b"malleate me").expect("registered domain");

    let mut bytes = *sig.as_bytes();
    let (_r, s) = bytes.split_at_mut(32);
    add_l(s);

    assert_eq!(
        id.public()
            .verify(CTX, b"malleate me", &Signature::from_bytes(bytes)),
        Err(IdentError::InvalidSignature),
        "s + L must be rejected as non-canonical"
    );
}

#[test]
fn signature_from_a_different_identity_is_rejected() {
    let signer = identity(10);
    let other = identity(11);
    let sig = signer.sign(CTX, b"payload").expect("registered domain");

    assert_eq!(
        other.public().verify(CTX, b"payload", &sig),
        Err(IdentError::InvalidSignature)
    );
}

// --- Domain validation (every IdentError variant triggered) --------------

#[test]
fn invalid_domains_are_typed_errors_never_panics() {
    let id = identity(12);
    let sig = id.sign(CTX, b"m").expect("registered domain");

    let bad_domains: [&str; 5] = [
        "",                         // empty
        "a\0b",                     // NUL
        "é",                        // non-ASCII (2 bytes)
        "aoheyra/idn/v1/\u{1F600}", // emoji: non-ASCII
        &"x".repeat(256),           // over the one-byte length prefix
    ];
    for domain in bad_domains {
        assert_eq!(
            id.sign(domain, b"m"),
            Err(IdentError::InvalidDomain),
            "sign must reject domain {domain:?}"
        );
        assert_eq!(
            id.public().verify(domain, b"m", &sig),
            Err(IdentError::InvalidDomain),
            "verify must reject domain {domain:?}"
        );
    }
}

#[test]
fn domain_length_boundary_255_ok_256_rejected() {
    let id = identity(13);

    let max_ok = "a".repeat(255);
    let sig = id.sign(&max_ok, b"m").expect("255 bytes fit the prefix");
    assert!(id.public().verify(&max_ok, b"m", &sig).is_ok());

    let too_long = "a".repeat(256);
    assert_eq!(id.sign(&too_long, b"m"), Err(IdentError::InvalidDomain));
}

#[test]
fn garbage_public_key_is_rejected() {
    let id = identity(14);
    let sig = id.sign(CTX, b"payload").expect("registered domain");

    // y = 2: the curve equation has no square root for this y, so the key
    // fails point decompression and never reaches verification.
    let mut garbage_bytes = [0u8; 32];
    garbage_bytes[0] = 2;
    let garbage = PublicIdentity::new(garbage_bytes, [0; 32], sig);
    assert_eq!(
        garbage.verify(CTX, b"payload", &sig),
        Err(IdentError::InvalidPublicKey)
    );
}

#[test]
fn small_order_public_key_is_rejected() {
    // The canonical encoding of the identity point (y = 1, sign = 0):
    // order-1, hence small order - a key that would "verify" almost any
    // message if it slipped through.
    let id = identity(15);
    let sig = id.sign(CTX, b"payload").expect("registered domain");

    let mut weak_bytes = [0u8; 32];
    weak_bytes[0] = 1;
    let weak = PublicIdentity::new(weak_bytes, [0; 32], sig);
    assert_eq!(
        weak.verify(CTX, b"payload", &sig),
        Err(IdentError::InvalidPublicKey),
        "small-order keys must be rejected before verification"
    );
}

// --- Properties ----------------------------------------------------------

/// A domain from arbitrary bytes: exercises empty, NUL, over-long ASCII
/// and non-ASCII cases through `from_utf8_lossy`.
fn any_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 0..=300)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// A registered-looking domain: 1..=64 bytes of the ADR namespace shape.
fn valid_domain() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z0-9/_-]{1,64}")
        .expect("regex is a valid regular expression")
}

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
    fn roundtrip_for_arbitrary_messages(msg in proptest::collection::vec(any::<u8>(), 0..512)) {
        let id = identity(20);
        let sig = id.sign(CTX, &msg).expect("registered domain");
        prop_assert!(id.public().verify(CTX, &msg, &sig).is_ok());
    }

    #[test]
    fn roundtrip_for_arbitrary_valid_domains(ctx in valid_domain(), msg in proptest::collection::vec(any::<u8>(), 0..64)) {
        let id = identity(21);
        prop_assert!(domain_valid(&ctx));
        let sig = id.sign(&ctx, &msg).expect("strategy yields a valid domain");
        prop_assert!(id.public().verify(&ctx, &msg, &sig).is_ok());
    }

    #[test]
    fn acceptance_of_sign_matches_the_validation_rule(domain in any_domain()) {
        // sign() must accept exactly the domains it documents - never
        // more (silent truncation) and never less (spurious rejection).
        let id = identity(22);
        let result = id.sign(&domain, b"m");
        match result {
            Ok(_) => prop_assert!(domain_valid(&domain)),
            Err(err) => {
                prop_assert_eq!(err, IdentError::InvalidDomain);
                prop_assert!(!domain_valid(&domain));
            }
        }
    }

    #[test]
    fn any_single_bit_signature_flip_is_rejected(
        index in 0usize..64,
        bit in 0u8..8,
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let id = identity(23);
        let sig = id.sign(CTX, &msg).expect("registered domain");
        let mut bytes = *sig.as_bytes();
        bytes[index] ^= 1 << bit;
        prop_assert_eq!(
            id.public().verify(CTX, &msg, &Signature::from_bytes(bytes)),
            Err(IdentError::InvalidSignature)
        );
    }

    #[test]
    fn arbitrary_signature_bytes_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 64..=64),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let id = identity(24);
        let bytes: [u8; 64] = bytes.try_into().expect("strategy yields 64 bytes");
        // Whatever the bytes are: a typed result, never a panic.
        let _ = id.public().verify(CTX, &msg, &Signature::from_bytes(bytes));
    }

    #[test]
    fn arbitrary_public_keys_never_panic(
        signing in proptest::collection::vec(any::<u8>(), 32..=32),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let id = identity(25);
        let signing: [u8; 32] = signing.try_into().expect("strategy yields 32 bytes");
        let sig = id.sign(CTX, &msg).expect("registered domain");
        let candidate = PublicIdentity::new(signing, [0; 32], sig);
        // Typed result for every key material, never a panic.
        let _ = candidate.verify(CTX, &msg, &sig);
    }

    #[test]
    fn message_tamper_after_signing_is_always_rejected(
        index in 0usize..64,
        bit in 0u8..8,
        msg in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let id = identity(26);
        let sig = id.sign(CTX, &msg).expect("registered domain");
        let mut tampered = msg.clone();
        let at = index % tampered.len();
        tampered[at] ^= 1 << bit;
        prop_assert_eq!(
            id.public().verify(CTX, &tampered, &sig),
            Err(IdentError::InvalidSignature)
        );
    }
}
