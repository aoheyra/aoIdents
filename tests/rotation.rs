//! Key rotation and revocation (IDN-16).
//!
//! Covers the done-when: a contact follows a valid rotation
//! automatically and rejects an unsigned one. Plus the statement and
//! notice codecs, the self-rotation refusal, blocked-not-deleted
//! revocation, the full-book atomicity of a rotation and the hostile
//! store's defensive arm.

mod common;

use ao_idents::{
    Contact, ContactBook, ContactStore, IdentError, Identity, MemoryContactStore, NodeId,
    RevocationNotice, RotationStatement, Trust,
};
use common::TestRng;

/// The rotation encoding is fixed: suite + four keys + two signatures.
const ROTATION_LEN: usize = 1 + 4 * 32 + 2 * 64;

/// The revocation encoding is fixed: suite + two keys + signature.
const REVOCATION_LEN: usize = 1 + 2 * 32 + 64;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn card(id: &Identity, name: &[u8]) -> ao_idents::IdentityCard {
    id.card(name, 1_700_000_000)
        .expect("name fits the card limit")
}

fn book_with(alice: &Identity) -> ContactBook<MemoryContactStore> {
    let mut book = ContactBook::new(MemoryContactStore::new());
    book.observe(alice.node_id(), &card(alice, b"alice"), 1_700_000_000)
        .expect("first use");
    book
}

/// A statement verifies, round-trips through its encoding, and its
/// derived ids are the identities it names.
#[test]
fn rotation_statement_signs_verifies_and_round_trips() {
    let old = identity(1);
    let new = identity(2);
    let statement = RotationStatement::sign(&old, &new).expect("distinct identities");
    statement.verify().expect("both keys signed");

    assert_eq!(statement.old_node_id(), old.node_id());
    assert_eq!(statement.new_node_id(), new.node_id());

    let encoded = statement.encode();
    assert_eq!(encoded.len(), ROTATION_LEN, "fixed layout");
    let decoded = RotationStatement::decode(&encoded).expect("round trip");
    assert_eq!(decoded, statement);
    decoded.verify().expect("survives the encoding");
}

/// The done-when, positive half: after a verified rotation the
/// contact is simply *there* under the successor id, carrying trust,
/// petname and history across; the old id is gone.
#[test]
fn a_contact_follows_a_valid_rotation_automatically() {
    let old = identity(1);
    let new = identity(2);
    let mut book = book_with(&old);
    book.set_trust(old.node_id(), Trust::Verified)
        .expect("known contact");
    book.set_petname(old.node_id(), Some("alice"))
        .expect("known contact");
    let first_seen = book.get(old.node_id()).expect("stored").first_seen();

    let statement = RotationStatement::sign(&old, &new).expect("distinct identities");
    let successor_id = book.rotate(&statement).expect("valid rotation");

    assert_eq!(successor_id, new.node_id());
    let successor = book.get(successor_id).expect("the contact followed");
    assert_eq!(successor.signing_pk(), new.public().signing_pk());
    assert_eq!(successor.agreement_pk(), new.public().agreement_pk());
    assert_eq!(successor.trust(), Trust::Verified, "trust follows");
    assert_eq!(successor.petname(), Some("alice"), "petname follows");
    assert_eq!(successor.first_seen(), first_seen, "history follows");
    assert!(book.get(old.node_id()).is_none(), "old id is gone");
}

/// The done-when, negative half: a statement whose signatures were
/// stripped is refused and changes nothing.
#[test]
fn an_unsigned_rotation_is_rejected() {
    let old = identity(1);
    let new = identity(2);
    let mut book = book_with(&old);

    let valid = RotationStatement::sign(&old, &new).expect("distinct identities");
    let encoded = valid.encode();

    // Both signature slots, separately: neither alone authorises the
    // succession.
    for (label, range) in [
        ("old signature stripped", 1 + 4 * 32..1 + 4 * 32 + 64),
        ("new signature stripped", 1 + 4 * 32 + 64..ROTATION_LEN),
    ] {
        let mut unsigned = encoded.clone();
        for byte in &mut unsigned[range.clone()] {
            *byte = 0;
        }
        let statement = RotationStatement::decode(&unsigned).expect("structure intact");
        let err = book.rotate(&statement).expect_err(label);
        assert!(
            matches!(err, IdentError::InvalidSignature),
            "{label}: wrong error: {err}"
        );
        assert!(
            book.get(old.node_id()).is_some(),
            "{label}: the contact must be untouched"
        );
        assert!(
            book.get(new.node_id()).is_none(),
            "{label}: nothing applied"
        );
    }
}

/// Rotating a contact onto itself is refused everywhere: at signing
/// time, at verification time (even for crafted bytes) and at the
/// book - applying it would delete the contact instead of migrating
/// it.
#[test]
fn a_rotation_onto_itself_is_refused() {
    let alice = identity(1);

    let err = RotationStatement::sign(&alice, &alice).expect_err("same identity");
    assert!(matches!(err, IdentError::InvalidRotation), "wrong: {err}");

    // Craft the degenerate statement from a valid one: the key slots
    // are unsigned until the signatures are checked, and the
    // consistency check runs first.
    let mut book = book_with(&alice);
    let encoded = RotationStatement::sign(&alice, &identity(2))
        .expect("distinct identities")
        .encode();
    let mut degenerate = encoded;
    let old_keys = degenerate[1..1 + 2 * 32].to_vec();
    degenerate[1 + 2 * 32..1 + 4 * 32].copy_from_slice(&old_keys);
    let statement = RotationStatement::decode(&degenerate).expect("structure intact");
    let err = statement.verify().expect_err("self-rotation");
    assert!(matches!(err, IdentError::InvalidRotation), "wrong: {err}");

    let err = book.rotate(&statement).expect_err("refused");
    assert!(matches!(err, IdentError::InvalidRotation), "wrong: {err}");
    assert!(
        book.get(alice.node_id()).is_some(),
        "the contact must survive the refusal"
    );
}

/// A rotation for someone we do not know is not an implicit create.
#[test]
fn a_rotation_for_an_unknown_contact_is_rejected() {
    let old = identity(1);
    let new = identity(2);
    let mut book = ContactBook::new(MemoryContactStore::new());

    let statement = RotationStatement::sign(&old, &new).expect("distinct identities");
    let err = book.rotate(&statement).expect_err("never met");
    assert!(matches!(err, IdentError::UnknownContact), "wrong: {err}");
    assert!(book.get(new.node_id()).is_none(), "nothing created");
}

/// A store that returns a contact for the wrong key - honest contacts
/// always hash to their own id, so only a broken store can reach this
/// arm - must not slip past: the chain has to meet what we know.
struct LyingStore {
    inner: MemoryContactStore,
    returned: Contact,
}

impl ContactStore for LyingStore {
    fn load(&self, _node_id: NodeId) -> Option<Contact> {
        Some(self.returned.clone())
    }

    fn save(&mut self, contact: Contact) -> Result<(), IdentError> {
        self.inner.save(contact)
    }

    fn delete(&mut self, node_id: NodeId) -> bool {
        self.inner.delete(node_id)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[test]
fn a_rotation_chaining_to_other_keys_is_rejected() {
    let old = identity(1);
    let impostor = identity(9);
    let store = LyingStore {
        inner: MemoryContactStore::new(),
        returned: Contact::from_card(&card(&impostor, b"mallory"), 1_700_000_000)
            .expect("verified card"),
    };
    let mut book = ContactBook::new(store);

    let statement = RotationStatement::sign(&old, &identity(2)).expect("distinct identities");
    let err = book.rotate(&statement).expect_err("chain meets other keys");
    assert!(
        matches!(err, IdentError::KeyChanged(_)),
        "wrong error: {err}"
    );
}

/// A rotation into a full book is refused without losing the old
/// contact: the successor is saved first, so failure leaves nothing
/// half-applied.
#[test]
fn a_full_book_keeps_the_old_contact_when_the_successor_does_not_fit() {
    let alice = identity(1);
    let mut book = book_with(&alice);
    for state in 100..100 + ao_idents::MAX_CONTACTS as u64 - 1 {
        let other = identity(state);
        book.observe(other.node_id(), &card(&other, b"other"), 1_700_000_000)
            .expect("book not full yet");
    }
    assert_eq!(
        book.store().len(),
        ao_idents::MAX_CONTACTS,
        "the book is at its cap"
    );

    let statement = RotationStatement::sign(&alice, &identity(2)).expect("distinct identities");
    let err = book
        .rotate(&statement)
        .expect_err("no room for the successor");
    assert!(
        matches!(err, IdentError::ContactBookFull),
        "wrong error: {err}"
    );
    assert!(
        book.get(alice.node_id()).is_some(),
        "the old contact must still be there"
    );
    assert!(
        book.get(statement.new_node_id()).is_none(),
        "nothing applied"
    );
}

/// A self-signed revocation blocks instead of deleting: the entry
/// stays, the petname stays for the human, and the dead keys keep
/// failing on every later presentation.
#[test]
fn a_revoked_contact_is_blocked_and_stays_blocked() {
    let bob = identity(3);
    let mut book = book_with(&bob);
    book.set_trust(bob.node_id(), Trust::Verified)
        .expect("known contact");
    book.set_petname(bob.node_id(), Some("bob"))
        .expect("known contact");

    let notice = RevocationNotice::sign(&bob).expect("self-signature");
    book.revoke(&notice).expect("known contact");

    let revoked = book.get(bob.node_id()).expect("entry stays");
    assert_eq!(revoked.trust(), Trust::Blocked, "revocation blocks");
    assert_eq!(revoked.petname(), Some("bob"), "petname kept for the human");

    // The same card offered again keeps the block: deleting would
    // have let the dead keys back in through trust-on-first-use.
    let update = book
        .observe(bob.node_id(), &card(&bob, b"bob"), 1_700_000_000)
        .expect("same keys");
    assert!(matches!(update, ao_idents::ContactUpdate::Unchanged));
    assert_eq!(
        book.get(bob.node_id()).expect("entry stays").trust(),
        Trust::Blocked,
        "still blocked"
    );

    // Re-applying the notice is idempotent.
    book.revoke(&notice).expect("already blocked");
    assert_eq!(
        book.get(bob.node_id()).expect("entry stays").trust(),
        Trust::Blocked
    );
}

/// Only the holder of a key can retire it, and there is nothing to
/// block for a stranger.
#[test]
fn a_forged_or_unknown_revocation_is_rejected() {
    let bob = identity(3);
    let stranger = identity(4);
    let mut book = book_with(&bob);

    let mut forged = RevocationNotice::sign(&bob)
        .expect("self-signature")
        .encode();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let notice = RevocationNotice::decode(&forged).expect("structure intact");
    let err = book.revoke(&notice).expect_err("forged");
    assert!(matches!(err, IdentError::InvalidSignature), "wrong: {err}");
    assert_ne!(
        book.get(bob.node_id()).expect("untouched").trust(),
        Trust::Blocked,
        "a forged notice must not block"
    );

    let notice = RevocationNotice::sign(&stranger).expect("self-signature");
    let err = book.revoke(&notice).expect_err("never met");
    assert!(matches!(err, IdentError::UnknownContact), "wrong: {err}");
}

/// Fixed-length decodes reject anything that is not exactly the
/// layout: truncated, over-long, trailing and unknown-suite input are
/// typed errors on both structures.
#[test]
fn decodings_reject_truncated_overlong_and_unknown_suite() {
    let statement = RotationStatement::sign(&identity(1), &identity(2)).expect("distinct");
    let encoded = statement.encode();

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(
        matches!(
            RotationStatement::decode(&truncated),
            Err(IdentError::MalformedRotation)
        ),
        "truncated"
    );

    let mut overlong = encoded;
    overlong.push(0);
    assert!(
        matches!(
            RotationStatement::decode(&overlong),
            Err(IdentError::MalformedRotation)
        ),
        "trailing byte"
    );

    let mut wrong_suite = statement.encode();
    wrong_suite[0] = 0x02;
    assert!(
        matches!(
            RotationStatement::decode(&wrong_suite),
            Err(IdentError::UnknownSuite(0x02))
        ),
        "unknown suite"
    );

    let notice = RevocationNotice::sign(&identity(3)).expect("self-signature");
    let encoded = notice.encode();
    assert_eq!(encoded.len(), REVOCATION_LEN, "fixed layout");

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(
        matches!(
            RevocationNotice::decode(&truncated),
            Err(IdentError::MalformedRevocation)
        ),
        "truncated"
    );

    let mut overlong = encoded;
    overlong.push(0);
    assert!(
        matches!(
            RevocationNotice::decode(&overlong),
            Err(IdentError::MalformedRevocation)
        ),
        "trailing byte"
    );

    let mut wrong_suite = notice.encode();
    wrong_suite[0] = 0x02;
    assert!(
        matches!(
            RevocationNotice::decode(&wrong_suite),
            Err(IdentError::UnknownSuite(0x02))
        ),
        "unknown suite"
    );
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
        /// or a statement/notice that then verifies or fails on its
        /// own merits.
        #[test]
        fn decoding_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let _ = RotationStatement::decode(&bytes);
            let _ = RevocationNotice::decode(&bytes);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(8))]

        /// Every single-byte corruption of a rotation statement is
        /// rejected: the flipped byte is either outside the layout,
        /// breaks the suite, or is covered by both signatures.
        #[test]
        fn every_single_byte_tamper_of_a_rotation_is_rejected(
            old_state in any::<u64>(),
        ) {
            // A non-zero offset keeps the two seeds distinct for every
            // input, including 0 and u64::MAX.
            let new_state = old_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let statement = RotationStatement::sign(
                &identity(old_state),
                &identity(new_state),
            )
            .expect("distinct identities");
            let encoded = statement.encode();

            for index in 0..encoded.len() {
                let mut tampered = encoded.clone();
                tampered[index] ^= 0x01;
                let rejected = RotationStatement::decode(&tampered)
                    .map_or(true, |decoded| decoded.verify().is_err());
                prop_assert!(
                    rejected,
                    "byte {index} survived: decode and verify both passed"
                );
            }
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(8))]

        /// Every single-byte corruption of a revocation notice is
        /// rejected the same way.
        #[test]
        fn every_single_byte_tamper_of_a_revocation_is_rejected(
            state in any::<u64>(),
        ) {
            let notice = RevocationNotice::sign(&identity(state)).expect("self-signature");
            let encoded = notice.encode();

            for index in 0..encoded.len() {
                let mut tampered = encoded.clone();
                tampered[index] ^= 0x01;
                let rejected = RevocationNotice::decode(&tampered)
                    .map_or(true, |decoded| decoded.verify().is_err());
                prop_assert!(
                    rejected,
                    "byte {index} survived: decode and verify both passed"
                );
            }
        }
    }
}
