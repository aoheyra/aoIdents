//! Contact book: trust on first use, key-change detection and safety
//! numbers (IDN-08).
//!
//! Covers both done-when lines: a changed key for a known NodeId is
//! never silently accepted, and both parties compute the same safety
//! number.

mod common;

use ao_idents::{
    Contact, ContactBook, ContactStore, ContactUpdate, IdentError, Identity, IdentityCard,
    MAX_CONTACTS, MAX_PETNAME_BYTES, MemoryContactStore, Trust, safety_number,
};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn card_of(id: &Identity) -> IdentityCard {
    id.card(b"Alice", 1_000).expect("name fits")
}

/// First sighting: stored as Unverified with the card's keys and the
/// caller's timestamp - trust on first use, no claim made.
#[test]
fn first_use_stores_an_unverified_contact() {
    let alice = identity(1);
    let mut book = ContactBook::new(MemoryContactStore::new());

    let update = book
        .observe(alice.node_id(), &card_of(&alice), 42)
        .expect("first sighting");
    assert_eq!(update, ContactUpdate::FirstUse);

    let contact = book.get(alice.node_id()).expect("stored");
    assert_eq!(contact.trust(), Trust::Unverified);
    assert_eq!(contact.signing_pk(), alice.public().signing_pk());
    assert_eq!(contact.agreement_pk(), alice.public().agreement_pk());
    assert_eq!(contact.first_seen(), 42);
    assert_eq!(contact.petname(), None);
    assert_eq!(contact.node_id(), &alice.node_id());
}

/// The same keys again: Unchanged, and an upgraded trust level is
/// not reset by a re-observation.
#[test]
fn unchanged_keys_keep_trust_and_report_unchanged() {
    let alice = identity(2);
    let mut book = ContactBook::new(MemoryContactStore::new());

    book.observe(alice.node_id(), &card_of(&alice), 1)
        .expect("first sighting");
    book.set_trust(alice.node_id(), Trust::Verified)
        .expect("known contact");

    let update = book
        .observe(alice.node_id(), &card_of(&alice), 2)
        .expect("re-observation");
    assert_eq!(update, ContactUpdate::Unchanged);
    let stored = book.get(alice.node_id()).expect("stored");
    assert_eq!(stored.trust(), Trust::Verified);
    assert_eq!(
        stored.first_seen(),
        1,
        "re-observation must not rewrite the original timestamp"
    );
}

/// The done-when: a known NodeId presenting different keys fails with
/// a typed warning, the stored contact is untouched, and nothing is
/// added under any other id either.
#[test]
fn changed_key_for_a_known_node_is_never_silently_accepted() {
    let alice = identity(3);
    let mallory = identity(4);
    let mut book = ContactBook::new(MemoryContactStore::new());
    book.observe(alice.node_id(), &card_of(&alice), 10)
        .expect("first sighting");
    book.set_trust(alice.node_id(), Trust::Verified)
        .expect("known contact");
    let before = book.get(alice.node_id()).expect("stored");

    // Mallory presents her own (valid) card while claiming Alice's
    // NodeId: keys do not hash to the claim.
    let result = book.observe(alice.node_id(), &card_of(&mallory), 99);
    assert!(
        matches!(result, Err(IdentError::KeyChanged(id)) if id == alice.node_id()),
        "key change must be a typed warning"
    );

    let after = book.get(alice.node_id()).expect("still stored");
    assert_eq!(after, before, "stored contact is untouched");
    assert_eq!(after.trust(), Trust::Verified);
    assert_eq!(book.store().len(), 1, "nothing was stored anywhere else");

    // The same typed warning for a fresh claim that does not hash to
    // itself - a mismatch is rejected whether or not the id is known.
    let claimed = identity(5).node_id();
    let mismatch = book.observe(claimed, &card_of(&mallory), 11);
    assert!(
        matches!(mismatch, Err(IdentError::KeyChanged(id)) if id == claimed),
        "unknown-claim mismatch must be a typed warning too"
    );
    assert!(book.get(claimed).is_none());
}

/// A tampered card never becomes a contact: the signature check
/// fires before anything is stored, and a structural break is its
/// own typed error.
#[test]
fn a_forged_card_is_rejected_and_stores_nothing() {
    let alice = identity(6);
    let bytes = card_of(&alice).encode();
    let mut flipped = bytes;
    flipped[10] ^= 0x01;

    let mut book = ContactBook::new(MemoryContactStore::new());
    let result = match IdentityCard::decode(&flipped) {
        Ok(card) => book.observe(alice.node_id(), &card, 1),
        Err(error) => Err(error),
    };
    assert!(result.is_err(), "forged card must be rejected");
    assert!(book.get(alice.node_id()).is_none());
    assert_eq!(book.store().len(), 0);
}

/// The book stops at MAX_CONTACTS with a typed error; the store
/// enforces the same cap when written to directly.
#[test]
fn a_full_book_rejects_new_contacts() {
    let mut book = ContactBook::new(MemoryContactStore::new());
    for state in 1..=MAX_CONTACTS {
        let peer = identity(state as u64);
        book.observe(peer.node_id(), &card_of(&peer), state as u64)
            .expect("under the cap");
    }
    let late = identity(999_999);
    assert!(matches!(
        book.observe(late.node_id(), &card_of(&late), 0),
        Err(IdentError::ContactBookFull)
    ));

    // The store itself refuses growth past the cap, so no other
    // caller can slip around the book's check.
    let mut store = MemoryContactStore::new();
    for state in 1..=MAX_CONTACTS {
        let peer = identity(state as u64);
        let contact = Contact::from_card(&card_of(&peer), 0).expect("valid card");
        store.save(contact).expect("under the cap");
    }
    let extra = Contact::from_card(&card_of(&late), 0).expect("valid card");
    assert!(matches!(
        store.save(extra),
        Err(IdentError::ContactBookFull)
    ));
}

/// Trust and petname changes require an existing contact.
#[test]
fn changes_to_an_unknown_contact_are_typed_errors() {
    let ghost = identity(7).node_id();
    let mut book = ContactBook::new(MemoryContactStore::new());

    assert!(matches!(
        book.set_trust(ghost, Trust::Verified),
        Err(IdentError::UnknownContact)
    ));
    assert!(matches!(
        book.set_petname(ghost, Some("ghost")),
        Err(IdentError::UnknownContact)
    ));
}

/// Petnames round-trip (set, overwrite, clear) and obey their bound.
#[test]
fn petnames_round_trip_and_are_bounded() {
    let alice = identity(8);
    let mut book = ContactBook::new(MemoryContactStore::new());
    book.observe(alice.node_id(), &card_of(&alice), 1)
        .expect("first sighting");

    book.set_petname(alice.node_id(), Some("mom")).expect("set");
    assert_eq!(
        book.get(alice.node_id()).expect("stored").petname(),
        Some("mom")
    );

    book.set_petname(alice.node_id(), Some("aunt"))
        .expect("overwrite");
    assert_eq!(
        book.get(alice.node_id()).expect("stored").petname(),
        Some("aunt")
    );

    book.set_petname(alice.node_id(), None).expect("clear");
    assert_eq!(book.get(alice.node_id()).expect("stored").petname(), None);

    let exact = "p".repeat(MAX_PETNAME_BYTES);
    book.set_petname(alice.node_id(), Some(&exact))
        .expect("at the limit");
    assert!(matches!(
        book.set_petname(alice.node_id(), Some(&"p".repeat(MAX_PETNAME_BYTES + 1))),
        Err(IdentError::PetnameTooLong)
    ));
}

/// The done-when: both parties derive identical safety numbers from
/// their own identity plus the other's contact entry - exactly what
/// a human compares over a second channel.
#[test]
fn both_parties_compute_the_same_safety_number() {
    let alice = identity(9);
    let bob = identity(10);

    // Each side stores the other's keys through its own book.
    let mut alice_book = ContactBook::new(MemoryContactStore::new());
    alice_book
        .observe(bob.node_id(), &card_of(&bob), 1)
        .expect("first sighting");
    let mut bob_book = ContactBook::new(MemoryContactStore::new());
    bob_book
        .observe(alice.node_id(), &card_of(&alice), 2)
        .expect("first sighting");

    let bob_from_alice = alice_book.get(bob.node_id()).expect("stored");
    let alice_from_bob = bob_book.get(alice.node_id()).expect("stored");

    let from_alice = safety_number(
        (alice.public().signing_pk(), alice.public().agreement_pk()),
        (bob_from_alice.signing_pk(), bob_from_alice.agreement_pk()),
    );
    let from_bob = safety_number(
        (bob.public().signing_pk(), bob.public().agreement_pk()),
        (alice_from_bob.signing_pk(), alice_from_bob.agreement_pk()),
    );
    assert_eq!(
        from_alice, from_bob,
        "both parties must derive identical safety numbers"
    );

    let carol = identity(11);
    assert_ne!(
        from_alice,
        safety_number(
            (alice.public().signing_pk(), alice.public().agreement_pk()),
            (carol.public().signing_pk(), carol.public().agreement_pk()),
        ),
        "different pairs must differ"
    );
}

/// The checked-in test vector: the exact safety number for two fixed
/// identities, so an accidental domain or derivation change fails
/// CI. Independently derived once (BLAKE3 over the ADR domain and
/// sorted keys) and reviewed before check-in; both orderings must
/// reproduce it.
#[test]
fn checked_in_safety_number_vector() {
    const VECTOR_HEX: &str = "f9eafecb42eb32c5";
    let expected: Vec<u8> = (0..VECTOR_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&VECTOR_HEX[i..i + 2], 16).expect("hex"))
        .collect();

    let a = Identity::from_seed([6u8; 32]);
    let b = Identity::from_seed([7u8; 32]);
    let from_a = safety_number(
        (a.public().signing_pk(), a.public().agreement_pk()),
        (b.public().signing_pk(), b.public().agreement_pk()),
    );
    assert_eq!(
        &from_a[..],
        &expected[..],
        "safety number changed: if intentional, this is a protocol change (ADR-0001)"
    );

    let from_b = safety_number(
        (b.public().signing_pk(), b.public().agreement_pk()),
        (a.public().signing_pk(), a.public().agreement_pk()),
    );
    assert_eq!(
        &from_b[..],
        &expected[..],
        "the number must be order-independent"
    );
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

        /// Safety numbers are symmetric for arbitrary key pairs -
        /// order must never change what the human compares.
        #[test]
        fn safety_numbers_are_symmetric(
            a_sign in any::<[u8; 32]>(),
            a_agree in any::<[u8; 32]>(),
            b_sign in any::<[u8; 32]>(),
            b_agree in any::<[u8; 32]>(),
        ) {
            prop_assert_eq!(
                safety_number((&a_sign, &a_agree), (&b_sign, &b_agree)),
                safety_number((&b_sign, &b_agree), (&a_sign, &a_agree))
            );
        }

        /// Petnames up to the limit round-trip through the book;
        /// over the limit are always a typed error, never truncated.
        #[test]
        fn petnames_round_trip_or_fail(name in any::<String>(), seed in any::<u64>()) {
            let id = identity(seed | 1);
            let mut book = ContactBook::new(MemoryContactStore::new());
            book.observe(id.node_id(), &card_of(&id), 1)
                .expect("first sighting");

            let result = book.set_petname(id.node_id(), Some(&name));
            let stored = book.get(id.node_id()).expect("stored");
            if name.len() <= MAX_PETNAME_BYTES {
                prop_assert!(result.is_ok());
                prop_assert_eq!(stored.petname(), Some(name.as_str()));
            } else {
                prop_assert!(matches!(result, Err(IdentError::PetnameTooLong)));
                prop_assert_eq!(
                    stored.petname(),
                    None,
                    "a rejected name must not be stored"
                );
            }
        }
    }
}
