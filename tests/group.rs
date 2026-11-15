//! Sender-key group encryption for private channels (IDN-17).
//!
//! Covers the done-when: removing a member prevents them from reading
//! new messages in a test. Plus distributions, late joiners, replayed
//! distributions, the counter window under reordering, malformed
//! inputs, membership statements, bounds and proptests.

mod common;

use ao_idents::{
    GroupId, GroupMessage, GroupReceiver, IdentError, Identity, MAX_COUNTER_JUMP,
    MAX_SENDERS_PER_GROUP, MembershipAction, MembershipChange, SenderChain, SenderKeyDistribution,
};
use common::TestRng;

/// The group message header: suite(1) + group id(16) + sender(16) +
/// counter(4) + nonce(24) + length(2).
const MSG_HEADER_LEN: usize = 63;

/// The counter field's offset in the encoding.
const COUNTER_OFFSET: usize = 33;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn group() -> GroupId {
    GroupId::from_bytes([7; 16])
}

/// Seal `chain` to `recipient` for the sender identity `sender`.
fn distribute(
    chain: &SenderChain,
    sender: &Identity,
    recipient: &Identity,
    seed: u64,
) -> SenderKeyDistribution {
    chain
        .distribution_to(sender, recipient.public(), &mut TestRng::new(seed))
        .expect("distribution seals")
}

/// Three members install each other's chains and every message flows
/// to every member; the encoding round-trips.
#[test]
fn distributions_install_and_messages_flow() {
    let alice = identity(1);
    let bob = identity(2);
    let mallory = identity(3);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let bob_chain = SenderChain::generate(gid, &mut TestRng::new(11));
    let mallory_chain = SenderChain::generate(gid, &mut TestRng::new(12));
    assert_eq!(alice_chain.group_id(), gid);
    assert_eq!(alice_chain.epoch(), 0);

    let mut alice_rx = GroupReceiver::new(gid);
    let mut bob_rx = GroupReceiver::new(gid);
    let mut mallory_rx = GroupReceiver::new(gid);

    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("bob accepts alice");
    mallory_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &mallory, 21), &mallory)
        .expect("mallory accepts alice");
    alice_rx
        .accept_distribution(&distribute(&bob_chain, &bob, &alice, 22), &alice)
        .expect("alice accepts bob");
    mallory_rx
        .accept_distribution(&distribute(&bob_chain, &bob, &mallory, 23), &mallory)
        .expect("mallory accepts bob");
    alice_rx
        .accept_distribution(&distribute(&mallory_chain, &mallory, &alice, 24), &alice)
        .expect("alice accepts mallory");
    bob_rx
        .accept_distribution(&distribute(&mallory_chain, &mallory, &bob, 25), &bob)
        .expect("bob accepts mallory");

    let message = alice_chain
        .encrypt(&alice, b"hello from alice", &mut TestRng::new(30))
        .expect("encrypts");
    assert_eq!(message.group_id(), gid);
    assert_eq!(message.sender(), alice.node_id());
    assert_eq!(message.counter(), 0);
    assert_eq!(alice_chain.next_counter(), 1, "the chain advanced");

    assert_eq!(bob_rx.decrypt(&message).unwrap(), b"hello from alice");
    assert_eq!(mallory_rx.decrypt(&message).unwrap(), b"hello from alice");
    // A sender who did not install their own chain cannot read their
    // own message back without it.
    assert!(matches!(
        alice_rx.decrypt(&message),
        Err(IdentError::UnknownSender)
    ));

    let decoded = GroupMessage::decode(&message.encode()).expect("round trip");
    assert_eq!(decoded, message);
    let dist = distribute(&alice_chain, &alice, &bob, 40);
    let decoded_dist = SenderKeyDistribution::decode(&dist.encode()).expect("round trip");
    assert_eq!(decoded_dist, dist);
}

/// The done-while: a message to the channel opens for every member;
/// the member is removed and the sender rekeys; the removed member,
/// holding the old chain, the sealed message and everything public,
/// cannot read the new message, and the remaining member can.
#[test]
fn removing_a_member_prevents_them_from_reading_new_messages() {
    let alice = identity(1);
    let bob = identity(2);
    let mallory = identity(3);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);
    let mut mallory_rx = GroupReceiver::new(gid);

    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("bob accepts alice");
    mallory_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &mallory, 21), &mallory)
        .expect("mallory accepts alice");

    // While mallory is a member he reads alice's messages.
    let before = alice_chain
        .encrypt(&alice, b"before removal", &mut TestRng::new(30))
        .expect("encrypts");
    assert_eq!(mallory_rx.decrypt(&before).unwrap(), b"before removal");

    // The admin signs the removal; the statement verifies against
    // the admin's identity.
    let removal =
        MembershipChange::sign(&alice, gid, 1, MembershipAction::Remove, mallory.node_id())
            .expect("signs");
    removal.verify(alice.public()).expect("verifies");

    // Rekey: alice rotates her chain and redistributes only to the
    // member that remains.
    alice_chain.rotate(&mut TestRng::new(31));
    assert_eq!(alice_chain.epoch(), 1);
    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 32), &bob)
        .expect("bob accepts the new chain");

    let after = alice_chain
        .encrypt(&alice, b"after removal", &mut TestRng::new(33))
        .expect("encrypts");

    // Mallory holds the old chain and the public message: the new
    // message does not open for him.
    let err = mallory_rx.decrypt(&after).expect_err("removed member");
    assert!(
        matches!(err, IdentError::CounterTooOld | IdentError::OpenFailed),
        "wrong error: {err}"
    );

    // The remaining member, who received the new distribution, reads
    // it fine.
    assert_eq!(bob_rx.decrypt(&after).unwrap(), b"after removal");
}

/// A member who joins mid-channel gets the chain at its current
/// position: what comes next opens, the history does not. This is
/// why the chain exists instead of a static key.
#[test]
fn a_new_member_cannot_read_history() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);

    let old = alice_chain
        .encrypt(&alice, b"sent before bob joined", &mut TestRng::new(30))
        .expect("encrypts");

    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("bob joins");

    let fresh = alice_chain
        .encrypt(&alice, b"sent after bob joined", &mut TestRng::new(31))
        .expect("encrypts");
    assert_eq!(bob_rx.decrypt(&fresh).unwrap(), b"sent after bob joined");
    assert!(matches!(
        bob_rx.decrypt(&old),
        Err(IdentError::CounterTooOld)
    ));
}

/// A replayed distribution never moves a chain backward: the same
/// blob is a harmless duplicate, and a superseded epoch is ignored,
/// so neither can reset the position and re-open a rejected message.
#[test]
fn replayed_distributions_never_move_a_chain_backward() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);

    let dist = distribute(&alice_chain, &alice, &bob, 20);
    bob_rx.accept_distribution(&dist, &bob).expect("first");

    let first = alice_chain
        .encrypt(&alice, b"one", &mut TestRng::new(30))
        .expect("encrypts");
    bob_rx.decrypt(&first).unwrap();

    // The identical distribution again: accepted as a duplicate,
    // position kept.
    bob_rx.accept_distribution(&dist, &bob).expect("replay");
    assert!(matches!(
        bob_rx.decrypt(&first),
        Err(IdentError::CounterTooOld)
    ));

    // After a rotation the new chain is installed; the old epoch-0
    // distribution arriving late is superseded and ignored.
    alice_chain.rotate(&mut TestRng::new(31));
    let new_dist = distribute(&alice_chain, &alice, &bob, 32);
    bob_rx
        .accept_distribution(&new_dist, &bob)
        .expect("new chain");
    bob_rx
        .accept_distribution(&dist, &bob)
        .expect("stale epoch is ignored");

    let second = alice_chain
        .encrypt(&alice, b"two", &mut TestRng::new(33))
        .expect("encrypts");
    assert_eq!(bob_rx.decrypt(&second).unwrap(), b"two");
}

/// Forgetting a sender is the receiver-side half of removal: their
/// later messages fail with `UnknownSender`.
#[test]
fn remove_sender_forgets_the_chain() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);
    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("accepts");
    assert!(bob_rx.has_sender(&alice.node_id()));

    assert!(bob_rx.remove_sender(&alice.node_id()));
    assert!(!bob_rx.has_sender(&alice.node_id()));
    assert!(!bob_rx.remove_sender(&alice.node_id()), "second removal");

    let message = alice_chain
        .encrypt(&alice, b"x", &mut TestRng::new(30))
        .expect("encrypts");
    assert!(matches!(
        bob_rx.decrypt(&message),
        Err(IdentError::UnknownSender)
    ));
}

/// Channels are isolated: a message or distribution from another
/// channel is refused, and a sender whose chain was never
/// distributed to this receiver is unknown.
#[test]
fn wrong_group_and_unknown_sender_are_typed() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();
    let other_gid = GroupId::from_bytes([8; 16]);

    let alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);
    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("accepts");

    // A distribution for a different channel.
    let mut other_rx = GroupReceiver::new(other_gid);
    let err = other_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 21), &bob)
        .expect_err("wrong channel");
    assert!(matches!(err, IdentError::WrongGroup), "wrong: {err}");

    // A message for a different channel.
    let mut other_chain = SenderChain::generate(other_gid, &mut TestRng::new(11));
    let foreign = other_chain
        .encrypt(&alice, b"other channel", &mut TestRng::new(30))
        .expect("encrypts");
    let err = bob_rx.decrypt(&foreign).expect_err("wrong channel");
    assert!(matches!(err, IdentError::WrongGroup), "wrong: {err}");

    // A sender this receiver never got a distribution for.
    let mut carol_chain = SenderChain::generate(gid, &mut TestRng::new(12));
    let message = carol_chain
        .encrypt(&identity(5), b"stranger", &mut TestRng::new(31))
        .expect("encrypts");
    let err = bob_rx.decrypt(&message).expect_err("no chain");
    assert!(matches!(err, IdentError::UnknownSender), "wrong: {err}");
}

/// The counter window under reordering: a jump within
/// `MAX_COUNTER_JUMP` opens and caches the keys it skipped, late
/// messages inside the window still open, a replay behind the
/// position is refused, and a jump past the window is refused
/// without any derivation work.
#[test]
fn counter_window_allows_reordering_and_bounds_gaps() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);
    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("accepts");

    let mut messages = Vec::new();
    for i in 0..5_u32 {
        messages.push(
            alice_chain
                .encrypt(
                    &alice,
                    format!("m{i}").as_bytes(),
                    &mut TestRng::new(30 + i as u64),
                )
                .expect("encrypts"),
        );
    }

    // Out of order: the third message first (a jump of two), then
    // the ones it jumped over.
    assert_eq!(bob_rx.decrypt(&messages[2]).unwrap(), b"m2");
    assert_eq!(bob_rx.decrypt(&messages[0]).unwrap(), b"m0");
    assert_eq!(bob_rx.decrypt(&messages[1]).unwrap(), b"m1");
    assert_eq!(bob_rx.decrypt(&messages[3]).unwrap(), b"m3");
    assert_eq!(bob_rx.decrypt(&messages[4]).unwrap(), b"m4");

    // Each accepted exactly once: the cached keys were consumed.
    assert!(matches!(
        bob_rx.decrypt(&messages[0]),
        Err(IdentError::CounterTooOld)
    ));

    // A jump past the window is refused before any derivation.
    let mut far = messages[4].clone();
    let mut encoded = far.encode();
    let target = 5 + MAX_COUNTER_JUMP + 1;
    encoded[COUNTER_OFFSET..COUNTER_OFFSET + 4].copy_from_slice(&target.to_be_bytes());
    far = GroupMessage::decode(&encoded).expect("structurally fine");
    assert!(matches!(
        bob_rx.decrypt(&far),
        Err(IdentError::CounterTooFarAhead)
    ));
}

/// Every envelope field is authenticated or scoped: a single flipped
/// byte anywhere in the encoding fails decoding or the decrypt, and
/// the suite byte specifically fails at decode.
#[test]
fn tampered_group_messages_fail() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let mut bob_rx = GroupReceiver::new(gid);
    bob_rx
        .accept_distribution(&distribute(&alice_chain, &alice, &bob, 20), &bob)
        .expect("accepts");
    let message = alice_chain
        .encrypt(&alice, b"payload", &mut TestRng::new(30))
        .expect("encrypts");
    let encoded = message.encode();

    let positions = [
        ("group id", 1),
        ("sender", 17),
        ("counter", 33),
        ("nonce", 37),
        ("first ciphertext byte", MSG_HEADER_LEN),
        ("last byte", encoded.len() - 1),
    ];
    for (label, at) in positions {
        let mut tampered = encoded.clone();
        tampered[at] ^= 0x01;
        let decoded = GroupMessage::decode(&tampered).expect("structure intact");
        let err = bob_rx.decrypt(&decoded).expect_err(label);
        assert!(
            matches!(
                err,
                IdentError::WrongGroup
                    | IdentError::UnknownSender
                    | IdentError::CounterTooOld
                    | IdentError::CounterTooFarAhead
                    | IdentError::OpenFailed
            ),
            "{label}: {err}"
        );
    }

    // The suite byte never gets that far: it fails at decode.
    let mut tampered = encoded;
    tampered[0] ^= 0x01;
    assert!(matches!(
        GroupMessage::decode(&tampered),
        Err(IdentError::UnknownSuite(0))
    ));
}

/// All three group encodings reject anything that is not exactly
/// the layout: truncated, trailing, or a field this suite version
/// does not define.
#[test]
fn decodings_reject_malformed_group_input() {
    let alice = identity(1);
    let bob = identity(2);
    let gid = group();

    let mut alice_chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let message = alice_chain
        .encrypt(&alice, b"payload", &mut TestRng::new(30))
        .expect("encrypts");
    let encoded = message.encode();

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        GroupMessage::decode(&truncated),
        Err(IdentError::MalformedGroup)
    ));
    let mut overlong = encoded.clone();
    overlong.push(0);
    assert!(matches!(
        GroupMessage::decode(&overlong),
        Err(IdentError::MalformedGroup)
    ));
    let mut short_length = encoded;
    short_length[61..63].copy_from_slice(&0_u16.to_be_bytes());
    assert!(matches!(
        GroupMessage::decode(&short_length),
        Err(IdentError::MalformedGroup)
    ));

    let dist = distribute(&alice_chain, &alice, &bob, 20);
    let encoded = dist.encode();
    assert!(matches!(
        SenderKeyDistribution::decode(&encoded[..16]),
        Err(IdentError::MalformedGroup)
    ));
    assert!(
        SenderKeyDistribution::decode(&encoded[16..]).is_err(),
        "the sealed half keeps its own bounds"
    );

    let statement = MembershipChange::sign(&alice, gid, 1, MembershipAction::Remove, bob.node_id())
        .expect("signs");
    let encoded = statement.encode();
    assert_eq!(encoded.len(), 101, "fixed layout");
    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        MembershipChange::decode(&truncated),
        Err(IdentError::MalformedGroup)
    ));
    let mut overlong = encoded.clone();
    overlong.push(0);
    assert!(matches!(
        MembershipChange::decode(&overlong),
        Err(IdentError::MalformedGroup)
    ));
    let mut bad_action = encoded;
    bad_action[20] = 2;
    assert!(matches!(
        MembershipChange::decode(&bad_action),
        Err(IdentError::MalformedGroup)
    ));
}

/// Membership statements round-trip and verify against the admin
/// who signed them; any tampering or the wrong admin fails with a
/// typed error.
#[test]
fn membership_statements_sign_and_verify() {
    let admin = identity(1);
    let carol = identity(5);
    let mallory = identity(3);
    let gid = group();

    let statement =
        MembershipChange::sign(&admin, gid, 3, MembershipAction::Remove, carol.node_id())
            .expect("signs");
    statement.verify(admin.public()).expect("verifies");
    assert_eq!(statement.group_id(), gid);
    assert_eq!(statement.epoch(), 3);
    assert_eq!(statement.action(), MembershipAction::Remove);
    assert_eq!(statement.member(), carol.node_id());

    let decoded = MembershipChange::decode(&statement.encode()).expect("round trip");
    assert_eq!(decoded, statement);
    decoded
        .verify(admin.public())
        .expect("survives the encoding");

    // A flipped body byte invalidates the signature.
    let mut forged = statement.encode();
    forged[0] ^= 0x01;
    let forged = MembershipChange::decode(&forged).expect("structure intact");
    assert!(matches!(
        forged.verify(admin.public()),
        Err(IdentError::InvalidSignature)
    ));

    // A flipped signature byte too.
    let mut forged = statement.encode();
    forged[100] ^= 0x01;
    let forged = MembershipChange::decode(&forged).expect("structure intact");
    assert!(matches!(
        forged.verify(admin.public()),
        Err(IdentError::InvalidSignature)
    ));

    // And a different identity cannot verify it as its own.
    assert!(matches!(
        statement.verify(mallory.public()),
        Err(IdentError::InvalidSignature)
    ));
}

/// The payload limit: exactly `65535 - tag` seals, one byte more is
/// refused before the buffer is allocated.
#[test]
fn oversize_group_payload_is_refused() {
    let alice = identity(1);
    let gid = group();
    let mut chain = SenderChain::generate(gid, &mut TestRng::new(10));

    let largest = vec![0_u8; 65535 - 16];
    chain
        .encrypt(&alice, &largest, &mut TestRng::new(30))
        .expect("at the limit");

    let over = vec![0_u8; 65535 - 16 + 1];
    let err = chain
        .encrypt(&alice, &over, &mut TestRng::new(31))
        .expect_err("over the limit");
    assert!(matches!(err, IdentError::PayloadTooLarge), "wrong: {err}");
}

/// The sender cap: a receiver installs up to
/// `MAX_SENDERS_PER_GROUP` distinct senders, refuses the next new
/// one, and still accepts updates from senders already installed.
#[test]
fn too_many_senders_is_refused() {
    let gid = group();
    let me = identity(7);
    let mut receiver = GroupReceiver::new(gid);

    let mut first_dist = None;
    for i in 0..MAX_SENDERS_PER_GROUP {
        let sender = identity(100 + i as u64);
        let mut chain = SenderChain::generate(gid, &mut TestRng::new(1000 + i as u64));
        let dist = distribute(&chain, &sender, &me, 2000 + i as u64);
        receiver
            .accept_distribution(&dist, &me)
            .expect("within the cap");
        if i == 0 {
            first_dist = Some(dist);
            // A later update from the same sender is fine even when
            // the channel is full: the cap is on distinct senders.
            chain.rotate(&mut TestRng::new(5000));
            let update = distribute(&chain, &sender, &me, 5001);
            receiver
                .accept_distribution(&update, &me)
                .expect("existing sender may update");
        }
    }

    let outsider = identity(999);
    let chain = SenderChain::generate(gid, &mut TestRng::new(9999));
    let dist = distribute(&chain, &outsider, &me, 9998);
    let err = receiver
        .accept_distribution(&dist, &me)
        .expect_err("channel full");
    assert!(matches!(err, IdentError::TooManySenders), "wrong: {err}");

    // Replaying a distribution from an installed sender is still a
    // harmless duplicate at the cap.
    receiver
        .accept_distribution(&first_dist.expect("kept"), &me)
        .expect("duplicate is ignored");
}

/// The chain and receiver Debug output names the type and the public
/// position, never key material.
#[test]
fn debug_of_chain_and_receiver_redacts_key_material() {
    let gid = group();
    let chain = SenderChain::generate(gid, &mut TestRng::new(10));
    let printed = format!("{chain:?}");
    assert!(printed.contains("SenderChain"), "names the type");
    assert!(!printed.contains("chain_key"), "no key bytes: {printed}");

    let receiver = GroupReceiver::new(gid);
    let printed = format!("{receiver:?}");
    assert!(printed.contains("GroupReceiver"), "names the type");
    assert!(!printed.contains("chain_key"), "no key bytes: {printed}");
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
        /// or a structure that then fails on its own merits.
        #[test]
        fn group_decoding_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..320),
        ) {
            let _ = GroupMessage::decode(&bytes);
            let _ = SenderKeyDistribution::decode(&bytes);
            let _ = MembershipChange::decode(&bytes);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(16))]

        /// Any payload round-trips: distribute once, encrypt, decrypt
        /// as the member, get the same bytes back.
        #[test]
        fn group_round_trip_arbitrary_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let alice = identity(1);
            let bob = identity(2);
            let gid = group();
            let mut chain = SenderChain::generate(gid, &mut TestRng::new(10));
            let mut receiver = GroupReceiver::new(gid);
            receiver
                .accept_distribution(&distribute(&chain, &alice, &bob, 20), &bob)
                .expect("accepts");
            let message = chain
                .encrypt(&alice, &payload, &mut TestRng::new(30))
                .expect("within the payload limit");
            prop_assert_eq!(receiver.decrypt(&message).unwrap(), payload.as_slice());
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(8))]

        /// Every single-byte corruption of a group message fails to
        /// open: the flipped byte is either outside the layout,
        /// breaks the suite or length, or is covered by the sender,
        /// counter and the AEAD.
        #[test]
        fn every_single_byte_tamper_of_a_group_message_fails(
            state in any::<u64>(),
        ) {
            let alice = identity(1);
            let bob = identity(state);
            let gid = group();
            let mut chain = SenderChain::generate(gid, &mut TestRng::new(10));
            let mut receiver = GroupReceiver::new(gid);
            receiver
                .accept_distribution(&distribute(&chain, &alice, &bob, 20), &bob)
                .expect("accepts");
            let payload = [0_u8; 8];
            let message = chain
                .encrypt(&alice, &payload, &mut TestRng::new(30))
                .expect("seals");
            let encoded = message.encode();

            for index in 0..encoded.len() {
                let mut tampered = encoded.clone();
                tampered[index] ^= 0x01;
                let rejected = GroupMessage::decode(&tampered).map_or(true, |decoded| {
                    receiver.decrypt(&decoded).is_err()
                });
                prop_assert!(
                    rejected,
                    "byte {index} survived: decode and decrypt both passed"
                );
            }
        }
    }
}
