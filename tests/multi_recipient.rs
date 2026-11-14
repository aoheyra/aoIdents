//! Multi-recipient sealed messages (IDN-10).
//!
//! Covers the done-when (every listed recipient opens it,
//! non-recipients cannot, ciphertext growth per recipient is
//! documented and asserted) plus duplicates, the recipient cap,
//! tampering, malformed encodings and proptests.

mod common;

use ao_idents::{
    IdentError, Identity, MAX_RECIPIENTS, MSG_ID_LEN, MultiSealedMessage, RECIPIENT_WRAP_LEN,
};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn msg_id() -> [u8; MSG_ID_LEN] {
    *b"multi-msg-id-001"
}

/// A sender and `n` recipients, deterministic under `TestRng`.
fn parties(n: usize) -> (Identity, Vec<Identity>) {
    let sender = identity(1);
    let recipients = (0..n)
        .map(|i| identity(10 + u64::try_from(i).expect("small")))
        .collect();
    (sender, recipients)
}

fn seal(sender: &Identity, recipients: &[&Identity], plaintext: &[u8]) -> MultiSealedMessage {
    let pubs: Vec<_> = recipients.iter().map(|r| r.public()).collect();
    MultiSealedMessage::seal(sender, &pubs, &msg_id(), plaintext, &mut TestRng::new(7))
        .expect("test plaintext fits")
}

/// The done-when: every listed recipient opens the same ciphertext
/// and sees the same authenticated sender.
#[test]
fn every_listed_recipient_opens_it() {
    let (sender, recipients) = parties(4);
    let plaintext = b"hello to all four of you";
    let refs: Vec<&Identity> = recipients.iter().collect();
    let sealed = seal(&sender, &refs, plaintext);

    for recipient in &recipients {
        let opened = sealed.open(recipient).expect("listed recipient opens");
        assert_eq!(opened.plaintext(), plaintext);
        assert_eq!(opened.sender(), sender.public());
    }
}

/// The done-when, negative half: an identity outside the recipient
/// list cannot open it.
#[test]
fn a_non_recipient_cannot_open_it() {
    let (sender, recipients) = parties(3);
    let outsider = identity(99);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let sealed = seal(&sender, &refs, b"members only");

    assert!(matches!(
        sealed.open(&outsider),
        Err(IdentError::OpenFailed)
    ));
}

/// The done-when, growth: each recipient adds exactly
/// `RECIPIENT_WRAP_LEN` bytes and nothing else - the ciphertext
/// length depends only on the plaintext.
#[test]
fn ciphertext_growth_per_recipient_is_documented() {
    let (sender, recipients) = parties(MAX_RECIPIENTS);
    let plaintext = b"constant plaintext";
    let single = seal(&sender, &[&recipients[0]], plaintext);

    for count in 1..=MAX_RECIPIENTS {
        let refs: Vec<&Identity> = recipients[..count].iter().collect();
        let sealed = seal(&sender, &refs, plaintext);
        assert_eq!(
            sealed.encode().len(),
            single.encode().len() + (count - 1) * RECIPIENT_WRAP_LEN,
            "recipient {count} adds exactly {RECIPIENT_WRAP_LEN} bytes"
        );
        assert_eq!(sealed.wraps().len(), count * RECIPIENT_WRAP_LEN);
    }
}

/// The encoding survives a decode round trip and still opens.
#[test]
fn encode_decode_round_trip_still_opens() {
    let (sender, recipients) = parties(3);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let sealed = seal(&sender, &refs, b"round trip");

    let decoded = MultiSealedMessage::decode(&sealed.encode()).expect("round trip");
    assert_eq!(decoded, sealed);
    for recipient in &recipients {
        assert_eq!(
            decoded
                .open(recipient)
                .expect("opens after round trip")
                .plaintext(),
            b"round trip"
        );
    }
}

/// Zero recipients and over the cap are typed errors before any
/// crypto runs.
#[test]
fn recipient_count_bounds_are_enforced() {
    let (sender, recipients) = parties(1);
    let empty: [&Identity; 0] = [];
    let pubs: Vec<_> = empty.iter().map(|r| r.public()).collect();
    assert!(matches!(
        MultiSealedMessage::seal(&sender, &pubs, &msg_id(), b"x", &mut TestRng::new(1)),
        Err(IdentError::NoRecipients)
    ));

    let too_many: Vec<Identity> = (0..MAX_RECIPIENTS + 1)
        .map(|i| identity(200 + u64::try_from(i).expect("small")))
        .collect();
    let refs: Vec<&Identity> = too_many.iter().collect();
    let pubs: Vec<_> = refs.iter().map(|r| r.public()).collect();
    assert!(matches!(
        MultiSealedMessage::seal(&sender, &pubs, &msg_id(), b"x", &mut TestRng::new(1)),
        Err(IdentError::TooManyRecipients)
    ));
    let _ = recipients;
}

/// The same identity listed twice is rejected: it would otherwise
/// produce two wraps for one key.
#[test]
fn a_duplicate_recipient_is_rejected() {
    let (sender, recipients) = parties(1);
    let dup = recipients[0].public();
    let pubs = [dup, dup];
    assert!(matches!(
        MultiSealedMessage::seal(&sender, &pubs, &msg_id(), b"x", &mut TestRng::new(1)),
        Err(IdentError::DuplicateRecipient(_))
    ));
}

/// A plaintext over the 65535-byte ciphertext field is refused.
#[test]
fn an_oversize_plaintext_is_refused() {
    let (sender, recipients) = parties(1);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let pubs: Vec<_> = refs.iter().map(|r| r.public()).collect();
    let oversized = vec![0u8; u16::MAX as usize];
    assert!(matches!(
        MultiSealedMessage::seal(&sender, &pubs, &msg_id(), &oversized, &mut TestRng::new(1)),
        Err(IdentError::PayloadTooLarge)
    ));
}

/// Flipping any single byte fails for everyone in the shared parts
/// (header, ciphertext length, ciphertext) and - exactly - for the
/// one recipient whose wrap was hit: a corrupted wrap denies service
/// to that recipient only, which is the documented design.
#[test]
fn every_single_byte_corruption_fails() {
    let (sender, recipients) = parties(3);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let bytes = seal(&sender, &refs, b"corrupt me").encode();

    let prefix_end = 1 + MSG_ID_LEN + 24 + 1;
    let wraps_end = prefix_end + 3 * RECIPIENT_WRAP_LEN;

    for index in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 0x01;
        let decoded = MultiSealedMessage::decode(&corrupted);

        if index < prefix_end || index >= wraps_end {
            // Shared material: nothing may open.
            for recipient in &recipients {
                let result = match &decoded {
                    Ok(m) => m.open(recipient).map(|_| ()).map_err(|_| ()),
                    Err(_) => Err(()),
                };
                assert!(result.is_err(), "shared byte {index} must not open");
            }
            continue;
        }

        // A wrap belongs to exactly one recipient; the others are
        // untouched by it and must still open.
        let owner = (index - prefix_end) / RECIPIENT_WRAP_LEN;
        for (i, recipient) in recipients.iter().enumerate() {
            let result = match &decoded {
                Ok(m) => m.open(recipient).map(|_| ()).map_err(|_| ()),
                Err(_) => Err(()),
            };
            if i == owner {
                assert!(result.is_err(), "byte {index} must not open for its owner");
            } else {
                assert!(result.is_ok(), "byte {index} must not affect recipient {i}");
            }
        }
    }
}

/// A wrap addressed to another recipient is ignored: the outsider's
/// slot never yields a content key even though the bytes parse.
#[test]
fn another_recipients_wrap_cannot_be_reused() {
    let (sender, recipients) = parties(3);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let sealed = seal(&sender, &refs, b"slot check");

    // Every wrap but the first recipient's must fail for them.
    let mine = &recipients[0].public().agreement_pk()[..8];
    let wraps = sealed.wraps();
    let mut foreign_only = Vec::new();
    for wrap in wraps.chunks_exact(RECIPIENT_WRAP_LEN) {
        if wrap[..8] != mine[..] {
            foreign_only.extend_from_slice(wrap);
        }
    }
    assert!(!foreign_only.is_empty(), "other recipients have wraps");
    // Build an encoding with only the foreign wraps: recipient 0
    // must fail to find a content key.
    let encoded = sealed.encode();
    // Prefix up to (but excluding) the wraps_len byte, then rebuild.
    let prefix_end = 1 + MSG_ID_LEN + 24;
    let mut rebuilt = encoded[..prefix_end].to_vec();
    rebuilt.push((foreign_only.len() / RECIPIENT_WRAP_LEN) as u8);
    rebuilt.extend_from_slice(&foreign_only);
    let ct_len = (sealed.ciphertext().len() as u16).to_be_bytes();
    rebuilt.extend_from_slice(&ct_len);
    rebuilt.extend_from_slice(sealed.ciphertext());

    let tampered = MultiSealedMessage::decode(&rebuilt).expect("parses");
    assert!(matches!(
        tampered.open(&recipients[0]),
        Err(IdentError::OpenFailed)
    ));
}

/// Malformed encodings are typed errors, never panics: truncation,
/// trailing bytes, zero wraps and an oversize wrap count.
#[test]
fn malformed_encodings_are_typed_errors() {
    let (sender, recipients) = parties(2);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let bytes = seal(&sender, &refs, b"malformed").encode();

    // Truncated at every length.
    for len in 0..bytes.len() {
        assert!(
            MultiSealedMessage::decode(&bytes[..len]).is_err(),
            "truncated to {len} must fail"
        );
    }
    // Trailing byte.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(MultiSealedMessage::decode(&trailing).is_err());

    // Zero wraps.
    let mut zero = bytes.clone();
    zero[1 + MSG_ID_LEN + 24] = 0;
    assert_eq!(
        MultiSealedMessage::decode(&zero),
        Err(IdentError::NoRecipients)
    );

    // Wrap count over the cap.
    let mut over = bytes;
    over[1 + MSG_ID_LEN + 24] = u8::try_from(MAX_RECIPIENTS + 1).expect("small");
    assert_eq!(
        MultiSealedMessage::decode(&over),
        Err(IdentError::TooManyRecipients)
    );
}

/// The `Debug` output never carries ciphertext or wrap bytes.
#[test]
fn debug_never_prints_contents() {
    let (sender, recipients) = parties(2);
    let refs: Vec<&Identity> = recipients.iter().collect();
    let sealed = seal(&sender, &refs, b"secret contents");

    let debugged = format!("{sealed:?}");
    assert!(debugged.contains("MultiSealedMessage"));
    assert!(!debugged.contains("secret contents"));
    assert!(!debugged.contains(&hex(sealed.ciphertext())));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Arbitrary plaintexts round trip for every listed recipient.
        #[test]
        fn arbitrary_plaintext_round_trips(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
            let (sender, recipients) = parties(3);
            let refs: Vec<&Identity> = recipients.iter().collect();
            let sealed = seal(&sender, &refs, &plaintext);
            let decoded = MultiSealedMessage::decode(&sealed.encode()).expect("round trip");
            for recipient in &recipients {
                let opened = decoded.open(recipient).expect("opens");
                prop_assert_eq!(opened.plaintext(), &plaintext[..]);
            }
        }

        /// Arbitrary bytes never panic on decode.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            if let Ok(message) = MultiSealedMessage::decode(&bytes) {
                // A decoded message may still be opened; that must
                // be a typed error, never a panic.
                let (sender, recipients) = parties(1);
                let _ = message.open(&recipients[0]);
                let _ = sender;
            }
        }
    }
}
