//! Rotating link tags and beacon hints (IDN-12).
//!
//! Covers the done-when (successive epochs statistically unlinkable;
//! the derived mode lets a contact recompute the tag) plus the epoch
//! validation, stability, jitter and hint contract.

mod common;

use std::collections::HashSet;

use ao_idents::{EPOCH_MAX_MS, EPOCH_MIN_MS, IdentError, Identity, RotatingTag};
use common::TestRng;

fn baseline(state: u64) -> RotatingTag {
    RotatingTag::random(&mut TestRng::new(state))
}

/// The done-when: a tag is stable inside its epoch and rotates at the
/// boundary; epoch indices are consecutive across it.
#[test]
fn tag_is_stable_within_an_epoch_and_rotates_at_the_boundary() {
    let tag = baseline(5);
    let len = tag.epoch_len_ms();
    assert!((EPOCH_MIN_MS..=EPOCH_MAX_MS).contains(&len));

    // Far enough from zero that the phase offset cannot saturate the
    // boundary arithmetic.
    let start = tag.epoch_start(len * 1000);
    assert!(start > 0);
    assert_eq!(tag.tag(start), tag.tag(start + len - 1));
    assert_eq!(tag.hint(start), tag.hint(start + len - 1));
    assert_eq!(tag.epoch_index(start), tag.epoch_index(start + len - 1));

    assert_ne!(tag.tag(start + len - 1), tag.tag(start + len));
    assert_eq!(tag.epoch_index(start + len), tag.epoch_index(start) + 1);
}

/// The done-when, baseline mode: over 512 successive epochs no tag
/// repeats, no tag matches or contains any part of the identity's
/// key material, and per-byte-position values are spread out - the
/// statistical picture of unlinkability to the `NodeId`.
#[test]
fn baseline_tags_are_statistically_unlinkable_to_the_identity() {
    let id = Identity::generate(&mut TestRng::new(77));
    let node_id = *id.node_id().as_bytes();
    let mut keys = Vec::new();
    keys.extend_from_slice(id.public().signing_pk());
    keys.extend_from_slice(id.public().agreement_pk());

    let tag = baseline(99);
    let len = tag.epoch_len_ms();
    // now = k * len lands in epoch exactly k (offset < len), so these
    // are 512 successive epochs.
    let tags: Vec<[u8; 16]> = (1..=512).map(|k| tag.tag(k * len)).collect();

    // No repetition across epochs.
    let unique: HashSet<[u8; 16]> = tags.iter().copied().collect();
    assert_eq!(
        unique.len(),
        tags.len(),
        "every epoch must have its own tag"
    );

    // No tag equals or contains any 16-byte window of the identity.
    for (k, t) in tags.iter().enumerate() {
        assert_ne!(t, &node_id, "tag of epoch {k} must not be the NodeId");
        for window in keys.windows(16) {
            assert!(t != window, "tag of epoch {k} must not repeat key material");
        }
    }

    // Per byte position, values must be spread across epochs: 512
    // samples over 256 possible byte values give an expected ~162
    // distinct values; 32 is a conservative floor that any
    // identity-derived or constant tag would fail.
    for position in 0..16 {
        let distinct: HashSet<u8> = tags.iter().map(|t| t[position]).collect();
        assert!(
            distinct.len() >= 32,
            "byte position {position} only takes {} distinct values over 512 epochs",
            distinct.len()
        );
    }

    // Successive epochs must differ in most bytes: independent uniform
    // tags differ in an expected 8 of 16; 7 is the floor (the observed
    // mean over this fixed seed is recorded by the assertion margin).
    let mean_diff: f64 = tags
        .windows(2)
        .map(|pair| (0..16).filter(|i| pair[0][*i] != pair[1][*i]).count() as f64)
        .sum::<f64>()
        / (tags.len() - 1) as f64;
    assert!(
        mean_diff >= 7.0,
        "successive tags differ in only {mean_diff:.2} of 16 bytes on average"
    );
}

/// Same RNG stream, same tags; a different device, different tags.
#[test]
fn baseline_is_deterministic_per_seed_and_differs_across_devices() {
    let a = baseline(1);
    let b = baseline(1);
    let c = baseline(2);
    let now = a.epoch_len_ms() * 1000;
    assert_eq!(a.tag(now), b.tag(now));
    assert_ne!(a.tag(now), c.tag(now));
}

/// The done-when, pairwise mode: a contact holding the same secret
/// recomputes the identical tag and hint from the same time; a
/// different secret cannot; the tag still rotates per epoch.
#[test]
fn pairwise_mode_lets_a_contact_recompute_the_tag() {
    let secret = [7u8; 32];
    let alice = RotatingTag::pairwise(secret, 600_000).expect("10 minutes is in range");
    let bob = RotatingTag::pairwise(secret, 600_000).expect("10 minutes is in range");
    for now in [0, 600_000, 1_234_567, 9_999_999, 86_400_000] {
        assert_eq!(
            alice.tag(now),
            bob.tag(now),
            "contact must recompute at {now}"
        );
        assert_eq!(alice.hint(now), bob.hint(now));
    }
    assert_ne!(alice.tag(600_000), alice.tag(1_200_000), "must rotate");

    let eve = RotatingTag::pairwise([8u8; 32], 600_000).expect("10 minutes is in range");
    assert_ne!(eve.tag(600_000), alice.tag(600_000));
}

/// Epoch lengths outside 10-15 minutes are a typed error, both sides
/// of the range.
#[test]
fn epoch_length_outside_ten_to_fifteen_minutes_is_rejected() {
    let secret = [0u8; 32];
    for bad in [0, EPOCH_MIN_MS - 1, EPOCH_MAX_MS + 1, u64::MAX] {
        assert!(
            matches!(
                RotatingTag::pairwise(secret, bad),
                Err(IdentError::InvalidEpochLength)
            ),
            "epoch length {bad} must be rejected"
        );
    }
    assert!(RotatingTag::pairwise(secret, EPOCH_MIN_MS).is_ok());
    assert!(RotatingTag::pairwise(secret, EPOCH_MAX_MS).is_ok());
}

/// The hint is exactly the first 8 bytes of the tag in both modes, so
/// a beacon receiver's check cannot drift from the full tag.
#[test]
fn hint_is_the_first_eight_bytes_of_the_tag() {
    let tag = baseline(3);
    let now = tag.epoch_len_ms() * 1000;
    assert_eq!(&tag.hint(now)[..], &tag.tag(now)[..8]);

    let pairwise = RotatingTag::pairwise([1u8; 32], 720_000).expect("12 minutes is in range");
    assert_eq!(&pairwise.hint(42)[..], &pairwise.tag(42)[..8]);
}

/// Secrets never leak through `Debug`.
#[test]
fn debug_prints_parameters_not_secrets() {
    let tag = RotatingTag::pairwise([203u8; 32], 600_000).expect("10 minutes is in range");
    let printed = format!("{tag:?}");
    assert!(printed.contains("pairwise"), "mode is printed: {printed}");
    assert!(
        printed.contains("epoch_len_ms"),
        "parameters are printed: {printed}"
    );
    assert!(
        !printed.contains("203"),
        "the pairwise secret must not be printed: {printed}"
    );
}
