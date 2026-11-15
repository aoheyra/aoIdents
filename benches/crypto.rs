//! Criterion benches for the ao_idents hot paths (README, Development).
//!
//! Deterministic input only: fixed seeds and the splitmix64 test
//! stream from `tests/common`, so runs compare across machines.

#[path = "../tests/common/mod.rs"]
mod common;

use ao_idents::{Identity, IdentityCard, MSG_ID_LEN, SealedMessage};
use common::TestRng;
use criterion::{criterion_group, criterion_main};
use std::hint::black_box;

/// A valid registered domain (ADR-0001 format rules).
const CTX: &str = "aoheyra/idn/v1/bench";

fn identity(c: &mut criterion::Criterion) {
    let seed = [7u8; 32];
    c.bench_function("identity_from_seed", |b| {
        b.iter(|| Identity::from_seed(black_box(seed)))
    });
}

fn sign_verify(c: &mut criterion::Criterion) {
    let id = Identity::from_seed([7u8; 32]);
    c.bench_function("sign", |b| {
        b.iter(|| {
            id.sign(CTX, black_box(b"bench payload"))
                .expect("valid ctx")
        })
    });

    let msg = b"bench payload";
    let sig = id.sign(CTX, msg).expect("valid ctx");
    c.bench_function("verify", |b| {
        b.iter(|| {
            id.public()
                .verify(CTX, black_box(msg), &sig)
                .expect("valid signature")
        })
    });
}

fn seal_open(c: &mut criterion::Criterion) {
    let alice = Identity::from_seed([1u8; 32]);
    let bob = Identity::from_seed([2u8; 32]);
    let msg_id = [3u8; MSG_ID_LEN];
    let mut rng = TestRng::new(42);

    c.bench_function("seal", |b| {
        b.iter(|| {
            SealedMessage::seal(
                &alice,
                bob.public(),
                &msg_id,
                black_box(b"plaintext"),
                &mut rng,
            )
            .expect("seals")
        })
    });

    let sealed =
        SealedMessage::seal(&alice, bob.public(), &msg_id, b"plaintext", &mut rng).expect("seals");
    c.bench_function("open", |b| {
        b.iter(|| sealed.open(black_box(&bob), &msg_id).expect("opens"))
    });
}

fn card(c: &mut criterion::Criterion) {
    let id = Identity::from_seed([5u8; 32]);
    c.bench_function("card_create", |b| {
        b.iter(|| {
            id.card(black_box(b"Alice"), 1_700_000_000)
                .expect("valid name")
        })
    });

    let created = id.card(b"Alice", 1_700_000_000).expect("valid name");
    let encoded = created.encode();
    c.bench_function("card_decode", |b| {
        b.iter(|| IdentityCard::decode(black_box(&encoded)).expect("valid card"))
    });

    let qr = created.to_qr_string();
    c.bench_function("card_qr_roundtrip", |b| {
        b.iter(|| IdentityCard::from_qr_string(black_box(&qr)).expect("valid qr"))
    });
}

criterion_group!(benches, identity, sign_verify, seal_open, card);
criterion_main!(benches);
