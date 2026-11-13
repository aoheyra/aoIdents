//! KeyStore: persistence for sealed secret blobs (IDN-05).
//!
//! Covers the done-when (round trip through a mock store; no clear
//! secret reaches a trait method) plus every bound and the backend
//! error variant.

use ao_idents::{
    IdentError, KeyStore, MAX_BLOB_BYTES, MAX_ENTRIES, MAX_KEY_ID_BYTES, MemoryKeyStore, SealedBlob,
};

/// The test's stand-in for aoheyra's device keystore: "sealing" by
/// XOR, only so the store receives something that is not the clear
/// secret. The real sealer lives in aoheyra (AND-13).
fn seal_for_store(clear: &[u8], key: u8) -> Vec<u8> {
    clear.iter().map(|byte| byte ^ key).collect()
}

/// The done-when: a blob survives store and load byte-for-byte, the
/// store never holds the clear secret, and delete removes it.
#[test]
fn round_trip_through_a_mock_store() {
    let clear = b"32-byte identity seed in clear text".to_vec();
    let sealed = seal_for_store(&clear, 0x5A);

    let mut store = MemoryKeyStore::new();
    store
        .store(
            "primary",
            SealedBlob::new(sealed.clone()).expect("within the blob limit"),
        )
        .expect("store succeeds");

    let loaded = store
        .load("primary")
        .expect("load succeeds")
        .expect("present");
    assert_eq!(loaded.as_bytes(), sealed, "blob round trips unchanged");
    assert_ne!(
        loaded.as_bytes(),
        clear,
        "the store must never carry the clear secret"
    );

    assert!(store.delete("primary").expect("delete succeeds"));
    assert!(
        store.load("primary").expect("load succeeds").is_none(),
        "deleted key is gone"
    );
    assert!(!store.delete("primary").expect("delete succeeds"));
    assert!(store.load("absent").expect("load succeeds").is_none());
}

/// The store compiles as a trait object: aoheyra can box its own
/// backend behind the same interface.
#[test]
fn the_trait_is_object_safe() {
    let mut store: Box<dyn KeyStore> = Box::new(MemoryKeyStore::new());
    let blob = SealedBlob::new(vec![1, 2, 3]).expect("within the blob limit");
    store.store("slot", blob).expect("store succeeds");
    assert!(store.load("slot").expect("load succeeds").is_some());
}

/// Key ids over the limit fail on every operation - a typed error,
/// never a silent miss that looks like absence.
#[test]
fn key_id_over_the_limit_is_rejected() {
    let mut store = MemoryKeyStore::new();
    let too_long = "k".repeat(MAX_KEY_ID_BYTES + 1);
    let blob = SealedBlob::new(vec![7]).expect("within the blob limit");

    assert!(matches!(
        store.store(&too_long, blob.clone()),
        Err(IdentError::KeyRefTooLong)
    ));
    assert!(matches!(
        store.load(&too_long),
        Err(IdentError::KeyRefTooLong)
    ));
    assert!(matches!(
        store.delete(&too_long),
        Err(IdentError::KeyRefTooLong)
    ));

    // Exactly at the limit works.
    let exact = "k".repeat(MAX_KEY_ID_BYTES);
    store.store(&exact, blob).expect("at the limit");
    assert!(store.load(&exact).expect("load succeeds").is_some());
}

/// Blobs over the limit are rejected by the type's constructor,
/// before any store sees them; the exact limit is accepted.
#[test]
fn blob_over_the_limit_is_rejected() {
    let exact = vec![0xAB; MAX_BLOB_BYTES];
    assert!(SealedBlob::new(exact).is_ok());
    assert!(matches!(
        SealedBlob::new(vec![0; MAX_BLOB_BYTES + 1]),
        Err(IdentError::BlobTooLarge)
    ));
}

/// The store stops at its entry cap with a typed error; replacing an
/// existing key still works at capacity, because it grows nothing.
#[test]
fn store_at_capacity_is_rejected() {
    let mut store = MemoryKeyStore::new();
    for index in 0..MAX_ENTRIES {
        let blob = SealedBlob::new(vec![index as u8]).expect("small blob");
        store
            .store(&format!("key-{index}"), blob)
            .expect("under the cap");
    }

    let extra = SealedBlob::new(vec![0xFF]).expect("small blob");
    assert!(matches!(
        store.store("one-too-many", extra.clone()),
        Err(IdentError::StoreFull)
    ));

    // Overwriting an existing key at capacity is not growth.
    let replacement = SealedBlob::new(vec![0xEE]).expect("small blob");
    store
        .store("key-0", replacement.clone())
        .expect("replace at capacity");
    assert_eq!(
        store
            .load("key-0")
            .expect("load succeeds")
            .expect("present"),
        replacement
    );
}

/// Platform backends can report their own failure through the typed
/// variant, with context.
#[test]
fn backend_failures_carry_context() {
    let error = IdentError::StoreBackend("device keystore locked".to_owned());
    assert_eq!(
        error.to_string(),
        "key store backend failed: device keystore locked"
    );
}
