//! Passphrase-encrypted backup of the identity seed (IDN-06).
//!
//! Covers the done-when (export then import reproduces the identical
//! identity; a wrong passphrase fails cleanly) plus the empty-
//! passphrase refusal, the parameter caps, the structural errors,
//! the NodeId verification and the hostile-input class.

mod common;

use ao_idents::{BackupBlob, IdentError, Identity, export_backup, import_backup};
use common::TestRng;

fn identity(state: u64) -> Identity {
    Identity::generate(&mut TestRng::new(state))
}

fn export(identity: &Identity, passphrase: &str) -> BackupBlob {
    export_backup(identity, passphrase, &mut TestRng::new(7)).expect("non-empty passphrase")
}

/// The done-when, first half: export then import reproduces the
/// identical identity - same NodeId, same keys, same binding.
#[test]
fn export_then_import_reproduces_the_identical_identity() {
    let original = identity(1);
    let blob = export(&original, "correct horse battery staple");
    let restored = import_backup(blob.as_bytes(), "correct horse battery staple")
        .expect("the same passphrase opens the backup");

    assert_eq!(
        restored.node_id(),
        original.node_id(),
        "the imported identity must be the exported one"
    );
    assert_eq!(restored.suite(), original.suite());
    let (exported, imported) = (original.public(), restored.public());
    assert_eq!(exported.signing_pk(), imported.signing_pk());
    assert_eq!(exported.agreement_pk(), imported.agreement_pk());
    assert_eq!(exported.agreement_binding(), imported.agreement_binding());
}

/// The done-when, second half: a wrong passphrase fails cleanly -
/// a typed error, no panic, no partial identity.
#[test]
fn wrong_passphrase_fails_cleanly() {
    let original = identity(2);
    let blob = export(&original, "the real passphrase");
    assert_eq!(
        import_backup(blob.as_bytes(), "not the passphrase").expect_err("must not import"),
        IdentError::InvalidPassphrase
    );
}

/// A backup is never sealed under a guessable key: export refuses an
/// empty passphrase.
#[test]
fn empty_passphrase_is_refused_at_export() {
    assert_eq!(
        export_backup(&identity(3), "", &mut TestRng::new(7)),
        Err(IdentError::EmptyPassphrase)
    );
}

/// Import refuses an empty passphrase before touching the KDF (a
/// legitimate backup can never have one, since export refuses it).
#[test]
fn empty_passphrase_is_refused_at_import() {
    let blob = export(&identity(4), "secret");
    assert_eq!(
        import_backup(blob.as_bytes(), "").expect_err("must not import"),
        IdentError::InvalidPassphrase
    );
}

/// One flipped ciphertext byte fails authentication: wrong passphrase
/// or tampered blob, the same typed error, never a partial identity.
#[test]
fn tampered_ciphertext_fails_authentication() {
    let blob = export(&identity(5), "secret");
    let mut bytes = blob.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert_eq!(
        import_backup(&bytes, "secret").expect_err("must not import"),
        IdentError::InvalidPassphrase
    );
}

/// The recorded NodeId is verified by derivation: flipping it in the
/// header still decrypts (it is not under the AEAD) but must not
/// import as a different identity.
#[test]
fn tampered_recorded_node_id_is_rejected() {
    let blob = export(&identity(6), "secret");
    let mut bytes = blob.as_bytes().to_vec();
    bytes[50] ^= 0x01; // recorded NodeId starts at offset 50 (layout in src/backup.rs)
    assert!(matches!(
        import_backup(&bytes, "secret"),
        Err(IdentError::IdentityMismatch(_))
    ));
}

/// Hostile KDF parameters are refused before any hashing: the
/// m_cost field is overwritten with `u32::MAX` and the import must
/// reject it as out of bounds rather than allocate 4 TiB.
#[test]
fn hostile_kdf_parameters_are_refused_before_hashing() {
    let blob = export(&identity(7), "secret");
    let mut bytes = blob.as_bytes().to_vec();
    bytes[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        import_backup(&bytes, "secret").expect_err("must not import"),
        IdentError::InvalidBackupParams
    );
}

/// Structural damage is a typed error: empty, truncated, over-long
/// and unknown-version inputs never panic.
#[test]
fn structural_damage_is_a_typed_error() {
    let blob = export(&identity(8), "secret");
    let bytes = blob.as_bytes();

    assert_eq!(
        import_backup(&[], "secret").expect_err("empty input"),
        IdentError::MalformedBackup
    );
    assert_eq!(
        import_backup(&bytes[..bytes.len() - 1], "secret").expect_err("truncated"),
        IdentError::MalformedBackup
    );
    let mut overlong = bytes.to_vec();
    overlong.push(0);
    assert_eq!(
        import_backup(&overlong, "secret").expect_err("over-long"),
        IdentError::MalformedBackup
    );
    let mut wrong_version = bytes.to_vec();
    wrong_version[0] = 2;
    assert_eq!(
        import_backup(&wrong_version, "secret").expect_err("unknown version"),
        IdentError::MalformedBackup
    );
}

/// Fresh salt and nonce per export: two exports of the same identity
/// from one advancing RNG stream differ byte for byte, and both
/// import. (A restarted RNG must reproduce the same bytes - that
/// determinism is the sans-IO contract.)
#[test]
fn exports_are_randomised_per_call() {
    let original = identity(9);
    let mut rng = TestRng::new(9);
    let first = export_backup(&original, "secret", &mut rng).expect("non-empty passphrase");
    let second = export_backup(&original, "secret", &mut rng).expect("non-empty passphrase");
    assert_ne!(
        first, second,
        "each export must draw a fresh salt and nonce from the RNG"
    );
    import_backup(first.as_bytes(), "secret").expect("first opens");
    import_backup(second.as_bytes(), "secret").expect("second opens");

    let mut restarted = TestRng::new(9);
    let again = export_backup(&original, "secret", &mut restarted).expect("non-empty passphrase");
    assert_eq!(
        first, again,
        "the same RNG state must reproduce the same bytes"
    );
}

/// Argon2id takes passphrase bytes: non-ASCII and long passphrases
/// round-trip like any other.
#[test]
fn unicode_and_long_passphrases_round_trip() {
    let original = identity(10);
    let long = "x".repeat(1024);
    for passphrase in ["пароль-батарейка-🔐", long.as_str()] {
        let blob = export(&original, passphrase);
        let restored = import_backup(blob.as_bytes(), passphrase).expect("round trip");
        assert_eq!(restored.node_id(), original.node_id());
    }
}

/// The `Debug` output reports only the length, never contents: the
/// blob carries the encrypted seed.
#[test]
fn debug_reports_length_only() {
    let blob = export(&identity(11), "secret");
    let printed = format!("{blob:?}");
    assert!(printed.contains("BackupBlob"));
    assert!(printed.contains("len"));
    assert!(!printed.contains(&hex(blob.as_bytes())));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

        /// Arbitrary bytes never panic: every malformed input is a
        /// typed error. Most random inputs fail the fixed-length
        /// check before any KDF runs.
        #[test]
        fn import_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..160),
            passphrase in ".{0,64}",
        ) {
            let _ = import_backup(&bytes, &passphrase);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_runtime(16))]

        /// Round-trip for arbitrary non-empty passphrases. Each case
        /// runs Argon2id twice by design (export and import), so the
        /// case count is deliberately small; the property itself is
        /// deterministic given the inputs.
        #[test]
        fn export_import_round_trips_for_arbitrary_passphrases(
            state in any::<u64>(),
            passphrase in ".{1,64}",
        ) {
            let original = Identity::generate(&mut TestRng::new(state));
            let blob = export_backup(
                &original,
                &passphrase,
                &mut TestRng::new(state.wrapping_add(1)),
            )
            .expect("non-empty passphrase");
            let restored = import_backup(blob.as_bytes(), &passphrase).expect("same passphrase");
            prop_assert_eq!(restored.node_id(), original.node_id());
        }
    }
}
