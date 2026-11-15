//! Passphrase-encrypted backup of the identity seed (IDN-06).
//!
//! [`export_backup`] encrypts an [`Identity`]'s seed under a passphrase
//! with Argon2id and XChaCha20-Poly1305; [`import_backup`] rebuilds the
//! identity and verifies that its seed derives the `NodeId` recorded in
//! the blob, so a backup can never silently import as a different
//! identity.
//!
//! ## Parameters
//!
//! Argon2id (RFC 9106, version 0x13) with OWASP's recommended
//! parameters: `m = 19456` KiB (19 MiB), `t = 2`, `p = 1`, 32-byte
//! output, 16-byte random salt - the parameters ADR-0001's suite
//! table points at ("documented in IDN-06"). The Argon2id output is
//! then domain-separated through HKDF under the ADR-0001 label
//! `aoheyra/idn/v1/backup` before it becomes the AEAD key.
//!
//! Imports accept at most `m = 32768` KiB (32 MiB), `t = 4`, `p = 4`
//! (twice the export parameters) and refuse anything larger *before*
//! allocating or hashing, so a hostile file cannot drive the KDF.
//!
//! ## Layout (version 1, fixed 114 bytes)
//!
//! ```text
//! [0]        version = 1
//! [1..5]     m_cost   u32 BE
//! [5..9]     t_cost   u32 BE
//! [9]        lanes    u8
//! [10..26]   salt     16 bytes
//! [26..50]   nonce    24 bytes
//! [50..66]   recorded NodeId, plaintext: public information, and
//!            verified by derivation after decryption, not by the AEAD
//! [66..114]  XChaCha20-Poly1305(seed): 32-byte ciphertext + 16-byte tag
//! ```
//!
//! The AEAD's associated data is `[0..26]` (version, parameters,
//! salt): tampering with any of them changes the derived key or fails
//! the tag, while the `NodeId` field is deliberately left to the
//! derivation check, which is what the issue asks import to verify.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::identity::{Identity, hkdf_expand};
use crate::seal::{NONCE_LEN, cipher_from};
use crate::types::{IdentError, NodeId};

/// Format version of the backup blob.
const BACKUP_VERSION: u8 = 1;

/// Argon2id salt length.
const SALT_LEN: usize = 16;

/// Retained seed length.
const SEED_LEN: usize = 32;

/// `version ‖ m_cost ‖ t_cost ‖ lanes ‖ salt`: the AEAD's associated
/// data, and everything the KDF reads.
const AAD_LEN: usize = 1 + 4 + 4 + 1 + SALT_LEN;

/// Offset of the recorded `NodeId`, after `AAD ‖ nonce`.
const NODE_ID_OFFSET: usize = AAD_LEN + NONCE_LEN;

/// Offset of the sealed seed, after the recorded `NodeId`.
const SEED_OFFSET: usize = NODE_ID_OFFSET + 16;

/// Total length of a version-1 backup: header + seed + tag.
const BACKUP_LEN: usize = SEED_OFFSET + SEED_LEN + 16;

/// Argon2id parameters for new exports: OWASP's Argon2id
/// recommendation (m = 19 MiB, t = 2, p = 1).
const M_COST_KIB: u32 = 19_456;
const T_COST: u32 = 2;
const LANES: u8 = 1;

/// Import-side caps: twice the export parameters, so a hostile file
/// can never make this build hash much more than a legitimate one.
/// A backup written with stronger parameters than this build allows
/// is refused as [`IdentError::InvalidBackupParams`], not attempted.
const MAX_M_COST_KIB: u32 = 32_768;
const MAX_T_COST: u32 = 4;
const MAX_LANES: u8 = 4;

/// ADR-0001 HKDF label separating the backup key from any other use
/// of Argon2id output.
const INFO_BACKUP: &str = "aoheyra/idn/v1/backup";

/// An exported backup: fixed-size opaque bytes, safe to write to
/// disk. `Debug` reports only the length, never contents.
#[derive(Clone, PartialEq, Eq)]
pub struct BackupBlob(Vec<u8>);

impl BackupBlob {
    /// The blob bytes, ready to persist. [`import_backup`] validates
    /// them again on the way back in.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for BackupBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BackupBlob")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Encrypt `identity`'s seed under `passphrase` for offline storage.
///
/// The salt and nonce come from the injected `rng`, so two exports of
/// the same identity differ byte for byte. An empty passphrase is
/// [`IdentError::EmptyPassphrase`]: a backup must never be sealed
/// under a guessable key.
///
/// # Errors
///
/// [`IdentError::EmptyPassphrase`] for an empty passphrase.
pub fn export_backup<R: RngCore + CryptoRng + ?Sized>(
    identity: &Identity,
    passphrase: &str,
    rng: &mut R,
) -> Result<BackupBlob, IdentError> {
    if passphrase.is_empty() {
        return Err(IdentError::EmptyPassphrase);
    }

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut blob = Vec::with_capacity(BACKUP_LEN);
    blob.push(BACKUP_VERSION);
    blob.extend_from_slice(&M_COST_KIB.to_be_bytes());
    blob.extend_from_slice(&T_COST.to_be_bytes());
    blob.push(LANES);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(identity.node_id().as_bytes());

    let cipher = cipher_from(derive_key(passphrase, &salt, M_COST_KIB, T_COST, LANES)?);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: identity.seed(),
                aad: &blob[..AAD_LEN],
            },
        )
        // A 32-byte message under a fresh key cannot exceed the AEAD's
        // size limits; map the impossible case to a typed error.
        .map_err(|_| IdentError::MalformedBackup)?;
    blob.extend_from_slice(&sealed);

    debug_assert_eq!(blob.len(), BACKUP_LEN, "version-1 layout is fixed");
    Ok(BackupBlob(blob))
}

/// Decrypt `bytes` and rebuild the identity it records, verifying that
/// the seed derives the recorded `NodeId`.
///
/// The stored Argon2id parameters are capped before any allocation;
/// the passphrase is checked by the AEAD tag; the final derivation
/// check catches a blob whose `NodeId` disagrees with its seed (a
/// tampered header, or a future change to the derivation).
///
/// # Errors
///
/// - [`IdentError::MalformedBackup`]: wrong length or version.
/// - [`IdentError::InvalidBackupParams`]: stored KDF parameters
///   outside the supported bounds, refused before hashing.
/// - [`IdentError::InvalidPassphrase`]: wrong passphrase, empty
///   passphrase, or a tampered ciphertext.
/// - [`IdentError::IdentityMismatch`]: the decrypted seed does not
///   derive the recorded `NodeId`.
pub fn import_backup(bytes: &[u8], passphrase: &str) -> Result<Identity, IdentError> {
    if bytes.len() != BACKUP_LEN || bytes[0] != BACKUP_VERSION {
        return Err(IdentError::MalformedBackup);
    }
    if passphrase.is_empty() {
        return Err(IdentError::InvalidPassphrase);
    }

    let m_cost = u32::from_be_bytes(
        bytes[1..5]
            .try_into()
            .map_err(|_| IdentError::MalformedBackup)?,
    );
    let t_cost = u32::from_be_bytes(
        bytes[5..9]
            .try_into()
            .map_err(|_| IdentError::MalformedBackup)?,
    );
    let lanes = bytes[9];
    if m_cost > MAX_M_COST_KIB || t_cost > MAX_T_COST || lanes == 0 || lanes > MAX_LANES {
        return Err(IdentError::InvalidBackupParams);
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[10..AAD_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[AAD_LEN..NODE_ID_OFFSET]);
    let mut recorded = [0u8; 16];
    recorded.copy_from_slice(&bytes[NODE_ID_OFFSET..SEED_OFFSET]);

    let cipher = cipher_from(derive_key(passphrase, &salt, m_cost, t_cost, lanes)?);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes[SEED_OFFSET..],
                    aad: &bytes[..AAD_LEN],
                },
            )
            .map_err(|_| IdentError::InvalidPassphrase)?,
    );
    if plaintext.len() != SEED_LEN {
        // The tag check above guarantees 32 bytes; still a typed
        // error rather than a slice panic.
        return Err(IdentError::MalformedBackup);
    }

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    let identity = Identity::from_seed(*seed);
    if identity.node_id().as_bytes() != &recorded {
        return Err(IdentError::IdentityMismatch(NodeId::from_bytes(recorded)));
    }
    Ok(identity)
}

/// Argon2id over the passphrase, then HKDF under the ADR-0001 backup
/// label. Every failure - out-of-bounds parameters, an impossible
/// salt - maps to [`IdentError::InvalidBackupParams`]; nothing here
/// panics on caller input.
fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    lanes: u8,
) -> Result<[u8; 32], IdentError> {
    let params = Params::new(m_cost, t_cost, u32::from(lanes), None)
        .map_err(|_| IdentError::InvalidBackupParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *raw)
        .map_err(|_| IdentError::InvalidBackupParams)?;
    Ok(hkdf_expand(&raw, INFO_BACKUP.as_bytes()))
}
