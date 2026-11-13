//! KeyStore: persistence for sealed secret blobs (IDN-05).
//!
//! The store never sees a secret in clear text - every method takes
//! or returns a [`SealedBlob`], an opaque byte bag the *caller*
//! sealed before handing it over (aoheyra seals with the Android
//! device keystore, AND-13). This crate holds no key that can open a
//! blob, so a leaked store is not a leaked identity.
//!
//! ```text
//! trait KeyStore { load, store, delete }
//! ```
//!
//! [`MemoryKeyStore`] is the in-memory implementation for tests and
//! ephemeral use; the platform-backed implementation lives in
//! aoheyra and maps its own failures to
//! [`IdentError::StoreBackend`].

use std::collections::BTreeMap;

use crate::types::IdentError;

/// Maximum key id length in bytes.
pub const MAX_KEY_ID_BYTES: usize = 64;

/// Maximum sealed blob length in bytes: a sealed identity seed is a
/// few hundred bytes; 4096 is a generous, tested ceiling.
pub const MAX_BLOB_BYTES: usize = 4096;

/// Maximum number of entries in one store: devices hold few
/// identities, and a bound keeps a hostile caller from growing the
/// map without limit.
pub const MAX_ENTRIES: usize = 16;

/// An opaque sealed secret blob: bytes the store carries but cannot
/// open. Constructed only through [`SealedBlob::new`], so every blob
/// a [`KeyStore`] ever receives is within [`MAX_BLOB_BYTES`].
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBlob(Vec<u8>);

impl SealedBlob {
    /// Wrap sealed bytes for storage. Over-[`MAX_BLOB_BYTES`] input
    /// is [`IdentError::BlobTooLarge`], rejected before it is
    /// retained.
    pub fn new(bytes: Vec<u8>) -> Result<Self, IdentError> {
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(IdentError::BlobTooLarge);
        }
        Ok(Self(bytes))
    }

    /// The sealed bytes. Opening them is the caller's business, not
    /// the store's.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SealedBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedBlob")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Persistence for sealed secret blobs. Implementations store bytes
/// they cannot read; no method accepts a secret in clear text.
///
/// Errors are [`IdentError`]: capacity and bound violations come from
/// any implementation, [`IdentError::StoreBackend`] carries platform
/// failures from real backends. Implementations apply
/// [`validate_key_id`] before touching their backend.
pub trait KeyStore {
    /// Fetch the blob stored under `key_id`, or [`None`] if absent.
    /// A too-long key id is [`IdentError::KeyRefTooLong`], never a
    /// silent miss.
    fn load(&mut self, key_id: &str) -> Result<Option<SealedBlob>, IdentError>;

    /// Store `blob` under `key_id`, replacing any existing entry.
    /// [`IdentError::StoreFull`] beyond [`MAX_ENTRIES`] - the error
    /// variant, never eviction.
    fn store(&mut self, key_id: &str, blob: SealedBlob) -> Result<(), IdentError>;

    /// Remove `key_id`; reports whether it existed. Backend failures
    /// surface as errors, absent keys do not.
    fn delete(&mut self, key_id: &str) -> Result<bool, IdentError>;
}

/// The key-id rule every [`KeyStore`] implementation applies before
/// touching its backend, so a too-long id fails the same way
/// everywhere: [`IdentError::KeyRefTooLong`] beyond
/// [`MAX_KEY_ID_BYTES`].
pub fn validate_key_id(key_id: &str) -> Result<(), IdentError> {
    if key_id.len() > MAX_KEY_ID_BYTES {
        return Err(IdentError::KeyRefTooLong);
    }
    Ok(())
}

/// An in-memory [`KeyStore`] for tests and ephemeral use.
///
/// `BTreeMap`, not `HashMap`: iteration order stays deterministic and
/// nothing pulls a global random state into this crate.
#[derive(Clone, Debug, Default)]
pub struct MemoryKeyStore {
    entries: BTreeMap<String, SealedBlob>,
}

impl MemoryKeyStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&mut self, key_id: &str) -> Result<Option<SealedBlob>, IdentError> {
        validate_key_id(key_id)?;
        Ok(self.entries.get(key_id).cloned())
    }

    fn store(&mut self, key_id: &str, blob: SealedBlob) -> Result<(), IdentError> {
        validate_key_id(key_id)?;
        if !self.entries.contains_key(key_id) && self.entries.len() >= MAX_ENTRIES {
            return Err(IdentError::StoreFull);
        }
        self.entries.insert(key_id.to_owned(), blob);
        Ok(())
    }

    fn delete(&mut self, key_id: &str) -> Result<bool, IdentError> {
        validate_key_id(key_id)?;
        Ok(self.entries.remove(key_id).is_some())
    }
}
