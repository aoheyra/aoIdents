//! Identity, trust and cryptography for the aoheyra mesh.
//!
//! `ao_idents` owns who a node *is*, how contacts are trusted, and how
//! messages are signed, sealed and replay-checked: node keys, `NodeId`,
//! identity cards, contextual signatures, sealed messages, rotating tags,
//! contact-book logic, the replay guard and the optional hop handshake.
//!
//! # Boundaries
//!
//! - **Pure Rust: no networking, no I/O, no FFI.** `now` and randomness are
//!   always parameters; persistence lives behind the `KeyStore` and
//!   `ContactStore` traits, implemented by the `aoheyra` app.
//! - This crate never depends on `ao_network`, `ao_mesh` or `aoheyra`.
//! - It signs and seals opaque bytes; it never sees packet formats, routing
//!   or app payload schemas.
//!
//! # Security
//!
//! The suite, domain strings and canonical encoding are fixed by the
//! crypto-suite ADR (IDN-01, `docs/adr/0001`). Nothing in this crate may
//! panic on external input.

// forbid, not deny: a future `unsafe` must be a compile error, not a review note.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod blob;
mod card;
mod contact;
mod identity;
mod keystore;
mod seal;
mod sign;
mod tag;
mod types;

pub use blob::SignedBlob;
pub use card::IdentityCard;
pub use contact::{
    Contact, ContactBook, ContactStore, ContactUpdate, MAX_CONTACTS, MAX_PETNAME_BYTES,
    MemoryContactStore, Trust, safety_number,
};
pub use identity::Identity;
pub use keystore::{
    KeyStore, MAX_BLOB_BYTES, MAX_ENTRIES, MAX_KEY_ID_BYTES, MemoryKeyStore, SealedBlob,
    validate_key_id,
};
pub use seal::{MSG_ID_LEN, OpenedMessage, SealedMessage};
pub use tag::{EPOCH_MAX_MS, EPOCH_MIN_MS, RotatingTag};
pub use types::{IdentError, NodeId, PublicIdentity, SecretIdentity, Signature, SuiteId};
