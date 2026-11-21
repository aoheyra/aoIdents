//! Identity, trust and cryptography for the aoheyra mesh.
//!
//! `ao_idents` owns who a node *is*, how contacts are trusted, and how
//! messages are signed, sealed and replay-checked: node keys, `NodeId`,
//! identity cards, contextual signatures, sealed messages, rotating tags,
//! passphrase-encrypted backups, contact-book logic, key rotation and
//! revocation, the replay guard and the optional hop handshake.
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

mod backup;
mod blob;
mod card;
mod contact;
mod group;
mod handshake;
mod identity;
mod keystore;
mod multi_seal;
mod prekey;
mod replay;
mod rotation;
mod seal;
mod sign;
mod tag;
mod types;

pub use backup::{BackupBlob, export_backup, import_backup};
pub use blob::SignedBlob;
pub use card::IdentityCard;
pub use contact::{
    Contact, ContactBook, ContactStore, ContactUpdate, MAX_CONTACTS, MAX_PETNAME_BYTES,
    MemoryContactStore, Trust, safety_number,
};
pub use group::{
    GroupId, GroupMessage, GroupReceiver, MAX_COUNTER_JUMP, MAX_SENDERS_PER_GROUP,
    MembershipAction, MembershipChange, SenderChain, SenderKeyDistribution,
};
pub use handshake::{
    EntropySource, HopHandshake, HopSessions, HopTransport, MAX_HOP_SESSIONS, RngAdapter,
};
pub use identity::{Identity, compute_node_id};
pub use keystore::{
    KeyStore, MAX_BLOB_BYTES, MAX_ENTRIES, MAX_KEY_ID_BYTES, MemoryKeyStore, SealedBlob,
    validate_key_id,
};
pub use multi_seal::{MAX_RECIPIENTS, MultiSealedMessage, RECIPIENT_WRAP_LEN};
pub use prekey::{MAX_ONE_TIME_PREKEYS, PrekeyBundle, PrekeySealedMessage, PrekeySecrets};
pub use replay::{
    MAX_ENTRIES as MAX_REPLAY_ENTRIES, MAX_SENDERS, MAX_TOLERANCE_MS, MAX_WINDOW, ReplayConfig,
    ReplayGuard,
};
pub use rotation::{RevocationNotice, RotationStatement};
pub use seal::{MSG_ID_LEN, OpenedMessage, SealedMessage};
pub use sign::verify_signing_pk;
pub use tag::{EPOCH_MAX_MS, EPOCH_MIN_MS, RotatingTag};
pub use types::{IdentError, NodeId, PublicIdentity, SecretIdentity, Signature, SuiteId};
