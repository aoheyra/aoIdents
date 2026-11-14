//! Contact book: trust on first use, key-change detection and safety
//! numbers (IDN-08).
//!
//! Contacts are local state: they hold verified public keys, an
//! optional *local* petname and a trust level. Nothing in a contact
//! is ever read from the wire unverified - [`ContactBook::observe`]
//! checks the card signature first and stores only what hashes to
//! the claimed [`NodeId`].
//!
//! **Key change is never silent.** A known [`NodeId`] presenting keys
//! that do not hash to it fails with [`IdentError::KeyChanged`]; the
//! stored contact is left untouched. A rotation must be an explicit,
//! verified operation (IDN-16), not a side effect of an announcement.
//!
//! [`safety_number`] gives both parties the same short number to
//! compare out of band, so a human can catch a swapped identity.

use std::collections::BTreeMap;

use crate::card::IdentityCard;
use crate::identity::{compute_node_id, preimage};
use crate::types::{IdentError, NodeId};

/// HKDF/BLAKE3 domain for safety numbers (ADR-0001 registry).
const DOMAIN_SAFETY: &str = "aoheyra/idn/v1/safety-number";

/// Maximum contacts one book holds. Devices meet few hundred peers;
/// the bound stops a hostile stream of fresh identities from growing
/// the store without limit.
pub const MAX_CONTACTS: usize = 512;

/// Maximum petname length in bytes. Local input, still bounded: no
/// unbounded string ever sits in a contact.
pub const MAX_PETNAME_BYTES: usize = 64;

/// How much a human vouches for a contact. `Unverified` is the
/// trust-on-first-use default and carries no claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Seen once, not vouched for (TOFU default).
    Unverified,
    /// A human confirmed the identity (ideally by comparing the
    /// safety number).
    Verified,
    /// Refused: never talk to this identity, whatever it presents.
    Blocked,
}

/// What [`ContactBook::observe`] did with the offered card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactUpdate {
    /// First time this [`NodeId`] was seen: stored as `Unverified`.
    FirstUse,
    /// Known [`NodeId`] with identical keys: nothing changed and the
    /// existing trust level is kept.
    Unchanged,
}

/// One entry in the contact book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    node_id: NodeId,
    signing_pk: [u8; 32],
    agreement_pk: [u8; 32],
    petname: Option<String>,
    trust: Trust,
    first_seen: u64,
}

impl Contact {
    /// Build a contact from a *verified* card. The [`NodeId`] is
    /// derived from the card's keys, so a contact can never disagree
    /// with its own identity material.
    ///
    /// Errors: the card's signature must verify
    /// ([`IdentError::InvalidSignature`]), otherwise a forged card
    /// becomes a contact.
    pub fn from_card(card: &IdentityCard, first_seen: u64) -> Result<Self, IdentError> {
        card.verify()?;
        Ok(Self {
            node_id: compute_node_id(card.signing_pk(), card.agreement_pk()),
            signing_pk: *card.signing_pk(),
            agreement_pk: *card.agreement_pk(),
            petname: None,
            trust: Trust::Unverified,
            first_seen,
        })
    }

    /// The contact's [`NodeId`].
    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// The contact's signing key (public).
    #[must_use]
    pub fn signing_pk(&self) -> &[u8; 32] {
        &self.signing_pk
    }

    /// The contact's agreement key (public).
    #[must_use]
    pub fn agreement_pk(&self) -> &[u8; 32] {
        &self.agreement_pk
    }

    /// The local petname, if one was set. Never taken from the wire:
    /// names are what *this* user calls the contact.
    #[must_use]
    pub fn petname(&self) -> Option<&str> {
        self.petname.as_deref()
    }

    /// The trust level.
    #[must_use]
    pub fn trust(&self) -> Trust {
        self.trust
    }

    /// Caller-supplied timestamp of the first observation.
    #[must_use]
    pub fn first_seen(&self) -> u64 {
        self.first_seen
    }
}

/// Persistence for contacts. aoheyra implements this over its own
/// storage; [`MemoryContactStore`] serves tests and ephemeral use.
///
/// All methods take a receiver, so the trait stays object safe.
/// [`NodeId`] is `Copy`, so ids pass by value.
pub trait ContactStore {
    /// The contact under `node_id`, if known.
    fn load(&self, node_id: NodeId) -> Option<Contact>;

    /// Insert or replace a contact. Implementations enforce
    /// [`MAX_CONTACTS`] themselves: [`IdentError::ContactBookFull`].
    fn save(&mut self, contact: Contact) -> Result<(), IdentError>;

    /// Remove the contact; reports whether it existed.
    fn delete(&mut self, node_id: NodeId) -> bool;

    /// Number of contacts held - [`ContactBook::observe`] checks it
    /// against [`MAX_CONTACTS`] before inserting.
    fn len(&self) -> usize;

    /// Whether the store holds no contacts, derived from
    /// [`len`](Self::len) so the pair stays consistent for every
    /// implementation.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An in-memory [`ContactStore`] for tests and ephemeral use.
///
/// `BTreeMap`, not `HashMap`: deterministic order, no global random
/// state in this crate.
#[derive(Clone, Debug, Default)]
pub struct MemoryContactStore {
    contacts: BTreeMap<NodeId, Contact>,
}

impl MemoryContactStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ContactStore for MemoryContactStore {
    fn load(&self, node_id: NodeId) -> Option<Contact> {
        self.contacts.get(&node_id).cloned()
    }

    fn save(&mut self, contact: Contact) -> Result<(), IdentError> {
        if !self.contacts.contains_key(contact.node_id()) && self.contacts.len() >= MAX_CONTACTS {
            return Err(IdentError::ContactBookFull);
        }
        let node_id = *contact.node_id();
        self.contacts.insert(node_id, contact);
        Ok(())
    }

    fn delete(&mut self, node_id: NodeId) -> bool {
        self.contacts.remove(&node_id).is_some()
    }

    fn len(&self) -> usize {
        self.contacts.len()
    }
}

/// The contact book: TOFU observation, key-change detection, trust
/// and petname management over any [`ContactStore`].
pub struct ContactBook<S: ContactStore> {
    store: S,
}

impl<S: ContactStore> ContactBook<S> {
    /// Wrap a store.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Offer a card seen while claiming `claimed_node_id`.
    ///
    /// - Card signature invalid: [`IdentError::InvalidSignature`],
    ///   nothing stored.
    /// - Presented keys hash to another identity than the claim:
    ///   [`IdentError::KeyChanged`] with the *claimed* [`NodeId`] -
    ///   whether the contact is known or the claim is fresh, a
    ///   mismatch is a typed warning, never a silent accept.
    /// - Known [`NodeId`], same keys: [`ContactUpdate::Unchanged`],
    ///   trust untouched.
    /// - Known [`NodeId`], book at [`MAX_CONTACTS`]:
    ///   [`IdentError::ContactBookFull`].
    /// - Otherwise: stored as `Unverified`
    ///   ([`ContactUpdate::FirstUse`]) - trust on first use.
    pub fn observe(
        &mut self,
        claimed_node_id: NodeId,
        card: &IdentityCard,
        first_seen: u64,
    ) -> Result<ContactUpdate, IdentError> {
        card.verify()?;
        let presented = compute_node_id(card.signing_pk(), card.agreement_pk());
        if presented != claimed_node_id {
            // The keys on offer do not hash to the identity being
            // claimed: a known contact's key "change" or a forged
            // claim - either way, store nothing.
            return Err(IdentError::KeyChanged(claimed_node_id));
        }

        if let Some(existing) = self.store.load(claimed_node_id) {
            if existing.signing_pk() == card.signing_pk()
                && existing.agreement_pk() == card.agreement_pk()
            {
                return Ok(ContactUpdate::Unchanged);
            }
            // Defensive: contacts always hash to their own id, so
            // this cannot trigger through honest storage - but a
            // store that was tampered with must not slip past.
            return Err(IdentError::KeyChanged(claimed_node_id));
        }

        if self.store.len() >= MAX_CONTACTS {
            return Err(IdentError::ContactBookFull);
        }
        self.store.save(Contact::from_card(card, first_seen)?)?;
        Ok(ContactUpdate::FirstUse)
    }

    /// The contact under `node_id`, if known.
    #[must_use]
    pub fn get(&self, node_id: NodeId) -> Option<Contact> {
        self.store.load(node_id)
    }

    /// Set the trust level of an existing contact.
    ///
    /// Errors: [`IdentError::UnknownContact`] - trusting is never
    /// an implicit create.
    pub fn set_trust(&mut self, node_id: NodeId, trust: Trust) -> Result<(), IdentError> {
        let mut contact = self.store.load(node_id).ok_or(IdentError::UnknownContact)?;
        contact.trust = trust;
        self.store.save(contact)
    }

    /// Set (`Some`) or clear (`None`) the local petname of an
    /// existing contact. A name over [`MAX_PETNAME_BYTES`] is
    /// [`IdentError::PetnameTooLong`]; an unknown node is
    /// [`IdentError::UnknownContact`] - never an implicit create.
    pub fn set_petname(
        &mut self,
        node_id: NodeId,
        petname: Option<&str>,
    ) -> Result<(), IdentError> {
        if let Some(name) = petname {
            if name.len() > MAX_PETNAME_BYTES {
                return Err(IdentError::PetnameTooLong);
            }
        }
        let mut contact = self.store.load(node_id).ok_or(IdentError::UnknownContact)?;
        contact.petname = petname.map(str::to_owned);
        self.store.save(contact)
    }

    /// The underlying store, for callers that list contacts directly.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Unwrap the store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

/// The safety number two parties can compare out of band: the first
/// 8 bytes of a BLAKE3 hash over both `(signing_pk, agreement_pk)`
/// pairs, sorted, so Alice computing it over `(hers, Bob's)` and Bob
/// over `(his, Alice's)` get identical bytes.
///
/// Key pairs rather than [`PublicIdentity`](crate::PublicIdentity)
/// because a contact (or a card) holds keys without the agreement
/// binding - and the binding is irrelevant to a human comparison.
/// It authenticates the *pair* of identities, not a direction.
#[must_use]
pub fn safety_number(a: (&[u8; 32], &[u8; 32]), b: (&[u8; 32], &[u8; 32])) -> [u8; 8] {
    // Sort by full key material so even degenerate pairs (equal
    // signing keys) order identically for both callers.
    let (first, second) = if a.0 < b.0 || (a.0 == b.0 && a.1 < b.1) {
        (a, b)
    } else {
        (b, a)
    };
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(first.0);
    body.extend_from_slice(first.1);
    body.extend_from_slice(second.0);
    body.extend_from_slice(second.1);
    let digest = blake3::hash(&preimage(DOMAIN_SAFETY, &body));
    let mut number = [0u8; 8];
    number.copy_from_slice(&digest.as_bytes()[..8]);
    number
}
