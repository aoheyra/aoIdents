# Threat model

- **Status:** accepted
- **Date:** 2026-11-08 (revised 2026-11-15 for IDN-16 and IDN-17)
- **Related:** ADR-0001 (crypto suite); IDN-05 (key storage), IDN-06 (backup), IDN-08 (contacts), IDN-09 (sealed messages), IDN-12 (rotating tags), IDN-13 (hop handshake), IDN-14 (replay guard), IDN-15 (prekeys), IDN-16 (revocation), IDN-17 (group keys); MSH-02 (routing metadata trade-off); NET-18 (link abuse protection)

## Scope and assets

aoIdents owns identity, signatures, sealed messages, contact trust and replay rejection. It is one layer of the stack: aoNetwork owns the link, aoMesh owns routing, aoheyra owns persistence and the OS integration. This document states what an attacker can and cannot achieve against the system as a whole, and which layer is responsible for each guarantee.

| Asset | Where it lives | Protected by |
|---|---|---|
| Message content | Sealed to the recipient; decrypted only on the recipient device | IDN-09 (AEAD), IDN-17 (group AEAD), IDN-04 (signatures) |
| Identity seed and secret keys | Memory only while in use (zeroized); at rest behind `KeyStore` and the aoheyra vault | IDN-02, IDN-05, AND-13 |
| Sender and recipient metadata | Mesh packet headers and radio traffic | Deliberately visible to relays (MSH-02); rotating tags unlinkable to `NodeId` (IDN-12) |
| Contact graph | aoheyra's contact store; never written to the mesh in clear text | IDN-08, app storage (APP-04) |
| Location | App payload, sealed like any other content | IDN-09, APP-07 |
| Device and app availability | The phone itself | OS lock screen and aoheyra (outside this crate) |

## Trust assumptions

- The primitives fixed by ADR-0001 behave as specified (Ed25519, X25519, XChaCha20-Poly1305, BLAKE3, HKDF).
- There is no server, no certificate authority and no global directory: trust is trust-on-first-use plus out-of-band comparison (safety numbers, IDN-08).
- Relays and radio neighbours are untrusted: every peer may be hostile, and the mesh layer treats it that way (NET-18, MSH-10).
- The user decides when to trust a contact; the code makes a changed key loud, never silent (IDN-08).

## Attacker classes

### Passive eavesdropper

Anyone in radio range observes link traffic: frame sizes, timing, beacons and scan responses.

- Protected: message content is sealed to the recipient (IDN-09); link tags and beacon hints rotate per epoch and are unlinkable to `NodeId` (IDN-12); secrets never appear in `Debug` output or logs.
- Not protected: traffic patterns, packet sizes and timing; mesh headers carry origin and destination in clear text by design (MSH-02) so relays can rate-limit spam.

### Malicious relay

A neighbour that forwards, drops, delays or analyses traffic it is trusted to relay.

- Protected: relays cannot read message content (IDN-09), cannot forge an origin, announcement or channel message (IDN-04, IDN-11, IDN-17), and cannot replay an old message past the recipient's replay guard (IDN-14). Flooding neighbours are token-bucketed and struck at the link layer (NET-18) and per origin at the mesh layer (MSH-10).
- Not protected: availability. A relay can drop or delay messages; delivery is best effort, and origin and destination are visible to every relay on the path.

### Impersonator

An attacker who substitutes keys, forges signatures or sits on the first contact.

- Protected: strict signatures with domain separation (IDN-04), the agreement key bound to its identity by signature (IDN-03), self-signed identity cards (IDN-07), link neighbours authenticate each other against their identity cards with the Noise XX hop handshake (IDN-13), and a changed key for a known `NodeId` raising a typed warning instead of being accepted silently (IDN-08).
- Not protected: first contact. Trust-on-first-use means an impostor present at first meeting is trusted until the user compares safety numbers out of band (IDN-08).

### Spammer or Sybil

An attacker who generates many identities or floods the mesh with traffic.

- Protected: every packet is signed, so origin spoofing costs a signature check; per-link and per-origin budgets bound what one identity can inject (NET-18, MSH-10).
- Not protected: identity is cheap. Key generation is free, so Sybil resistance in the sense of costly identities does not exist in the MVP; budgets limit damage per identity, not the number of identities.

### Device thief

Someone with the physical device.

- Protected: secrets are zeroized on drop and redacted in `Debug` (IDN-02); at rest they sit behind `KeyStore` with the aoheyra vault and the Android Keystore (IDN-05, AND-13); exported backups are passphrase-encrypted with Argon2id (IDN-06).
- Not protected: a device that is unlocked with the app open exposes the identity while it is in use. Rotation and revocation notices exist (IDN-16), but the thief controls the device and can delay the notice; a stolen identity stays valid until contacts receive and act on it.

## What the MVP protects

- **Content confidentiality:** only the recipient can open a sealed message; a wrong recipient fails to open (IDN-09).
- **Content integrity and authenticity:** any tampered field fails to open, and the sender's signature is verified before the plaintext is returned (IDN-09, IDN-04).
- **Replay rejection:** a replayed sealed message is rejected at the recipient while an out-of-order but fresh one is accepted (IDN-14).
- **Key substitution:** a substituted agreement key fails the bind-agreement check; a changed key for a known `NodeId` is never silently accepted (IDN-03, IDN-08).
- **Neighbour authentication:** the optional Noise XX hop handshake authenticates a link neighbour against its identity card before its traffic is trusted (IDN-13).
- **Channel confidentiality and authenticity:** only members open a channel message, membership changes are signed statements, and removing a member rotates the chain so it cannot read new messages (IDN-17).
- **No secrets in output:** secret types print `<redacted>`, zeroize on drop and compare in constant time (IDN-02).

## What the MVP does not protect

These limits are deliberate:

1. **Origin and destination are visible to relays.** Every relay and every radio observer sees who sent a message and who it is for. This is the metadata trade-off accepted in MSH-02 so relays can rate-limit spam; only the content is sealed.
2. **No forward secrecy against recipient key compromise.** Sealed message v1 (IDN-09) derives its key from an ephemeral-to-recipient-static DH. Anyone who obtains the recipient's long-term agreement key can decrypt every stored message ever sealed to it, past and future. IDN-15 (prekeys) improves this for messages sealed under deleted prekeys; a full ratchet is explicitly out of scope.
3. **Contact graph and traffic patterns are exposed.** Relays and radio observers see who communicates with whom, how often, at what sizes and when, even though the content is sealed.
4. **Location is protected in transit, not after delivery.** A sealed location payload is confidential on the wire, but a malicious recipient can forward what it receives; there is no post-delivery control.
5. **Availability is not guaranteed.** Any relay on the path can drop or delay messages; the mesh is best effort with no end-to-end delivery proof in the MVP.
6. **First-contact impersonation survives without user action.** Trust-on-first-use trusts the first key seen; only out-of-band safety-number comparison (IDN-08) detects an impostor present at first meeting.
7. **Sybil is bounded, not prevented.** Identities are free to create; per-origin budgets limit each identity's damage, not the number of identities.
8. **A stolen, unlocked device is game until revocation propagates.** Rotation and revocation notices exist (IDN-16), but the thief controls the device and can delay the notice; contacts stay exposed until they receive and act on it.
9. **A compromised channel member impersonates the others.** Every member holds the sender chains distributed to it, so it can read channel traffic and forge messages as those senders until they rotate; a removed member keeps everything it already received (IDN-17).

## Forward secrecy status per milestone

| Milestone | Forward secrecy status |
|---|---|
| M0 to M3 (MVP) | None. Sealed v1 binds to the recipient's static agreement key: compromise of that key decrypts all stored ciphertext sealed to it. |
| M4 (IDN-06) | Exported backups are Argon2id passphrase-encrypted, which protects a backup at rest, not message forward secrecy. |
| M6 (IDN-15) | Prekeys: a message sealed under a deleted one-time prekey survives later compromise of the long-term key; the remaining gap is documented in IDN-15 and closed only by a future ratchet design. |
| M6 (IDN-17) | Sender-key chains ratchet one way per message: a compromised chain key reveals messages from that point until the chain rotates, not earlier ones. A removed member keeps the history it already received. |

## Layer responsibilities

| Layer | Responsible for | Not responsible for |
|---|---|---|
| aoNetwork (NET-18) | Per-link rate limits, malformed-frame strikes, link liveness | Content, identity, routing metadata |
| aoMesh (MSH-02, MSH-10) | Routing headers, per-origin budgets, forwarding dedupe | Content confidentiality, contact trust |
| aoIdents (this crate) | Sealing, signatures, identity, contacts, replay rejection | Availability, routing, persistence, device security |
| aoheyra (APP, AND) | Persistence behind the stores, OS integration, keystore, app lock | Cryptographic decisions, which live here |

## Review

Security-relevant changes to this document need a reviewer other than the author (AGENTS.md, section 8). When a guarantee weakens or strengthens, this document and the matching doc-comment are updated in the same change.
