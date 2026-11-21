# Host-side hop encryption integration (IDN-14, MSH-26)

- **Status:** accepted, framing pending sign-off by a reviewer other than the author
- **Related:** IDN-13 (`HopHandshake`, `HopTransport`), ADR-0001 (suite and domain registry), MSH-07 (signed `MeshHello`), MSH-26 (aoMesh hop encryption)

This document is the contract between aoIdents and the **host** (aoheyra) that assembles the stack. aoMesh's sans-IO engine neither implements crypto nor keeps secrets; it carries opaque bytes, a capability bit and the 8-byte card hash from the signed hello. aoIdents never sees a packet format or a radio.

## Ownership model

All state is owned by the host and passed in explicitly. Nothing is global, nothing is persisted by this crate, and no reference to it lives in aoMesh's engine.

| State | Owner | Where it lives | aoMesh sees |
|---|---|---|---|
| Local `Identity` | host | aoheyra's keystore-backed identity | opaque signing input, passed by reference |
| Neighbour full `IdentityCard` | host | out-of-band (QR/NFC) store beside the engine | not at all; only its 8-byte hash in `MeshHello` |
| In-flight `HopHandshake` | host | per-link host map, driven from Control frames | not at all |
| Finished `HopTransport` keys | host | `HopSessions` table passed by `&mut` | not at all; only opaque frame bytes |
| Card hash, capability bits | aoMesh engine | `MeshHello` fields and negotiated caps | the raw values, never a key |

Flow for one link:

1. Link-up delivers a verified `MeshHello` (MSH-07) with `node_id`, `card_hash` and negotiation caps. The host looks up the full card for that hash in its out-of-band store.
2. The host calls `HopHandshake::initiator_pinned_by_hash` / `responder_pinned_by_hash` with that hash, the full card and its injected RNG. aoIdents verifies the card self-signature and that `card.announcement_hash()` equals the pin, returning `IdentError::CardHashMismatch` otherwise. The full-card constructors remain available for callers that hold the card directly.
3. The host drives `write_message` / `read_message` as Control frames arrive, then calls `into_transport`. An impostor static key fails with `IdentError::ImpostorCard` before a transport exists.
4. The host installs the transport in `HopSessions` under the neighbour's `NodeId`. aoMesh calls the host to seal an opaque Data frame; the host calls `HopSessions::seal_frame`. On receive, the host calls `open_frame` and returns only the resulting bytes.
5. Link-down calls `HopSessions::close`, which drops the keys and leaves a tombstone so late frames fail as `HopSessionClosed` rather than being opened under a stale key. `forget` frees the slot.

The host is responsible for matching a link to a neighbour id and for keeping the card store authentic. aoIdents authenticates the Noise static key against the card it was given; it cannot know whether the host's out-of-band card is the right one for a stranger (first-contact trust is still out of band, IDN-08).

## Control and Data frame contract

Capability negotiation and aoMesh's own frame header belong to aoMesh (MSH-26). Within a frame body, aoIdents fixes these bytes:

```text
Control body (hop handshake)
  offset 0   1 byte   kind = 0x01  (Noise_XX_25519_ChaChaPoly_SHA256 v1)
  offset 1   ..       Noise XX handshake message, empty payload

  message 1: 32 bytes  e
  message 2: 96 bytes  e || enc_s || tag
  message 3: 64 bytes  enc_s || tag

Data body
  raw HopTransport ciphertext = plaintext + 16-byte ChaCha20-Poly1305 tag
  no aoIdents header; maximum frame 65535 bytes
```

The `kind` byte is a demultiplexing tag, not a cryptographic field. No message-index byte is included: the Noise state machine already rejects out-of-order and duplicate messages, and an index would be an unauthenticated field an attacker could flip. The plaintext is exactly what aoMesh hands to the host; if aoMesh wants a passive observer to see no packet headers, it must pass the entire serialized packet (header plus payload) as that plaintext. aoIdents does not parse it.

No new signature or KDF domain string is introduced: the Noise suite name binds the handshake transcript, and the card hash uses the registered `aoheyra/idn/v1/card-hash` domain. A new Noise suite needs a new `kind` byte, an ADR update, a version bump and a compatibility note; a receiver that does not recognise the kind refuses the frame. The byte layout above is registered in ADR-0001.

## Caps and cleartext fallback

aoMesh owns the capability bit and its negotiation rule. aoIdents defines what the host may do with the result:

- **Both ends advertise hop encryption:** run the three-message handshake over Control frames, pin the card hash, install the transport, and seal Data frames. If any step fails, no session is installed and the typed error is surfaced; there is no automatic cleartext retry that could hide an impostor or a tampered card.
- **Neither advertises it, or only one does:** no handshake is run, and Data frames stay cleartext. End-to-end content remains protected by aoIdents sealed messages; link headers and traffic patterns are visible to a passive observer (the documented MVP limit).
- The `MeshHello` carrying the cap is signed under `aoheyra/mesh/v1/hello` (MSH-07), so a third party cannot strip the bit in transit. A peer that genuinely lacks support can still choose cleartext; this is an explicit limit of an optional link-layer feature, not a silent downgrade of a peer that asked for encryption.

## RNG seam

snow is built against `rand_core` 0.6, while aoMesh injects a `rand_core` 0.9 generator. Two options were compared:

| Option | Trade-off |
|---|---|
| Add `rand_core` 0.9 as a second runtime dependency and write two blanket implementations | Works, but adds a second trait line to the security-critical core, doubles the injection surface, and makes support for 0.6 and 0.9 a permanent maintenance commitment. |
| Inject a one-method `EntropySource`, blanket-implemented for the existing 0.6 `RngCore` plus a closure newtype `RngAdapter` (chosen) | No new runtime dependency, no global RNG or I/O, one draw point to audit, and seeded runs stay byte-identical. The caller bridges 0.9 with `RngAdapter::new(|dest| rng09.fill_bytes(dest))`. A real 0.9 generator is used in a dev-only test. |

`fill_bytes` keeps `RngCore`'s semantics: the injected generator is responsible for entropy and for handling its own failures. aoIdents draws exactly the 32 ephemeral bytes and hands snow a bounded buffer-backed RNG; it never reads a clock, file, socket or OS entropy source.

## Errors and bounds

- `CardHashMismatch`, `ImpostorCard`, `HandshakeFailed` and `InvalidSignature` cover pinning, handshake and card failures.
- `NoHopSession`, `HopSessionClosed`, `HopFrameInvalid` and `HopSessionTableFull` cover per-link Data frames. A bad frame never produces plaintext or a panic.
- `HopSessions` holds at most `MAX_HOP_SESSIONS` (64) entries, twice aoMesh's default neighbour table of 32. A full table is a typed error, never an eviction of a live link. Debug output lists neighbour ids and open/closed state only; no key bytes are printed.

## Limits

- Hop encryption protects the bytes handed to it on one link. Relays still see and route the outer frame; a relay that must read routing metadata cannot be excluded by this seam.
- The Noise XX transport has per-session forward secrecy from the ephemeral DH, but compromise of a live session key exposes that session's frames. Session keys are dropped on `close` / `forget`.
- Cleartext fallback exposes whatever aoMesh puts on the wire. This is a link-layer option, not a replacement for end-to-end sealed messages (IDN-09) or signed origin headers (MSH-04).
