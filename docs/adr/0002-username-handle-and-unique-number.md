# ADR-0002: Username handle and unique number

- **Status:** accepted, pending sign-off by a reviewer other than the author (IDN-20 done-when)
- **Date:** 2026-11-06 (decisions taken 2026-11-05)
- **Related:** IDN-07 (IdentityCard carries the handle), IDN-01 (NodeId it derives from), the directory and search flows

## Decision

`NodeId` is cryptographic but unfriendly to humans. The user-facing primary identity is a **handle**: `username#NNNNNNNNNNNN`, a username plus a 12-digit number derived from the public key. `NodeId` (ADR-0001) remains the cryptographic identity; the handle is an alias for humans, bound into the signed IdentityCard so it cannot be forged independently of the key.

### Format

| Part | Rule |
|---|---|
| username | 3..20 characters; charset `[a-z0-9_]`; must start with a letter `a`-`z`; ASCII only |
| separator | a single literal `#` |
| number | exactly 12 decimal digits, zero-padded (`000000000042`) |

- **Case:** the canonical username is lowercase. Validation rejects uppercase rather than folding it, so two spellings can never silently map to one handle; applications normalize (ASCII-lowercase) user input before validation.
- **Reserved usernames**, rejected at card creation: `admin`, `root`, `system`, `official`, `support`, `aoheyra`, `mesh`, `all`, `everyone`, `null`, `none`. Rationale: these read as platform identities; letting a user claim one is phishing surface.
- **Minimum length 3:** one- and two-character names are squatting magnets and lookalike-phishing bait. Pair-uniqueness (below) removes any need to allow them.

### Number derivation

The number comes from the public key, so it cannot be chosen or squatted, needs no registry, and anyone can verify it.

1. `D = BLAKE3(NodeId || "aoheyra/idn/v1/handle")` - 32 bytes. `NodeId` is the raw 16-byte value (ADR-0001), no hex encoding, no suite byte, no separators. The domain string is registered in ADR-0001's domain table.
2. Take `D[0..16]`, interpreted **big-endian** as `u128`.
3. `number = value mod 10^12`, rendered zero-padded to exactly 12 digits.

Grinding a vanity number costs about `10^12` key generations (each a full identity derivation), so numbers are effectively unchoosable. This ADR does not implement the function; the derivation is pinned by known-answer tests against this document.

Worked example: NodeId `000102030405060708090a0b0c0d0e0f` (bytes `0x00`..`0x0f`) with username `alice` gives handle `alice#107409223262`.

### Uniqueness

The **unique key is the pair `(username, number)`**. A pair collision needs both components to match: with 1000 users on the same username, expected pair collisions are about `1000^2 / (2 * 10^12)` = `5 * 10^-7`, negligible at any realistic scale.

- The **number alone** is only near-unique: the birthday bound bites at about `10^6` users (`n^2 / (2 * 10^12)` approaches 1 around then). It is a strong hint, never the identity.
- The **username alone** conflicts freely across disconnected partitions: two users in partitions that never met may pick the same username. Harmless - their numbers differ (key-derived), and the directory/contact record shows the pair.

### Search

**Three search modes only:**

1. by username only,
2. by number only,
3. by the combination.

If mode 1 or 2 returns colliding entries in the network, users switch to the combination (username + number) to disambiguate - the pair is the definitive lookup. No other modes, no fuzzy matching, no case folding at this layer.

### Where the handle appears

- inside the signed **IdentityCard** payload (IDN-07), covered by the card's self-signature;
- on the **QR card**, rendered for scanning;
- **in-app**: profile, contact records, directory results, and the disambiguation UI.

Never a security boundary: the handle is display-level. Uniqueness and trust come from the key (ADR-0001), not from the 12 digits. Verification of a received handle is recomputing the number from the NodeId and comparing the pair.

## Consequences

- No handle registry: derivation replaces allocation, and every node can verify a handle offline.
- The `10^12` space is chosen so a12-digit string is exact and `u128` arithmetic covers the modulus with negligible bias (`2^128` vs `10^12`).
- IdentityCard (IDN-07) gains one field; its signature covers it, so a forged handle fails card verification.
- The username rules are validated by aoIdents at card creation (typed error), not silently corrected.
- Changing any rule here (charset, length, modulus, domain string) is a protocol change: new ADR, version bump, compatibility note - same rule as ADR-0001.
