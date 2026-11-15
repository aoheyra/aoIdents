# Changelog

Notable changes to `ao_idents` are recorded here. The crate is
pre-alpha: there are no tagged releases yet, the public API may
change without notice until v0.1.0, and consumers pin by git tag
(AGENTS.md, section 8).

## Unreleased

Initial implementation of the full `IDN-00` to `IDN-20` backlog:
identity derivation, context-separated signatures, the `KeyStore`
seam, identity cards and QR text, sealed and multi-recipient
messages, signed public blobs, rotating tags, the contact book,
the replay guard, passphrase-encrypted backup, the Noise XX hop
handshake, prekeys and X3DH initial agreement, key rotation and
revocation, sender-key group encryption, known-answer vectors and
property tests, and the threat model.

Breaking API changes are listed here once a tag exists.
