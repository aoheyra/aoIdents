# Constant-time review checklist

Secret material in this crate: the two secret keys inside
[`SecretIdentity`](https://docs.rs/ao_idents), the pairwise/baseline
seed inside `RotatingTag`, AEAD keys and nonces inside `seal` and
`multi_seal` (all `zeroize`-managed), and the sealed blobs in a
key store. Everything else the crate compares - `NodeId`s, public
keys, safety numbers, signatures, msg ids - is public by design and
may be compared in variable time.

When touching secret handling, re-check each item:

1. **No secret reaches `Debug`, `Display` or logs.** `SecretIdentity`
   prints `<redacted>`; `RotatingTag` prints mode and parameters only;
   `SealedBlob` prints its length only; `Identity` delegates to those.
   A new secret-bearing type needs the same redaction and a test that
   the redaction holds.
2. **Secret comparisons are constant-time.** The only secret
   comparison in this crate is `SecretIdentity` equality, which goes
   through `subtle::ConstantTimeEq`. A new secret-bearing type must
   not derive `PartialEq`; use `subtle` and add a test. Never compare
   secret bytes with `==`.
3. **AEAD tag checks stay inside the `chacha20poly1305` crate.** Do
   not hand-roll tag comparison after decryption; let `decrypt` fail.
4. **Secrets are zeroized on every exit path.** Keys live in
   `zeroize::Zeroizing` or are explicitly `zeroize()`d at the end of
   the function that derived them (see `Identity::from_seed`).
   A new derivation must do the same, including error paths.
5. **No secret-dependent branches or table indices** in code this
   crate owns. The primitives (HKDF, Ed25519, X25519, BLAKE3,
   XChaCha20-Poly1305) provide this; we must not add our own
   secret-dependent control flow on top of their output.
6. **Timing of failures is public-input only.** Every error this
   crate returns (`InvalidSignature`, `OpenFailed`, ...) is decided
   from public data (ciphertext, signature, public keys), so
   variable-time rejection leaks nothing about secrets.

This checklist is the IDN-18 review artifact; update it in the same
PR as any change to the list above.
