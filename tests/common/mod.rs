//! Shared helpers for the integration tests.
//!
//! Only deterministic test scaffolding lives here - never production
//! randomness. Each `tests/*.rs` file opts in with `mod common;`.

/// Deterministic splitmix64 PRNG implementing `rand_core::RngCore`.
///
/// Non-cryptographic on purpose: tests need reproducible byte streams to
/// feed `Identity::generate`, not entropy. Production code always receives
/// a CSPRNG from its caller.
pub struct TestRng(u64);

impl TestRng {
    /// A rng with the given state.
    pub fn new(state: u64) -> Self {
        Self(state)
    }
}

impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // splitmix64 (Steele, Lea, Flood 2014); test use only.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
