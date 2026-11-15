//! Hop-handshake message reading must never panic on hostile bytes
//! from a malicious responder.
#![no_main]

use ao_idents::{HopHandshake, Identity};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, RngCore};

/// Deterministic splitmix64 stream: fuzzing wants reproducible bytes,
/// not entropy (same construction as `tests/common`).
struct FuzzRng(u64);

impl CryptoRng for FuzzRng {}

impl RngCore for FuzzRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
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

fuzz_target!(|data: &[u8]| {
    let local = Identity::from_seed([1u8; 32]);
    let remote = Identity::from_seed([2u8; 32]);
    let Ok(card) = remote.card(b"remote", 1_700_000_000) else {
        return;
    };
    let mut rng = FuzzRng(0x5EED);
    let Ok(mut handshake) = HopHandshake::initiator(&local, &card, &mut rng) else {
        return;
    };
    let _ = handshake.read_message(data);
});
