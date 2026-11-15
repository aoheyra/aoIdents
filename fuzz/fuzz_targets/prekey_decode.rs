//! Prekey bundle verification and prekey-sealed message decoding
//! must never panic on hostile bytes.
#![no_main]

use ao_idents::{PrekeyBundle, PrekeySealedMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = PrekeyBundle::decode(data) {
        let _ = bundle.verify();
    }
    let _ = PrekeySealedMessage::decode(data);
});
