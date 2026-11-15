//! Identity-card decode, verify and QR parsing must never panic on
//! hostile bytes.
#![no_main]

use ao_idents::IdentityCard;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(card) = IdentityCard::decode(data) {
        let _ = card.verify();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = IdentityCard::from_qr_string(text);
    }
});
