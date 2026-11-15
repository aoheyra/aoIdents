//! Sealed and multi-recipient message decode/open must never panic
//! on hostile bytes.
#![no_main]

use ao_idents::{Identity, MSG_ID_LEN, MultiSealedMessage, SealedMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Typed errors are the expected outcome; a panic is the bug.
    let bob = Identity::from_seed([2u8; 32]);
    let msg_id = [3u8; MSG_ID_LEN];

    if let Ok(sealed) = SealedMessage::decode(data) {
        let _ = sealed.open(&bob, &msg_id);
    }
    if let Ok(multi) = MultiSealedMessage::decode(data) {
        let _ = multi.open(&bob);
    }
});
