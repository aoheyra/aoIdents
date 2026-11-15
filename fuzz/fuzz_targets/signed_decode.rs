//! Signed public structures (blob, rotation statement, revocation
//! notice) must decode without panicking on hostile bytes.
#![no_main]

use ao_idents::{RevocationNotice, RotationStatement, SignedBlob};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SignedBlob::decode(data);
    let _ = RotationStatement::decode(data);
    let _ = RevocationNotice::decode(data);
});
