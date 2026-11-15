//! Group distribution, membership and channel message decoding must
//! never panic on hostile bytes.
#![no_main]

use ao_idents::{GroupMessage, MembershipChange, SenderKeyDistribution};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = GroupMessage::decode(data);
    let _ = SenderKeyDistribution::decode(data);
    let _ = MembershipChange::decode(data);
});
