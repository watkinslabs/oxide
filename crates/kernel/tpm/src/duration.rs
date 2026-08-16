// How long a command may take. A device that is still working when the
// driver gives up looks exactly like a device that has failed, so these
// bounds are per-command rather than one global timeout.

use crate::limits::DURATION_DEFAULT_MS;
use crate::uapi::{
    TPM2_CC_CREATE, TPM2_CC_CREATE_LOADED, TPM2_CC_CREATE_PRIMARY,
    TPM2_CC_EVENT_SEQUENCE_COMPLETE, TPM2_CC_GET_CAPABILITY, TPM2_CC_GET_RANDOM,
    TPM2_CC_HASH_SEQUENCE_START, TPM2_CC_HIERARCHY_CHANGE_AUTH, TPM2_CC_HIERARCHY_CONTROL,
    TPM2_CC_NV_READ, TPM2_CC_PCR_EXTEND, TPM2_CC_SELF_TEST, TPM2_CC_SEQUENCE_COMPLETE,
    TPM2_CC_SEQUENCE_UPDATE, TPM2_CC_STARTUP, TPM2_CC_VERIFY_SIGNATURE,
};

/// Longest a command may run, in milliseconds. Commands with no entry take
/// the default. # C: O(table size)
pub fn ordinal_duration_ms(cc: u32) -> u32 {
    match cc {
        TPM2_CC_STARTUP => 750,
        TPM2_CC_SELF_TEST => 3000,
        TPM2_CC_GET_RANDOM => 2000,
        TPM2_CC_SEQUENCE_UPDATE => 750,
        TPM2_CC_SEQUENCE_COMPLETE => 750,
        TPM2_CC_EVENT_SEQUENCE_COMPLETE => 750,
        TPM2_CC_HASH_SEQUENCE_START => 750,
        TPM2_CC_VERIFY_SIGNATURE => 30000,
        TPM2_CC_PCR_EXTEND => 750,
        TPM2_CC_HIERARCHY_CONTROL => 2000,
        TPM2_CC_HIERARCHY_CHANGE_AUTH => 2000,
        TPM2_CC_GET_CAPABILITY => 750,
        TPM2_CC_NV_READ => 2000,
        TPM2_CC_CREATE_PRIMARY => 300000,
        TPM2_CC_CREATE => 300000,
        TPM2_CC_CREATE_LOADED => 300000,
        _ => DURATION_DEFAULT_MS,
    }
}
