//! Native user-stack creation boundary for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

/// Validate the INITIAL_TEB output and stack sizing contract.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlCreateUserStack { return None; }
    if call.args.a5 == 0 || call.args.a3 == 0 || !call.args.a3.is_power_of_two() {
        return Some(STATUS_INVALID_PARAMETER);
    }
    if call.args.a1 < call.args.a0 || call.args.a1 == 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    // Linux-shaped VMM stack ownership already exists for exec-created
    // processes. A new NT thread stack needs an INITIAL_TEB layout, guard-page
    // policy, and teardown path connected to that owner before allocation here.
    Some(STATUS_NOT_IMPLEMENTED)
}
