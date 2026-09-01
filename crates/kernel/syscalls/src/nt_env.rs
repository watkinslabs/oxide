//! Native environment block boundary for the Windows personality.
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

/// Validate the output boundary before the process-environment owner exists.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlCreateProcessParametersEx {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // The ten pointer arguments describe strings and an environment block;
        // constructing the owned RTL_USER_PROCESS_PARAMETERS record is still
        // pending a process-parameters lifetime owner.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service != NtService::RtlCreateEnvironment { return None; }
    if call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    // Wine copies the process environment for inherit != FALSE and otherwise
    // allocates an empty double-NUL-terminated block. Oxide's PEB owner does
    // not yet expose a mutable NT environment allocation/lifetime interface.
    Some(STATUS_NOT_IMPLEMENTED)
}
