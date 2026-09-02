//! Native owner for Wine's private Unix-call ABI.
//!
//! The handle is an opaque Oxide table identity, not a userspace function
//! pointer. This keeps the transition safe while preserving Wine's ABI.

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

fn windows_time_ticks(realtime_ns: u64) -> u64 { realtime_ns.saturating_div(100) }

/// Wine's `unixlib_handle_t` is a table identity. Only the native table may
/// consume it; arbitrary user pointers are rejected before dispatch.
pub(crate) fn dispatch(call: NtCall) -> u64 {
    if call.service != NtService::WineUnixCall || call.args.a0 != syscall::nt::WINE_UNIXLIB_HANDLE {
        return STATUS_INVALID_PARAMETER;
    }
    match call.args.a1 {
        // unix_wine_dbg_write: `{ const char *str; size_t len; }`.
        // Logging ownership is added with the kernel console bridge; reject
        // malformed requests now rather than dereferencing an untrusted ptr.
        2 => {
            if call.args.a2 == 0 { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED }
        }
        // unix_system_time_precise: writes one Windows 100ns timestamp.
        7 => {
            if call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
            // Wine's unix_system_time_precise returns Windows epoch-relative
            // 100ns units; CLOCK_REALTIME is the canonical Linux owner.
            let ticks = windows_time_ticks(timekeeper::realtime_ns());
            if uaccess::put_user_u64(call.args.a2, ticks).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        // The remaining entries require Wine's server protocol or a Unix
        // module loader and are deliberately kept behind this typed boundary.
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_native_unix_table_handles() {
        let call = NtCall { service: NtService::WineUnixCall, args: syscall::SyscallArgs { a0: 1, a1: 7, a2: 0x1000, a3: 0, a4: 0, a5: 0 } };
        assert_eq!(dispatch(call), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn unix_system_time_uses_windows_100ns_units() {
        assert_eq!(windows_time_ticks(1_700_000_000_123_456_700), 17_000_000_001_234_567);
        assert_eq!(windows_time_ticks(99), 0);
    }
}
