//! The two entries into the win32u ordinal space. Each normalizes its own
//! arguments into one Windows-order array and then walks the single chain
//! (`chain`); neither carries routing of its own.
use super::*;

/// Tagged descriptor entry: the argument array is already in Windows order in
/// user memory. # C: O(len(chain)) plus bounded usercopy
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> u64 {
    if call.service != NtService::WineSyscall { return STATUS_INVALID_PARAMETER; }
    let Some(args) = read_args(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
    chain::kernel::route(call.args.a0, &args).unwrap_or(STATUS_NOT_IMPLEMENTED)
}

/// The Wine x86-64 register and stack capture. # C: see `raw_args::normalize`
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn normalize(ordinal: u64, linux: SyscallArgs) -> raw_args::Normalized {
    raw_args::normalize(ordinal, [linux.a0, linux.a1, linux.a2, linux.a3, linux.a4, linux.a5],
                        crate::nt_dispatch::stack_argument)
}

/// No win32u register ABI is defined for this architecture; the Linux
/// snapshot is passed through and the chain's own claims decide.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", not(target_arch = "x86_64")))]
fn normalize(_ordinal: u64, linux: SyscallArgs) -> raw_args::Normalized {
    let mut args = [0u64; chain::MAX_ARGS];
    args[..6].copy_from_slice(&[linux.a0, linux.a1, linux.a2, linux.a3, linux.a4, linux.a5]);
    raw_args::Normalized::Ready(args)
}

/// Raw win32u thunk entry, reached with the Linux syscall register snapshot.
/// # C: same as `normalize` plus O(len(chain))
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch_raw_linux(ordinal: u64, linux: SyscallArgs) -> Option<u64> {
    if ordinal == WINE_GET_CLASS_INFO_EX || ordinal == WINE_GET_CLASS_NAME {
        klog::write_raw(b"[WINDOWS-PE-WINE-RAW-CLASS-ROUTE] ordinal=");
        klog::write_hex_u64(ordinal); klog::write_raw(b"\n");
    }
    match normalize(ordinal, linux) {
        raw_args::Normalized::Unclaimed => None,
        raw_args::Normalized::StackFault(index) => {
            klog::write_raw(b"[WINDOWS-PE-WINE-RAW-STACK-FAULT] ordinal=");
            klog::write_hex_u64(ordinal);
            klog::write_raw(b" index=");
            klog::write_hex_u64(index as u64);
            klog::write_raw(b"\n");
            Some(STATUS_INVALID_PARAMETER)
        },
        raw_args::Normalized::Ready(args) => chain::kernel::route(ordinal, &args),
    }
}
