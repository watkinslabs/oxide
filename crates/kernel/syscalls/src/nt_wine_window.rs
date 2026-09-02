//! Wine x86-64 win32u syscall ordinal adapter.

use syscall::{nt::{NtCall, NtService}, SyscallArgs};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

const WINE_CREATE_WINDOW_EX: u64 = 0x136b;
const WINE_GET_MESSAGE: u64 = 0x141b;
const WINE_PEEK_MESSAGE: u64 = 0x14ca;
const WINE_POST_MESSAGE: u64 = 0x14d0;
const WINE_SHOW_WINDOW: u64 = 0x15bd;

#[cfg(target_os = "oxide-kernel")]
fn read_args(pointer: u64) -> Option<[u64; 17]> {
    let mut args = [0u64; 17];
    for (index, value) in args.iter_mut().enumerate() {
        let address = pointer.checked_add((index * 8) as u64)?;
        *value = uaccess::get_user_u64(address).ok()?;
    }
    Some(args)
}

/// Translate one Wine ordinal into the existing native window-state owner.
/// # C: O(1) dispatch plus bounded usercopy
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> u64 {
    if call.service != NtService::WineSyscall { return STATUS_INVALID_PARAMETER; }
    let ordinal = call.args.a0;
    let Some(args) = read_args(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
    let native = |service: NtService, args: SyscallArgs| crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    match ordinal {
        WINE_CREATE_WINDOW_EX => {
            native(NtService::CreateWindow, SyscallArgs { a0: args[9], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })
        }
        WINE_POST_MESSAGE => native(NtService::PostMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: 0, a5: 0 }),
        WINE_PEEK_MESSAGE => native(NtService::PeekMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: args[4], a5: 0 }),
        WINE_GET_MESSAGE => native(NtService::GetMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: 0, a5: 0 }),
        WINE_SHOW_WINDOW => native(NtService::ShowWindow, SyscallArgs { a0: args[0], a1: args[1], a2: 0, a3: 0, a4: 0, a5: 0 }),
        _ => STATUS_NOT_IMPLEMENTED,
    }
}
