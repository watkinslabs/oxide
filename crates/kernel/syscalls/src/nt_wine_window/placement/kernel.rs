use alloc::vec::Vec;
use ipc::win32_window::WindowRect;
use syscall::{nt::{NtCall, NtService}, nt_compositor::Monitor, SyscallArgs};
use super::{codec::Context, policy::{self, Owner}};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const PEB_PARAMETERS: u64 = 0x20;
const PARAMETERS_FLAGS: u64 = 0xa4;
const PARAMETERS_SHOW: u64 = 0xa8;
const STARTF_USESHOWWINDOW: u32 = 1;
const ERROR_INVALID_PARAMETER: u64 = 87;

struct Current;
fn native(service: NtService, args: SyscallArgs) -> u64 {
    crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER)
}
impl Owner for Current {
    fn context(&mut self, hwnd: u64) -> Option<Context> { crate::nt_window::placement_context_for_current(hwnd) }
    fn desktop(&mut self) -> Option<Vec<Monitor>> { crate::nt_compositor::monitors_current() }
    fn startup_show(&mut self) -> Result<Option<u32>, ()> {
        let cur = sched::live::current().ok_or(())?;
        let address = cur.nt_peb().checked_add(PEB_PARAMETERS).ok_or(())?;
        let parameters = uaccess::get_user_u64(address).map_err(|_| ())?;
        if parameters == 0 { return Err(()); }
        let flags = uaccess::get_user_u32(parameters.checked_add(PARAMETERS_FLAGS).ok_or(())?).map_err(|_| ())?;
        if flags & STARTF_USESHOWWINDOW == 0 { return Ok(None); }
        uaccess::get_user_u32(parameters.checked_add(PARAMETERS_SHOW).ok_or(())?).map(Some).map_err(|_| ())
    }
    fn set_rect(&mut self, hwnd: u64, rect: WindowRect) -> u64 {
        native(NtService::SetWindowRectValues, SyscallArgs { a0: hwnd, a1: rect.left as u64,
            a2: rect.top as u64, a3: rect.right as u64, a4: rect.bottom as u64, a5: 0 })
    }
    fn show(&mut self, hwnd: u64, command: u32) -> u64 {
        native(NtService::ShowWindow, SyscallArgs { a0: hwnd, a1: command as u64, a2: 0, a3: 0, a4: 0, a5: 0 })
    }
    fn invalid_parameter(&mut self) {
        let _ = crate::nt_rtl::dispatch(NtCall { service: NtService::RtlSetLastWin32Error,
            args: SyscallArgs { a0: ERROR_INVALID_PARAMETER, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } });
    }
}

/// Raw ordinal 0x15a6, argc=2; BOOL, never a native status word. # C: O(monitors + GUI operations)
pub(crate) fn set(hwnd: u64, pointer: u64) -> u64 {
    policy::read_apply(&mut Current, hwnd, pointer, |bytes, address| uaccess::copy_from_user(bytes, address).is_ok())
}

/// Raw ordinal 0x1463 writes exact layout and returns TRUE after successful copyout. # C: O(monitors)
pub(crate) fn get(hwnd: u64, pointer: u64) -> u64 {
    policy::read_query(&mut Current, hwnd, pointer,
        |bytes, address| uaccess::copy_from_user(bytes, address).is_ok(),
        |address, bytes| uaccess::copy_to_user(address, bytes).is_ok())
}

/// Raw ShowWindow keeps previous-visibility BOOL and converts owner failures to FALSE. # C: O(GUI operations)
pub(crate) fn show(hwnd: u64, command: u64) -> u64 { policy::show(&mut Current, hwnd, command as u32) }
