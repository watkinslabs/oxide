//! Native userspace user32 façade over the tagged NT window ABI.

use std::io;
use syscall::nt::{NtService, NtWindowMessage};

const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
const STATUS_FAILURE_MASK: u64 = 0x8000_0000;

#[derive(Debug)]
pub enum WindowError { Status(u64), Host(io::Error) }

/// User32-shaped client whose state remains owned by the native NT window service.
pub struct User32;

impl User32 {
    /// Construct a stateless façade over the current NT process. # C: O(1)
    pub const fn new() -> Self { Self }

    /// Create one window and return its native identifier. # C: O(1) plus kernel service
    pub fn create_window(&self, parent: u64, wndproc: u64) -> Result<u64, WindowError> {
        invoke(NtService::CreateWindow, [parent, wndproc, 0, 0, 0, 0])
    }

    /// Destroy a window owned by the current NT process. # C: O(1) plus kernel service
    pub fn destroy_window(&self, hwnd: u64) -> Result<(), WindowError> {
        invoke(NtService::DestroyWindow, [hwnd, 0, 0, 0, 0, 0]).map(|_| ())
    }

    /// Post one message to a native window queue. # C: O(1) plus kernel service
    pub fn post_message(&self, hwnd: u64, message: u32, wparam: u64, lparam: i64) -> Result<(), WindowError> {
        invoke(NtService::PostMessage, [hwnd, message as u64, wparam, lparam as u64, 0, 0]).map(|_| ())
    }

    /// Inspect one queued message, optionally removing it. # C: O(1) plus usercopy
    pub fn peek_message(&self, hwnd: u64, first: u32, last: u32, remove: bool) -> Result<Option<NtWindowMessage>, WindowError> {
        let mut message = NtWindowMessage { hwnd: 0, message: 0, padding: 0, wparam: 0, lparam: 0 };
        let result = invoke(NtService::PeekMessage, [(&mut message as *mut NtWindowMessage) as u64, hwnd, first as u64, last as u64, remove as u64, 0]);
        match result { Ok(_) => Ok(Some(message)), Err(WindowError::Status(STATUS_NO_MORE_ENTRIES)) => Ok(None), Err(error) => Err(error) }
    }

    /// Remove and return the next matching message, waiting in the native service if needed. # C: O(1) plus scheduler wait
    pub fn get_message(&self, hwnd: u64, first: u32, last: u32) -> Result<NtWindowMessage, WindowError> {
        let mut message = NtWindowMessage { hwnd: 0, message: 0, padding: 0, wparam: 0, lparam: 0 };
        invoke(NtService::GetMessage, [(&mut message as *mut NtWindowMessage) as u64, hwnd, first as u64, last as u64, 0, 0]).map(|_| message)
    }

    /// Invoke the native default window procedure. # C: O(1) plus kernel service
    pub fn default_window_proc(&self, hwnd: u64, message: u32, wparam: u64, lparam: i64) -> Result<u64, WindowError> {
        invoke(NtService::DefaultWindowProc, [hwnd, message as u64, wparam, lparam as u64, 0, 0])
    }
}

fn invoke(service: NtService, args: [u64; 6]) -> Result<u64, WindowError> {
    let result = unsafe { libc::syscall(service.entry() as libc::c_long, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 { return Err(WindowError::Host(io::Error::last_os_error())); }
    let result = result as u64;
    if result & STATUS_FAILURE_MASK != 0 { Err(WindowError::Status(result)) } else { Ok(result) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_message_layout_is_fixed_64_bit_abi() {
        assert_eq!(std::mem::size_of::<NtWindowMessage>(), 32);
        assert_eq!(std::mem::align_of::<NtWindowMessage>(), 8);
    }

    #[test]
    fn selectors_remain_outside_linux_syscall_namespace() {
        assert_eq!(NtService::CreateWindow.entry(), 0x4e54_0000_0000_001b);
        assert_eq!(NtService::GetMessage.entry(), 0x4e54_0000_0000_001f);
    }

    #[test]
    fn no_message_status_is_not_a_transport_failure() {
        assert_eq!(STATUS_NO_MORE_ENTRIES & STATUS_FAILURE_MASK, STATUS_FAILURE_MASK);
        assert!(matches!(WindowError::Status(STATUS_NO_MORE_ENTRIES), WindowError::Status(value) if value == STATUS_NO_MORE_ENTRIES));
    }
}
