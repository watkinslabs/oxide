//! Native x86_64 TLS cleanup used by the Windows user DLL layer.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const THREAD_ZERO_TLS_CELL: u32 = 10;
const CURRENT_THREAD: u64 = u64::MAX - 1;
const TEB_TLS_SLOTS_OFFSET: u64 = 0x1480;
const TEB_TLS_SLOT_COUNT: u32 = 64;
const TEB_TLS_EXPANSION_POINTER_OFFSET: u64 = 0x1780;
const TLS_EXPANSION_SLOT_COUNT: u32 = 1024;

/// Clear one TLS cell on the current thread.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::SetInformationThread || call.args.a1 as u32 != THREAD_ZERO_TLS_CELL {
        return None;
    }
    Some(zero_tls_cell(call.args.a0, call.args.a2, call.args.a3 as u32))
}

fn zero_tls_cell(thread: u64, info: u64, length: u32) -> u64 {
    if thread != CURRENT_THREAD || info == 0 || length != core::mem::size_of::<u32>() as u32 {
        return if thread == CURRENT_THREAD { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED };
    }
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !task.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Ok(index) = uaccess::get_user_u32(info) else { return STATUS_INVALID_PARAMETER; };
    let teb = task.nt_teb();
    if teb == 0 { return STATUS_INVALID_PARAMETER; }
    if index < TEB_TLS_SLOT_COUNT {
        let Some(address) = teb.checked_add(TEB_TLS_SLOTS_OFFSET + index as u64 * 8) else { return STATUS_INVALID_PARAMETER; };
        return uaccess::put_user_u64(address, 0).map_or(STATUS_INVALID_PARAMETER, |_| STATUS_SUCCESS);
    }
    let expansion_index = index - TEB_TLS_SLOT_COUNT;
    if expansion_index >= TLS_EXPANSION_SLOT_COUNT { return STATUS_INVALID_PARAMETER; }
    let Some(expansion_pointer) = teb.checked_add(TEB_TLS_EXPANSION_POINTER_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let Ok(slots) = uaccess::get_user_u64(expansion_pointer) else { return STATUS_INVALID_PARAMETER; };
    if slots == 0 { return STATUS_SUCCESS; }
    let Some(address) = slots.checked_add(expansion_index as u64 * 8) else { return STATUS_INVALID_PARAMETER; };
    uaccess::put_user_u64(address, 0).map_or(STATUS_INVALID_PARAMETER, |_| STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tls_layout_has_expected_x64_limits() {
        assert_eq!(TEB_TLS_SLOTS_OFFSET, 0x1480);
        assert_eq!(TEB_TLS_EXPANSION_POINTER_OFFSET, 0x1780);
        assert_eq!(TEB_TLS_SLOT_COUNT + TLS_EXPANSION_SLOT_COUNT, 1088);
        assert_eq!(THREAD_ZERO_TLS_CELL, 10);
    }
}
