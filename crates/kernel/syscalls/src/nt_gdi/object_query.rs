//! Canonical font object creation/query adapters; usercopy never holds GDI.
use super::*;
use ipc::win32_gdi::{FontRecord, LOGFONTW_BYTES};
#[path = "object_query/transfer.rs"]
mod transfer;

const ERROR_NOACCESS: u32 = 998;
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;

/// Raw font ingress preserves every LOGFONTW byte and publishes the same identity.
/// # C: O(processes + fonts)
pub(crate) fn create_font_record_for_current(bytes: [u8; LOGFONTW_BYTES]) -> Result<u32, u64> {
    let record = FontRecord::from_bytes(bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
    lifecycle::create_font_record_for_current(record).map_err(|_| STATUS_INVALID_PARAMETER)
}

/// Query font bytes under the lifetime gate, copying only after the owner lock drops.
/// # C: O(processes + fonts + output bytes)
pub(crate) fn get_object_w_for_current(handle: u64, count: i32, output: u64) -> u64 {
    let Ok(handle) = u32::try_from(handle) else { return 0; };
    let Ok(_gate) = lifecycle::ClientGate::acquire_current() else { return 0; };
    let Some(cur) = sched::live::current() else { return 0; };
    let query = {
        let entries = GDI.lock();
        let Some(entry) = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
        entry.state.query_font(handle, count, output != 0)
    };
    transfer::complete_query(query, output, |address, bytes| uaccess::copy_to_user(address, bytes).is_ok(), || {
        if cur.nt_teb() != 0 {
            if let Some(address) = cur.nt_teb().checked_add(TEB_LAST_ERROR_OFFSET) { let _ = uaccess::put_user_u32(address, ERROR_NOACCESS); }
        }
    })
}
