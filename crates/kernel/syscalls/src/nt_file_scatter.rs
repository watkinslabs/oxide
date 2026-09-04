//! Native NT scatter-read adapter over the canonical VFS file object.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::vec;
use syscall::nt::{NtCall, NtService};
use crate::nt_file_scatter_policy as policy;

const MAX_NT_IO: usize = 16 * 1024 * 1024;
const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

/// Claim the native scatter service; file identity and I/O remain owned by
/// the process-local NT object table and retained VFS open description. # C: O(pages)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::NtReadFileScatter { Some(read(call)) } else { None }
}

fn read(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return policy::STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 { return policy::STATUS_INVALID_PARAMETER; }
    let Some(length) = crate::nt_dispatch::stack_argument(6) else { return policy::STATUS_INVALID_PARAMETER; };
    let Some(offset_ptr) = crate::nt_dispatch::stack_argument(7) else { return policy::STATUS_INVALID_PARAMETER; };
    let Some(_key) = crate::nt_dispatch::stack_argument(8) else { return policy::STATUS_INVALID_PARAMETER; };
    if length > MAX_NT_IO as u64 { return policy::STATUS_INVALID_PARAMETER; }
    let offset = if offset_ptr == 0 { None } else {
        let Ok(raw) = uaccess::get_user_u64(offset_ptr) else { return policy::STATUS_INVALID_PARAMETER; };
        let value = raw as i64;
        if value < 0 && value != FILE_USE_FILE_POINTER_POSITION { return policy::STATUS_INVALID_PARAMETER; }
        if value == FILE_USE_FILE_POINTER_POSITION { None } else { Some(raw) }
    };
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(native, policy::FILE_READ_DATA) else {
        return if table.contains(native) { policy::STATUS_ACCESS_DENIED } else { policy::STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return policy::STATUS_INVALID_HANDLE; };
    let Some(info) = object.file_info() else { return policy::STATUS_INVALID_HANDLE; };
    let page_size = hal::PAGE_SIZE_BYTES as usize;
    let pages = match policy::validate_shape(call.args.a4, call.args.a5, length as usize,
        page_size, MAX_NT_IO, info.fd_type, info.options) {
        Ok(pages) => pages,
        Err(status) => return status,
    };
    let mut page = vec![0u8; page_size];
    let mut total = 0usize;
    let mut status = policy::STATUS_SUCCESS;
    for index in 0..pages {
        let Some(entry_offset) = (index as u64).checked_mul(8) else { status = policy::STATUS_INVALID_PARAMETER; break; };
        let Some(entry) = call.args.a5.checked_add(entry_offset) else { status = policy::STATUS_INVALID_USER_BUFFER; break; };
        let Ok(destination) = uaccess::get_user_u64(entry) else { status = policy::STATUS_INVALID_USER_BUFFER; break; };
        if !policy::validate_segment(destination, page_size) { status = policy::STATUS_INVALID_USER_BUFFER; break; }
        let result = match offset {
            Some(base) => {
                let Some(at) = base.checked_add(total as u64).and_then(|value| i64::try_from(value).ok()) else {
                    status = policy::STATUS_INVALID_PARAMETER; break;
                };
                file.pread(&mut page, at)
            }
            None => file.read(&mut page),
        };
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => { status = crate::nt_file_policy::status_from_errno(-(error as i64)); break; }
        };
        if bytes == 0 { break; }
        if uaccess::copy_to_user(destination, &page[..bytes]).is_err() { status = policy::STATUS_INVALID_USER_BUFFER; break; }
        total = total.saturating_add(bytes);
        if bytes != page_size { break; }
    }
    if status == policy::STATUS_SUCCESS { status = policy::completion_status(length as usize, total); }
    super::nt_file::write_io_status(call.args.a4, status, total as u64);
    super::nt_file::post_completion(&object, call.args.a3, status, total as u64);
    status
}
