//! NT filesystem-information queries backed by the owning VFS superblock.

#![cfg(target_os = "oxide-kernel")]

use crate::nt_file_volume_abi::encode;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;

/// Answer filesystem-information queries using the file's captured mount and
/// inode, preserving the VFS statfs owner and NT output framing. # C: O(1)
pub fn query(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let Some(object) = table.get(native, FILE_READ_ATTRIBUTES) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let Some(mount) = file.vfsmount() else { return STATUS_INVALID_HANDLE; };
    let Ok(stat) = mount.sb.statfs_at(file.inode()) else { return STATUS_INVALID_PARAMETER; };
    let (payload, required) = match encode(&stat, class) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if (length as usize) < required {
        return finish(io_status, STATUS_BUFFER_TOO_SMALL, 0);
    }
    if uaccess::copy_to_user(information, &payload).is_err() { return STATUS_ACCESS_VIOLATION; }
    if finish(io_status, STATUS_SUCCESS, required as u64) != STATUS_SUCCESS { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

fn finish(io_status: u64, status: u64, information: u64) -> u64 {
    if uaccess::put_user_u64(io_status, status).is_err()
        || io_status.checked_add(8).and_then(|address| uaccess::put_user_u64(address, information).ok()).is_none() {
        STATUS_ACCESS_VIOLATION
    } else { status }
}
