//! Native NT byte-range locks over the inode-owned record-lock state.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::nt::{NtLockFileRequest, NtUnlockFileRequest};
use fs::posix_lock::{F_RDLCK, F_UNLCK, F_WRLCK};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_LOCK_NOT_GRANTED: u64 = 0xc000_0054;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

/// Decode and apply one synchronous `NtLockFile`/`NtUnlockFile` request.
/// The ABI deliberately carries only the fields Oxide can honor today:
/// handle, flags, status record, and an absolute half-open byte range.
pub fn dispatch(cur: &sched::Task, addr: u64, unlock: bool) -> u64 {
    if unlock {
        let request = match read_unlock(addr) { Some(request) => request, None => return STATUS_INVALID_PARAMETER };
        apply_unlock(cur, request)
    } else {
        let request = match read_lock(addr) { Some(request) => request, None => return STATUS_INVALID_PARAMETER };
        apply_lock(cur, request)
    }
}

fn read_lock(addr: u64) -> Option<NtLockFileRequest> {
    Some(NtLockFileRequest {
        handle: uaccess::get_user_u32(addr).ok()?,
        flags: uaccess::get_user_u32(addr + 4).ok()?,
        io_status: uaccess::get_user_u64(addr.checked_add(8)?).ok()?,
        offset: uaccess::get_user_u64(addr + 16).ok()?,
        length: uaccess::get_user_u64(addr + 24).ok()?,
    })
}

fn read_unlock(addr: u64) -> Option<NtUnlockFileRequest> {
    Some(NtUnlockFileRequest {
        handle: uaccess::get_user_u32(addr).ok()?,
        padding: uaccess::get_user_u32(addr + 4).ok()?,
        io_status: uaccess::get_user_u64(addr.checked_add(8)?).ok()?,
        offset: uaccess::get_user_u64(addr + 16).ok()?,
        length: uaccess::get_user_u64(addr + 24).ok()?,
    })
}

fn apply_lock(cur: &sched::Task, request: NtLockFileRequest) -> u64 {
    if request.io_status == 0 { 
        return STATUS_INVALID_PARAMETER;
    }
    let Some((start, end)) = crate::nt_file_lock_policy::range(request.offset, request.length) else { return STATUS_INVALID_PARAMETER; };
    let Some(policy) = crate::nt_file_lock_policy::decode(request.flags) else { return STATUS_INVALID_PARAMETER; };
    let exclusive = policy.exclusive;
    let required = if exclusive { FILE_WRITE_DATA } else { FILE_READ_DATA };
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let lock_type = if exclusive { F_WRLCK } else { F_RDLCK };
    if !fs::posix_lock::fmode_ok_for_setlk(&file, lock_type) { return STATUS_ACCESS_DENIED; }
    let owner = fs::posix_lock::owner_for(true, &file, 0);
    let lock = vfs::RecordLock {
        l_type: lock_type,
        start,
        end,
        owner,
        pid: cur.tgid.load(core::sync::atomic::Ordering::Relaxed),
    };
    let result = if !policy.wait {
        fs::posix_lock::setlk(&file, &lock)
    } else {
        fs::posix_lock::setlkw(&file, &lock)
    };
    let status = status_from_lock_result(result);
    write_io_status(request.io_status, status, 0);
    status
}

fn apply_unlock(cur: &sched::Task, request: NtUnlockFileRequest) -> u64 {
    if request.io_status == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some((start, end)) = crate::nt_file_lock_policy::range(request.offset, request.length) else { return STATUS_INVALID_PARAMETER; };
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, 0) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let lock = vfs::RecordLock {
        l_type: F_UNLCK,
        start,
        end,
        owner: fs::posix_lock::owner_for(true, &file, 0),
        pid: cur.tgid.load(core::sync::atomic::Ordering::Relaxed),
    };
    let status = status_from_lock_result(fs::posix_lock::setlk(&file, &lock));
    write_io_status(request.io_status, status, 0);
    status
}

fn status_from_lock_result(result: i64) -> u64 {
    if result == 0 { STATUS_SUCCESS }
    else if result == -(Errno::Eagain.as_i32() as i64) { STATUS_LOCK_NOT_GRANTED }
    else { STATUS_INVALID_PARAMETER }
}

fn write_io_status(addr: u64, status: u64, information: u64) {
    let _ = uaccess::put_user_u64(addr, status);
    let Some(information_address) = addr.checked_add(8) else { return; };
    let _ = uaccess::put_user_u64(information_address, information);
}
