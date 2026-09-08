//! Native NT byte-range locks over the inode-owned record-lock state.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::nt::{NtCall, NtService};
use fs::posix_lock::{F_RDLCK, F_UNLCK, F_WRLCK};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_LOCK_NOT_GRANTED: u64 = 0xc000_0054;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const EVENT_MODIFY_STATE: u32 = 0x0002;

/// Claim the two byte-range-lock services in the Windows calling convention:
/// ten arguments for the lock, five for the unlock, with the byte range and
/// the lock key arriving as pointers and the wait and share modes as one-byte
/// flags in the caller's own frame. # C: O(locks on the inode)
pub fn dispatch_native(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::LockFile => Some(lock(call)),
        NtService::UnlockFile => Some(unlock(call)),
        _ => None,
    }
}

fn frame_tail<const N: usize>(first: usize) -> Option<[u64; N]> {
    let mut tail = [0u64; N];
    let mut index = 0;
    while index < N {
        tail[index] = crate::nt_dispatch::stack_argument(first + index)?;
        index += 1;
    }
    Some(tail)
}

fn lock(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(tail) = frame_tail::<4>(6) else { return STATUS_INVALID_PARAMETER; };
    let args = [call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5];
    let Some(request) = crate::nt_file_sig::file_lock(args, tail) else { return STATUS_ACCESS_VIOLATION; };
    let (Ok(offset), Ok(count)) = (uaccess::get_user_u64(request.offset_ptr),
        uaccess::get_user_u64(request.count_ptr)) else { return STATUS_ACCESS_VIOLATION; };
    let Some((start, end)) = crate::nt_file_lock_policy::range(offset, count) else { return STATUS_INVALID_PARAMETER; };
    let required = if request.exclusive { FILE_WRITE_DATA } else { FILE_READ_DATA };
    let native = sched::nt_object::NtHandle::from_raw(request.file);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let lock_type = if request.exclusive { F_WRLCK } else { F_RDLCK };
    if !fs::posix_lock::fmode_ok_for_setlk(&file, lock_type) { return STATUS_ACCESS_DENIED; }
    let record = vfs::RecordLock { l_type: lock_type, start, end,
        owner: fs::posix_lock::owner_for(true, &file, 0),
        pid: cur.tgid.load(core::sync::atomic::Ordering::Relaxed) };
    let result = if request.dont_wait { fs::posix_lock::setlk(&file, &record) } else { fs::posix_lock::setlkw(&file, &record) };
    let status = status_from_lock_result(result);
    if request.io_status != 0 { write_io_status(request.io_status, status, 0); }
    if status == STATUS_SUCCESS { signal_event(cur, request.event); }
    status
}

fn unlock(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let args = [call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5];
    let Some(request) = crate::nt_file_sig::file_unlock(args) else { return STATUS_ACCESS_VIOLATION; };
    let (Ok(offset), Ok(count)) = (uaccess::get_user_u64(request.offset_ptr),
        uaccess::get_user_u64(request.count_ptr)) else { return STATUS_ACCESS_VIOLATION; };
    let Some((start, end)) = crate::nt_file_lock_policy::range(offset, count) else { return STATUS_INVALID_PARAMETER; };
    let native = sched::nt_object::NtHandle::from_raw(request.file);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, 0) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let record = vfs::RecordLock { l_type: F_UNLCK, start, end,
        owner: fs::posix_lock::owner_for(true, &file, 0),
        pid: cur.tgid.load(core::sync::atomic::Ordering::Relaxed) };
    let status = status_from_lock_result(fs::posix_lock::setlk(&file, &record));
    if request.io_status != 0 { write_io_status(request.io_status, status, 0); }
    status
}

/// Signal the optional completion event a lock request may carry, through the
/// same NT event object the wait services observe. # C: O(waiters)
fn signal_event(cur: &sched::Task, event: u64) {
    if event == 0 { return; }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(crate::nt_file_sig::handle(event));
    let Some(object) = table.get(handle, EVENT_MODIFY_STATE) else { return; };
    if let Some(event) = object.event() { event.set(); }
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
