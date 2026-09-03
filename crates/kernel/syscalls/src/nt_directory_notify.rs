//! Native `NtNotifyChangeDirectoryFile` over the canonical VFS dirent stream.

#![cfg(target_os = "oxide-kernel")]

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as NtDirectoryWatchLock};
use syscall::nt::NtCall;

const STATUS_SUCCESS: u64 = 0;
const STATUS_PENDING: u64 = 0x0000_0103;
const STATUS_CANCELLED: u64 = 0xc000_0120;
const STATUS_HANDLES_CLOSED: u64 = 0xc000_0117;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_NOTIFY_ENUM_DIR: u64 = 0x0000_010c;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const FILE_ACTION_ADDED: u32 = 1;
const FILE_ACTION_REMOVED: u32 = 2;

struct Watch {
    handle: u32,
    owner_tid: u32,
    directory: Arc<vfs::File>,
    event: Arc<sched::nt_object::NtEvent>,
    io_status: u64,
    buffer: u64,
    length: u32,
    filter: u32,
}

static WATCHES: Spinlock<Vec<Watch>, NtDirectoryWatchLock> = Spinlock::new(Vec::new());
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

pub fn dispatch(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 > u32::MAX as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(buffer_size) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(filter) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(subtree) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    if call.args.a2 != 0 || call.args.a3 != 0 || call.args.a4 == 0 || call.args.a5 == 0
        || buffer_size == 0 || buffer_size > u32::MAX as u64 || filter > u32::MAX as u64
        || subtree != 0 { return STATUS_INVALID_PARAMETER; }
    let filter = filter as u32;
    if !crate::nt_directory_notify_policy::valid_filter(filter) { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let file_handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(file_object) = table.get(file_handle, FILE_LIST_DIRECTORY) else {
        return if table.contains(file_handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    if file_object.kind() != sched::nt_object::NtObjectType::File { return STATUS_INVALID_HANDLE; }
    let Some(directory) = file_object.file() else { return STATUS_INVALID_HANDLE; };
    let event_handle = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
    let Some(event_object) = table.get(event_handle, SYNCHRONIZE_ACCESS) else {
        return if table.contains(event_handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(event) = event_object.event() else { return STATUS_INVALID_HANDLE; };
    if !HOOK_INSTALLED.swap(true, Ordering::AcqRel) { vfs::set_dirent_observer_hook(observe); }
    let mut watches = WATCHES.lock();
    watches.push(Watch { handle: call.args.a0 as u32, owner_tid: cur.tid, directory, event, io_status: call.args.a4, buffer: call.args.a5,
        length: buffer_size as u32, filter });
    STATUS_PENDING
}

/// Cancel pending directory watches owned by one issuing thread. # C: O(N_watches)
pub fn cancel(handle: u32, owner_tid: u32, target_io_status: Option<u64>) -> bool {
    let mut watches = WATCHES.lock();
    let mut cancelled = false;
    let mut index = 0;
    while index < watches.len() {
        let watch = &watches[index];
        if watch.handle != handle || watch.owner_tid != owner_tid
            || target_io_status.is_some_and(|target| target != watch.io_status) {
            index += 1;
            continue;
        }
        let watch = watches.remove(index);
        let _ = uaccess::put_user_u64(watch.io_status, STATUS_CANCELLED);
        let _ = uaccess::put_user_u64(watch.io_status.saturating_add(8), 0);
        watch.event.set();
        cancelled = true;
    }
    cancelled
}

/// Tear down watches before the corresponding NT handle is removed. # C: O(N_watches)
pub fn close(handle: u32) {
    let mut watches = WATCHES.lock();
    let mut index = 0;
    while index < watches.len() {
        if watches[index].handle != handle { index += 1; continue; }
        let watch = watches.remove(index);
        let _ = uaccess::put_user_u64(watch.io_status, STATUS_HANDLES_CLOSED);
        let _ = uaccess::put_user_u64(watch.io_status.saturating_add(8), 0);
        watch.event.set();
    }
}

fn observe(parent: &vfs::InodeRef, leaf: &str, child_dir: bool, action: u32) {
    let required = if child_dir { crate::nt_directory_notify_policy::FILE_NOTIFY_CHANGE_DIR_NAME } else { crate::nt_directory_notify_policy::FILE_NOTIFY_CHANGE_FILE_NAME };
    if action != vfs::DIRENT_CREATE && action != vfs::DIRENT_DELETE { return; }
    let mut watches = WATCHES.lock();
    let mut index = 0;
    while index < watches.len() {
        if !Arc::ptr_eq(watches[index].directory.inode(), parent) || watches[index].filter & required == 0 {
            index += 1;
            continue;
        }
        let watch = watches.remove(index);
        let status = write_record(&watch, leaf, if action == vfs::DIRENT_CREATE { FILE_ACTION_ADDED } else { FILE_ACTION_REMOVED });
        let _ = uaccess::put_user_u64(watch.io_status, status);
        let _ = uaccess::put_user_u64(watch.io_status.saturating_add(8), if status == STATUS_SUCCESS { crate::nt_directory_notify_policy::record_size(leaf) as u64 } else { 0 });
        watch.event.set();
    }
}

fn write_record(watch: &Watch, leaf: &str, action: u32) -> u64 {
    let size = crate::nt_directory_notify_policy::record_size(leaf);
    if size > watch.length as usize { return STATUS_NOTIFY_ENUM_DIR; }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(size).is_err() { return STATUS_NO_MEMORY; }
    bytes.resize(size, 0);
    let Some(_) = crate::nt_directory_notify_policy::encode_record(leaf, action, &mut bytes) else {
        return STATUS_NOTIFY_ENUM_DIR;
    };
    if uaccess::copy_to_user(watch.buffer, &bytes).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS }
}
