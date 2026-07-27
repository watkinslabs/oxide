extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

mod userbuf {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static WRITABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

    pub fn reset() {
        WRITABLE_CALLS.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_readable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub fn validate_user_buf_writable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        WRITABLE_CALLS.fetch_add(1, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

#[path = "../../syscalls/src/016_ioctl/uapi.rs"]
mod uapi;
#[path = "../../syscalls/src/016_ioctl/fileattr.rs"]
mod fileattr;
#[path = "../../syscalls/src/016_ioctl/remap.rs"]
mod remap;
#[path = "../../syscalls/src/016_ioctl/common.rs"]
mod ioctl_common;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(core::ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7600);
const INODE_BLOCK_BYTES: i64 = 512;

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() { None } else {
        // SAFETY: tests leak task objects for the full test process lifetime.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(core::ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
}

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7600, "fioqsize-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(ft: FileType, size: u64, blocks: u64) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), default_inode_ops(), default_file_ops())
        .size(size).blocks(blocks).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

fn fioqsize(file: Arc<File>, out: &mut i64) -> i64 {
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIOQSIZE, out as *mut i64 as u64).unwrap()
}

#[test]
fn fioqsize_regular_reports_allocated_bytes_not_logical_size() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let file = mk_file(FileType::Regular, 123, 9);
    let mut out = -1;

    assert_eq!(fioqsize(file, &mut out), 0);

    assert_eq!(out, 9 * INODE_BLOCK_BYTES);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn fioqsize_directory_and_symlink_report_allocated_bytes() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let dir = mk_file(FileType::Directory, 4096, 2);
    let mut dir_out = -1;
    assert_eq!(fioqsize(dir, &mut dir_out), 0);
    assert_eq!(dir_out, 2 * INODE_BLOCK_BYTES);

    reset();
    let symlink = mk_file(FileType::Symlink, 11, 1);
    let mut link_out = -1;
    assert_eq!(fioqsize(symlink, &mut link_out), 0);
    assert_eq!(link_out, INODE_BLOCK_BYTES);
}

#[test]
fn fioqsize_special_file_returns_enotty_without_user_write() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let chr = mk_file(FileType::CharDev, 0, 8);
    let mut out = -1;

    assert_eq!(fioqsize(chr, &mut out), -(Errno::Enotty.as_i32() as i64));

    assert_eq!(out, -1);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 0);
}
