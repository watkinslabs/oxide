extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

mod userbuf {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static READABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static WRITABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static LAST_LEN: AtomicU64 = AtomicU64::new(0);

    pub fn reset() {
        READABLE_CALLS.store(0, Ordering::SeqCst);
        WRITABLE_CALLS.store(0, Ordering::SeqCst);
        LAST_LEN.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_readable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        READABLE_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        WRITABLE_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

#[path = "../../syscalls/src/016_ioctl/common.rs"]
mod ioctl_common;

const FIONREAD: u64 = 0x541B;
const FIONBIO: u64 = 0x5421;
const FIONCLEX: u64 = 0x5450;
const FIOCLEX: u64 = 0x5451;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x1600);

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store only leaked Task pointers and clear the hook pointer before returning.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
}

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x1600, "ioctl-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(ft: FileType, flags: OpenFlags, size: u64) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), default_inode_ops(), default_file_ops()).size(size).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

#[test]
fn fioclex_and_fionclex_update_fdtable_close_on_exec() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Regular, OpenFlags::O_RDONLY, 0)).unwrap();
    install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(&file_for(&fdt, fd), &fdt, fd, FIOCLEX, 0), Some(0));
    assert_eq!(fdt.cloexec(fd), Ok(true));
    assert_eq!(ioctl_common::handle_common_ioctl(&file_for(&fdt, fd), &fdt, fd, FIONCLEX, 0), Some(0));
    assert_eq!(fdt.cloexec(fd), Ok(false));
    reset();
}

#[test]
fn fionbio_is_common_before_chardev_fallback_and_bad_pointer_faults() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::CharDev, OpenFlags::O_RDONLY, 0);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    install_current_with_fdt(Arc::clone(&fdt));
    let mut on: i32 = 1;

    assert_eq!(ioctl_common::handle_common_ioctl(&file, &fdt, fd, FIONBIO, &mut on as *mut i32 as u64), Some(0));
    assert!(file.flags().contains(OpenFlags::O_NONBLOCK));
    assert_eq!(ioctl_common::handle_common_ioctl(&file, &fdt, fd, FIONBIO, 0), Some(-(Errno::Efault.as_i32() as i64)));
    reset();
}

#[test]
fn regular_fionread_reports_size_minus_position_as_linux_common_ioctl() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 12);
    file.set_pos(5);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    install_current_with_fdt(Arc::clone(&fdt));
    let mut out: i32 = -1;

    assert_eq!(ioctl_common::handle_common_ioctl(&file, &fdt, fd, FIONREAD, &mut out as *mut i32 as u64), Some(0));
    assert_eq!(out, 7);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn socket_fionread_rejects_null_out_pointer_instead_of_succeeding() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Socket, OpenFlags::O_RDWR, 0)).unwrap();
    install_current_with_fdt(Arc::clone(&fdt));

    let file = file_for(&fdt, fd);
    assert_eq!(ioctl_common::handle_common_ioctl(&file, &fdt, fd, FIONREAD, 0), None);
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, FIONREAD, 0), Some(-(Errno::Efault.as_i32() as i64)));
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

fn file_for(fdt: &FdTable, fd: i32) -> Arc<File> {
    fdt.get(fd).expect("fd installed")
}
