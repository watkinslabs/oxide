extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, InodeOps, InodeRef,
          KResult, OpenFlags, default_file_ops, default_inode_ops, mk_mode};

mod userbuf {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static READABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static WRITABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

    pub fn reset() {
        READABLE_CALLS.store(0, Ordering::SeqCst);
        WRITABLE_CALLS.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_readable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        READABLE_CALLS.fetch_add(1, Ordering::SeqCst);
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

const O_ASYNC: u32 = 0o20000;

#[derive(Default)]
struct AsyncOps {
    calls: AtomicUsize,
}

impl InodeOps for AsyncOps {}

impl FileOps for AsyncOps {
    fn fasync_file(&self, _fd: i32, file: &Arc<File>, on: bool) -> KResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        file.set_fasync_state(on);
        Ok(())
    }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7680);

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store only leaked Task pointers.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
}

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7680, "ioctl-fasync-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_default_file(ft: FileType, flags: OpenFlags) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), default_inode_ops(), default_file_ops()).build();
    File::new(Arc::clone(&ino), Dentry::new_root(ino), flags)
}

fn mk_async_file(flags: OpenFlags, ops: Arc<AsyncOps>) -> Arc<File> {
    let i_op: Arc<dyn InodeOps> = ops.clone();
    let f_op: Arc<dyn FileOps> = ops;
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Socket, 0o600), i_op, f_op).build();
    File::new(Arc::clone(&ino), Dentry::new_root(ino), flags)
}

fn context(file: Arc<File>) -> (Arc<FdTable>, i32, &'static Task) {
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(file).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    (fdt, fd, task)
}

#[test]
fn fioasync_unsupported_state_change_returns_enotty_without_side_effects() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let before = vfs::file::fasync_registered();
    let file = mk_default_file(FileType::Regular, OpenFlags::O_RDONLY);
    let (fdt, fd, task) = context(Arc::clone(&file));
    let on: i32 = 1;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIOASYNC, &on as *const i32 as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));

    assert_eq!(file.flags().bits() & O_ASYNC, 0);
    assert_eq!(vfs::file::fasync_registered(), before);
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn socket_owner_ioctl_aliases_share_linux_f_owner_and_usercopy_order() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let file = mk_async_file(OpenFlags::O_RDWR, Arc::new(AsyncOps::default()));
    // Linux represents a process-group owner with a negative `f_owner` id.
    const TEST_PROCESS_GROUP_OWNER: i32 = -0x1234;
    let owner = TEST_PROCESS_GROUP_OWNER;
    assert_eq!(ioctl_common::handle_socket_owner_ioctl(&file, uapi::FIOSETOWN,
        &owner as *const i32 as u64), Some(0));
    assert_eq!(file.f_getown(), owner);
    let mut got = 0;
    assert_eq!(ioctl_common::handle_socket_owner_ioctl(&file, uapi::SIOCGPGRP,
        &mut got as *mut i32 as u64), Some(0));
    assert_eq!(got, owner);
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(ioctl_common::handle_socket_owner_ioctl(&file, uapi::SIOCSPGRP, 0),
        Some(-(Errno::Efault.as_i32() as i64)));
    reset();
}

#[test]
fn fioasync_same_state_is_noop_even_without_backend_fasync() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let file = mk_default_file(FileType::Regular, OpenFlags::from_bits_retain(O_ASYNC));
    let (fdt, fd, task) = context(Arc::clone(&file));
    let on: i32 = 1;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIOASYNC, &on as *const i32 as u64), Some(0));

    assert_ne!(file.flags().bits() & O_ASYNC, 0);
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn fioasync_supported_backend_toggles_fasync_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let before = vfs::file::fasync_registered();
    let ops = Arc::new(AsyncOps::default());
    let file = mk_async_file(OpenFlags::O_RDWR, Arc::clone(&ops));
    let (fdt, fd, task) = context(Arc::clone(&file));
    let on: i32 = 1;
    let off: i32 = 0;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIOASYNC, &on as *const i32 as u64), Some(0));
    assert_ne!(file.flags().bits() & O_ASYNC, 0);
    assert_eq!(vfs::file::fasync_registered(), before + 1);

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIOASYNC, &off as *const i32 as u64), Some(0));
    assert_eq!(file.flags().bits() & O_ASYNC, 0);
    assert_eq!(vfs::file::fasync_registered(), before);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 2);
    reset();
}

#[test]
fn fioasync_bad_user_pointer_faults_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(AsyncOps::default());
    let file = mk_async_file(OpenFlags::O_RDWR, Arc::clone(&ops));
    let (fdt, fd, task) = context(Arc::clone(&file));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIOASYNC, 0),
        Some(-(Errno::Efault.as_i32() as i64)));

    assert_eq!(ops.calls.load(Ordering::SeqCst), 0);
    assert_eq!(file.flags().bits() & O_ASYNC, 0);
    reset();
}
