extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use vfs::{Dentry, FdTable, File, FileType, Inode, InodeBuilder, InodeOps, InodeRef,
          KResult, OpenFlags, default_file_ops, mk_mode};

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

#[derive(Default)]
struct Ops {
    bmap_calls: AtomicUsize,
    fallocate_calls: Mutex<Vec<(u64, u64, bool, bool, bool)>>,
}

impl InodeOps for Ops {
    fn bmap(&self, _inode: &Inode, block: u64) -> KResult<u64> {
        self.bmap_calls.fetch_add(1, Ordering::SeqCst);
        Ok(block + 10)
    }

    fn fallocate(&self, _inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool, punch: bool) -> KResult<()> {
        self.fallocate_calls.lock().unwrap().push((off, len, keep_size, zero_range, punch));
        Ok(())
    }
}

#[repr(C)]
struct SpaceResv {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_sysid: i32,
    l_pid: u32,
    l_pad: [i32; 4],
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7670);

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
    let task = Box::leak(Box::new(Task::new(0x7670, "ioctl-gate-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(ft: FileType, flags: OpenFlags, ops: Arc<Ops>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), ops, default_file_ops()).size(100).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn context(file: Arc<File>) -> (Arc<FdTable>, i32, &'static Task) {
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(file).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    (fdt, fd, task)
}

#[test]
fn fibmap_non_regular_files_do_not_take_regular_file_ioctl_path() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(Ops::default());
    let dir = mk_file(FileType::Directory, OpenFlags::O_RDONLY, Arc::clone(&ops));
    let (fdt, fd, task) = context(Arc::clone(&dir));
    let mut block = 3i32;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dir, &fdt, fd, uapi::FIBMAP, &mut block as *mut i32 as u64), None);

    assert_eq!(block, 3);
    assert_eq!(ops.bmap_calls.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn preallocate_non_regular_files_do_not_take_regular_file_ioctl_path() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(Ops::default());
    let symlink = mk_file(FileType::Symlink, OpenFlags::O_RDWR, Arc::clone(&ops));
    let (fdt, fd, task) = context(Arc::clone(&symlink));
    let sr = SpaceResv { l_type: 0, l_whence: uapi::SEEK_SET, l_start: 4, l_len: 8, l_sysid: 0, l_pid: 0, l_pad: [0; 4] };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &symlink, &fdt, fd, uapi::FS_IOC_RESVSP, &sr as *const SpaceResv as u64), None);

    assert!(ops.fallocate_calls.lock().unwrap().is_empty());
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn regular_files_still_take_fibmap_and_preallocate_paths() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(Ops::default());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDWR, Arc::clone(&ops));
    let (fdt, fd, task) = context(Arc::clone(&file));
    let mut block = 5i32;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIBMAP, &mut block as *mut i32 as u64), Some(0));
    assert_eq!(block, 15);

    let sr = SpaceResv { l_type: 0, l_whence: uapi::SEEK_SET, l_start: 6, l_len: 7, l_sysid: 0, l_pid: 0, l_pad: [0; 4] };
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_ZERO_RANGE, &sr as *const SpaceResv as u64), Some(0));
    assert_eq!(*ops.fallocate_calls.lock().unwrap(), vec![(6, 7, true, true, false)]);
}
