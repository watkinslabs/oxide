extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, InodeRef, KResult,
          OpenFlags, SimpleSuperOps, SuperBlock, default_inode_ops, mk_mode};

mod userbuf {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static LAST_LEN: AtomicU64 = AtomicU64::new(0);
    pub static READABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static WRITABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

    pub fn reset() {
        LAST_LEN.store(0, Ordering::SeqCst);
        READABLE_CALLS.store(0, Ordering::SeqCst);
        WRITABLE_CALLS.store(0, Ordering::SeqCst);
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

#[path = "../../syscalls/src/016_ioctl/uapi.rs"]
mod uapi;
#[path = "../../syscalls/src/016_ioctl/fileattr.rs"]
mod fileattr;
#[path = "../../syscalls/src/016_ioctl/remap.rs"]
mod remap;
#[path = "../../syscalls/src/016_ioctl/common.rs"]
mod ioctl_common;

#[repr(C)]
struct FileDedupeRangeInfo {
    dest_fd: i64, dest_offset: u64, bytes_deduped: u64, status: i32, reserved: u32,
}

#[repr(C)]
struct FileDedupeRangeOne {
    src_offset: u64, src_length: u64, dest_count: u16, reserved1: u16, reserved2: u32,
    info: [FileDedupeRangeInfo; 1],
}

struct RemapOps {
    ret: Mutex<KResult<u64>>,
    calls: Mutex<Vec<(u64, u64, u64, u32)>>,
}

impl RemapOps {
    fn new(ret: KResult<u64>) -> Arc<Self> {
        Arc::new(Self { ret: Mutex::new(ret), calls: Mutex::new(Vec::new()) })
    }
}

impl FileOps for RemapOps {
    fn supports_remap_file_range(&self) -> bool { true }

    fn remap_file_range(&self, _src: &File, src_off: u64, _dst: &File, dst_off: u64, len: u64, flags: u32) -> KResult<u64> {
        self.calls.lock().unwrap().push((src_off, dst_off, len, flags));
        *self.ret.lock().unwrap()
    }
}

static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7900);
static TEST_LOCK: Mutex<()> = Mutex::new(());

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

fn install_current_with_fdt_cred(fdt: Arc<FdTable>, uid: u32, gid: u32, caps: u64) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7900, "ioctl-dedupe-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    task.creds.fsuid.store(uid, Ordering::Release);
    task.creds.fsgid.store(gid, Ordering::Release);
    task.creds.cap_effective.store(caps, Ordering::Release);
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(ft: FileType, flags: OpenFlags, size: u64, fop: Arc<dyn FileOps>, perm: u16, uid: u32, gid: u32) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, perm), default_inode_ops(), fop).size(size).owner(uid, gid).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn remap_sb(block_size: u32) -> &'static Arc<SuperBlock> {
    let fs_ty = vfs::fs::FsType::new("dedupe-alignfs", 0x7931, vfs::fs::FsFlags::empty(), Box::new(|_, _, _, _| Err(vfs::VfsError::Enotty)));
    let sb = SuperBlock::new(fs_ty, Arc::new(SimpleSuperOps {
        magic: 0x7931,
        block_size,
        options: alloc::string::String::new(),
    }), 0x7931, 0x7931, block_size, "dedupe-alignfs".into(), Arc::new(()));
    Box::leak(Box::new(sb))
}

fn mk_file_on_sb(ft: FileType, flags: OpenFlags, size: u64, fop: Arc<dyn FileOps>, perm: u16, uid: u32, gid: u32, sb: &'static Arc<SuperBlock>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, perm), default_inode_ops(), fop).size(size).owner(uid, gid).sb(Arc::downgrade(sb)).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

#[test]
fn fideduperange_allows_destination_with_may_write_permission() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(4));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone(), 0o644, 0, 0);
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone(), 0o666, 1000, 1000);
    let dst_fd = fdt.alloc(dst).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let task = install_current_with_fdt_cred(Arc::clone(&fdt), 2000, 2000, 0);
    let mut range = FileDedupeRangeOne {
        src_offset: 2,
        src_length: 4,
        dest_count: 1,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_fd as i64, dest_offset: 6, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &src, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 4);
    assert_eq!(range.info[0].status, 0);
    assert_eq!(*remap.calls.lock().unwrap(), vec![(2, 6, 4, 3)]);
    reset();
}

#[test]
fn fideduperange_rejects_unaligned_destination_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(4096));
    let sb = remap_sb(4096);
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_on_sb(FileType::Regular, OpenFlags::O_RDONLY, 8192, remap.clone(), 0o644, 0, 0, sb);
    let dst = mk_file_on_sb(FileType::Regular, OpenFlags::O_RDONLY, 8192, remap.clone(), 0o666, 1000, 1000, sb);
    let dst_fd = fdt.alloc(dst).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let task = install_current_with_fdt_cred(Arc::clone(&fdt), 2000, 2000, 0);
    let mut range = FileDedupeRangeOne {
        src_offset: 0,
        src_length: 4096,
        dest_count: 1,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_fd as i64, dest_offset: 1, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &src, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 0);
    assert_eq!(range.info[0].status, -(Errno::Einval.as_i32()));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn fideduperange_rejects_destination_range_past_eof_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(4));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone(), 0o644, 0, 0);
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 8, remap.clone(), 0o666, 1000, 1000);
    let dst_fd = fdt.alloc(dst).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let task = install_current_with_fdt_cred(Arc::clone(&fdt), 2000, 2000, 0);
    let mut range = FileDedupeRangeOne {
        src_offset: 2,
        src_length: 4,
        dest_count: 1,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_fd as i64, dest_offset: 6, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &src, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 0);
    assert_eq!(range.info[0].status, -(Errno::Einval.as_i32()));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn fideduperange_rejects_same_inode_overlap_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(4));
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDWR, 20, remap.clone(), 0o644, 0, 0);
    let dst_fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt_cred(Arc::clone(&fdt), 2000, 2000, 0);
    let mut range = FileDedupeRangeOne {
        src_offset: 2,
        src_length: 4,
        dest_count: 1,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_fd as i64, dest_offset: 4, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 0);
    assert_eq!(range.info[0].status, -(Errno::Einval.as_i32()));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn fideduperange_shortens_partial_eof_block_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(2048));
    let sb = remap_sb(1024);
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_on_sb(FileType::Regular, OpenFlags::O_RDONLY, 3000, remap.clone(), 0o644, 0, 0, sb);
    let dst = mk_file_on_sb(FileType::Regular, OpenFlags::O_RDONLY, 5000, remap.clone(), 0o666, 1000, 1000, sb);
    let dst_fd = fdt.alloc(dst).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let task = install_current_with_fdt_cred(Arc::clone(&fdt), 2000, 2000, 0);
    let mut range = FileDedupeRangeOne {
        src_offset: 0,
        src_length: 3000,
        dest_count: 1,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_fd as i64, dest_offset: 0, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &src, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 3000);
    assert_eq!(range.info[0].status, 0);
    assert_eq!(*remap.calls.lock().unwrap(), vec![(0, 0, 2048, 3)]);
    reset();
}
