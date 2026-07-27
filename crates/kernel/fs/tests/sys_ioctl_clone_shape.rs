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
struct FileCloneRange {
    src_fd: i64, src_offset: u64, src_length: u64, dest_offset: u64,
}

struct RemapOps {
    calls: Mutex<Vec<(u64, u64, u64, u32)>>,
}

impl RemapOps {
    fn new() -> Arc<Self> {
        Arc::new(Self { calls: Mutex::new(Vec::new()) })
    }
}

impl FileOps for RemapOps {
    fn supports_remap_file_range(&self) -> bool { true }

    fn remap_file_range(&self, _src: &File, src_off: u64, _dst: &File, dst_off: u64, len: u64, flags: u32) -> KResult<u64> {
        self.calls.lock().unwrap().push((src_off, dst_off, len, flags));
        Ok(len)
    }
}

static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7910);
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

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7910, "ioctl-clone-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file_with_fop(flags: OpenFlags, size: u64, fop: Arc<dyn FileOps>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), fop).size(size).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn remap_sb(block_size: u32) -> &'static Arc<SuperBlock> {
    let fs_ty = vfs::fs::FsType::new("remap-alignfs", 0x7930, vfs::fs::FsFlags::empty(), Box::new(|_, _, _, _| Err(vfs::VfsError::Enotty)));
    let sb = SuperBlock::new(fs_ty, Arc::new(SimpleSuperOps {
        magic: 0x7930,
        block_size,
        options: alloc::string::String::new(),
    }), 0x7930, 0x7930, block_size, "remap-alignfs".into(), Arc::new(()));
    Box::leak(Box::new(sb))
}

fn mk_file_with_fop_on_sb(flags: OpenFlags, size: u64, fop: Arc<dyn FileOps>, sb: &'static Arc<SuperBlock>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), fop).size(size).sb(Arc::downgrade(sb)).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

#[test]
fn ficlonerange_rejects_same_inode_overlap_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_fop(OpenFlags::O_RDWR, 32, remap.clone());
    let src_fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 0, src_length: 8, dest_offset: 4 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn ficlonerange_rejects_unaligned_offsets_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new();
    let sb = remap_sb(4096);
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop_on_sb(OpenFlags::O_RDONLY, 8192, remap.clone(), sb);
    let dst = mk_file_with_fop_on_sb(OpenFlags::O_RDWR, 8192, remap.clone(), sb);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 1, src_length: 4096, dest_offset: 0 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn ficlonerange_rejects_unaligned_midfile_length_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new();
    let sb = remap_sb(4096);
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop_on_sb(OpenFlags::O_RDONLY, 12288, remap.clone(), sb);
    let dst = mk_file_with_fop_on_sb(OpenFlags::O_RDWR, 12288, remap.clone(), sb);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 0, src_length: 4097, dest_offset: 4096 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn ficlonerange_rejects_partial_eof_block_into_destination_middle_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new();
    let sb = remap_sb(4096);
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop_on_sb(OpenFlags::O_RDONLY, 5000, remap.clone(), sb);
    let dst = mk_file_with_fop_on_sb(OpenFlags::O_RDWR, 8192, remap.clone(), sb);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 4096, src_length: 904, dest_offset: 0 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn ficlonerange_allows_same_inode_adjacent_ranges() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_fop(OpenFlags::O_RDWR, 32, remap.clone());
    let src_fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 0, src_length: 8, dest_offset: 8 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(0));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(0, 8, 8, 0)]);
    reset();
}
