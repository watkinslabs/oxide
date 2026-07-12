extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileAttr, FileType, Inode, InodeBuilder, InodeOps,
          InodeRef, KResult, OpenFlags, SimpleSuperOps, SuperBlock, VfsError,
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

#[path = "../../syscalls/src/016_ioctl/uapi.rs"]
mod uapi;
#[path = "../../syscalls/src/016_ioctl/common.rs"]
mod ioctl_common;

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

#[derive(Default)]
struct IoctlOps {
    bmap_block: AtomicU64,
    fallocate_calls: Mutex<Vec<(u64, u64, bool, bool, bool)>>,
    attr: Mutex<FileAttr>,
}

impl InodeOps for IoctlOps {
    fn bmap(&self, _inode: &Inode, block: u64) -> KResult<u64> {
        Ok(self.bmap_block.load(Ordering::SeqCst) + block)
    }

    fn fallocate(&self, _inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool, punch: bool) -> KResult<()> {
        self.fallocate_calls.lock().unwrap().push((off, len, keep_size, zero_range, punch));
        Ok(())
    }

    fn fileattr_get(&self, _inode: &Inode) -> KResult<FileAttr> {
        Ok(*self.attr.lock().unwrap())
    }

    fn fileattr_set(&self, _inode: &Inode, fa: &FileAttr) -> KResult<()> {
        *self.attr.lock().unwrap() = *fa;
        Ok(())
    }
}

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

fn mk_file_with_ops(flags: OpenFlags, size: u64, ops: Arc<IoctlOps>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), ops, default_file_ops()).size(size).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn mk_file_with_uuid(uuid: [u8; 16]) -> Arc<File> {
    let fs_ty = vfs::fs::FsType::new("uuidfs", 0x1600, vfs::fs::FsFlags::empty(), Box::new(|_, _, _, _| Err(VfsError::Enotty)));
    let sb = SuperBlock::new(fs_ty, Arc::new(SimpleSuperOps {
        magic: 0x1600,
        block_size: 4096,
        options: alloc::string::String::new(),
    }), 0x1600, 0x1600, 4096, "uuidfs".into(), Arc::new(()));
    sb.set_uuid(uuid, 16);
    let sb = Box::leak(Box::new(sb));
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

#[test]
fn fioclex_and_fionclex_update_fdtable_close_on_exec() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Regular, OpenFlags::O_RDONLY, 0)).unwrap();

    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file_for(&fdt, fd), &fdt, fd, uapi::FIOCLEX, 0), Some(0));
    assert_eq!(fdt.cloexec(fd), Ok(true));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file_for(&fdt, fd), &fdt, fd, uapi::FIONCLEX, 0), Some(0));
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
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut on: i32 = 1;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONBIO, &mut on as *mut i32 as u64), Some(0));
    assert!(file.flags().contains(OpenFlags::O_NONBLOCK));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONBIO, 0), Some(-(Errno::Efault.as_i32() as i64)));
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
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out: i32 = -1;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, &mut out as *mut i32 as u64), Some(0));
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
    let task = install_current_with_fdt(Arc::clone(&fdt));

    let file = file_for(&fdt, fd);
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, 0), None);
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::FIONREAD, 0), Some(-(Errno::Efault.as_i32() as i64)));
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn fibmap_requires_rawio_and_writes_bmap_result() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(IoctlOps::default());
    ops.bmap_block.store(100, Ordering::SeqCst);
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDONLY, 0, ops);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut block: i32 = 7;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIBMAP, &mut block as *mut i32 as u64), Some(0));
    assert_eq!(block, 107);
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn preallocate_ioctls_adjust_whence_and_call_fallocate_keep_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(IoctlOps::default());
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDWR, 40, Arc::clone(&ops));
    file.set_pos(5);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let sr = SpaceResv { l_type: 0, l_whence: 1, l_start: 3, l_len: 9, l_sysid: 0, l_pid: 0, l_pad: [0; 4] };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_RESVSP, &sr as *const SpaceResv as u64), Some(0));
    let hole = SpaceResv { l_type: 0, l_whence: 2, l_start: -10, l_len: 4, l_sysid: 0, l_pid: 0, l_pad: [0; 4] };
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_UNRESVSP, &hole as *const SpaceResv as u64), Some(0));
    assert_eq!(*ops.fallocate_calls.lock().unwrap(), vec![
        (8, 9, true, false, false),
        (30, 4, true, false, true),
    ]);
    reset();
}

#[test]
fn fsxattr_get_and_set_translate_linux_xflags() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(IoctlOps::default());
    *ops.attr.lock().unwrap() = FileAttr { flags: 0x10 | 0x80, fsx_xflags: 0, fsx_projid: 0 };
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDWR, 0, Arc::clone(&ops));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut xattr = [0u8; 28];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSGETXATTR, xattr.as_mut_ptr() as u64), Some(0));
    assert_eq!(u32::from_ne_bytes(xattr[0..4].try_into().unwrap()), 0x08 | 0x40);
    xattr[0..4].copy_from_slice(&(0x10u32 | 0x80u32).to_ne_bytes());
    xattr[12..16].copy_from_slice(&42u32.to_ne_bytes());
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64), Some(0));
    assert_eq!(*ops.attr.lock().unwrap(), FileAttr { flags: 0x20 | 0x40, fsx_xflags: 0x10 | 0x80, fsx_projid: 42 });
    reset();
}

#[test]
fn getfsuuid_copies_superblock_uuid_or_enotty_without_one() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let uuid = [0xAB; 16];
    let file = mk_file_with_uuid(uuid);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out = [0u8; 17];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_GETFSUUID, out.as_mut_ptr() as u64), Some(0));
    assert_eq!(out[0], 16);
    assert_eq!(&out[1..], &uuid);
    reset();
}

fn file_for(fdt: &FdTable, fd: i32) -> Arc<File> {
    fdt.get(fd).expect("fd installed")
}
