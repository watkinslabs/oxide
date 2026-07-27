extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{Dentry, Devt, FdTable, File, FileAttr, FileOps, FileType, Inode, InodeBuilder, InodeOps,
          InodeRef, KResult, OpenFlags, SimpleSuperOps, SuperBlock, VfsError, make_device_node_inode,
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
#[path = "../../syscalls/src/016_ioctl/blk.rs"]
mod blk;
#[path = "../../syscalls/src/016_ioctl/fileattr.rs"]
mod fileattr;
#[path = "../../syscalls/src/016_ioctl/remap.rs"]
mod remap;
#[path = "../../syscalls/src/016_ioctl/common.rs"]
mod ioctl_common;

#[repr(C)]
struct SpaceResv {
    l_type: i16, l_whence: i16, l_start: i64, l_len: i64, l_sysid: i32, l_pid: u32,
    l_pad: [i32; 4],
}

#[repr(C)]
struct FileCloneRange {
    src_fd: i64, src_offset: u64, src_length: u64, dest_offset: u64,
}

#[repr(C)]
struct FileDedupeRangeInfo {
    dest_fd: i64, dest_offset: u64, bytes_deduped: u64, status: i32, reserved: u32,
}

#[repr(C)]
struct FileDedupeRangeOne {
    src_offset: u64, src_length: u64, dest_count: u16, reserved1: u16, reserved2: u32,
    info: [FileDedupeRangeInfo; 2],
}

#[derive(Default)]
struct IoctlOps {
    bmap_block: AtomicU64,
    fallocate_calls: Mutex<Vec<(u64, u64, bool, bool, bool)>>,
    attr: Mutex<FileAttr>,
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

    fn ioctl_int(&self, _file: &File, cmd: vfs::IoctlIntCmd) -> KResult<u32> {
        match cmd {
            vfs::IoctlIntCmd::Fionread => Ok(4),
            vfs::IoctlIntCmd::Siocoutq => Ok(0),
            vfs::IoctlIntCmd::Siocoutqnsd => Err(VfsError::Enotty),
            vfs::IoctlIntCmd::Siocatmark => Err(VfsError::Enotty),
        }
    }
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
/// Linux BLKZEROOUT remains 512-byte ABI-addressed, but the request itself
/// must meet the device's logical block alignment.
const TEST_SECTOR_BYTES: u32 = 512;
const TEST_FOUR_KIB_BLOCK_BYTES: u32 = 4096;
const TEST_FOUR_KIB_BLOCK_COUNT: u64 = 2;
const MISALIGNED_ZEROOUT_BYTES: u64 = TEST_SECTOR_BYTES as u64;
const LOGICAL_BLOCK_ZEROOUT_BYTES: u64 = TEST_FOUR_KIB_BLOCK_BYTES as u64;

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
    mk_file_with_ops_type(FileType::Regular, flags, size, ops)
}

fn mk_file_with_ops_type(ft: FileType, flags: OpenFlags, size: u64, ops: Arc<IoctlOps>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), ops, default_file_ops()).size(size).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn mk_file_with_fop(ft: FileType, flags: OpenFlags, size: u64, fop: Arc<dyn FileOps>) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), default_inode_ops(), fop).size(size).build();
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

fn mk_file_with_sysfs_name(sysfs_name: Option<&str>) -> Arc<File> {
    let fs_ty = vfs::fs::FsType::new("sysfsnamefs", 0x1601, vfs::fs::FsFlags::empty(), Box::new(|_, _, _, _| Err(VfsError::Enotty)));
    let sb = SuperBlock::new(fs_ty, Arc::new(SimpleSuperOps {
        magic: 0x1601,
        block_size: 4096,
        options: alloc::string::String::new(),
    }), 0x1601, 0x1601, 4096, "not-the-sysfs-name".into(), Arc::new(()));
    if let Some(name) = sysfs_name { sb.set_sysfs_name(name); }
    let sb = Box::leak(Box::new(sb));
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

fn mk_block_file(name: &str, flags: OpenFlags, blocks: u64) -> (Arc<File>, Arc<block::blockdev::MemDisk<sync::Inode>>) {
    mk_block_file_with_block_size(name, flags, TEST_SECTOR_BYTES, blocks)
}

fn mk_block_file_with_block_size(name: &str, flags: OpenFlags, block_size: u32,
    blocks: u64) -> (Arc<File>, Arc<block::blockdev::MemDisk<sync::Inode>>) {
    let disk = block::blockdev::MemDisk::<sync::Inode>::new(block_size, blocks);
    let idx = block::registry::register(name, Arc::clone(&disk) as Arc<dyn block::blockdev::BlockDevice>);
    assert_ne!(idx, 0, "block registry should publish the test disk");
    let devt = Devt::from_raw(block::registry::dev_t_of(name, idx).unwrap());
    let ino = make_device_node_inode(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        FileType::BlockDev, devt, 0o660, alloc::sync::Weak::new());
    let dentry = Dentry::new_root(Arc::clone(&ino));
    (File::new(ino, dentry, flags), disk)
}

fn write_disk(disk: &dyn block::blockdev::BlockDevice, start: u64, blocks: u32, byte: u8) {
    let mut req = block::blockdev::BlockRequest::new_write(start, blocks, alloc::vec![byte; blocks as usize * 512]);
    disk.submit_sync(&mut req).expect("seed test disk");
}

fn read_disk(disk: &dyn block::blockdev::BlockDevice, start: u64, blocks: u32) -> alloc::vec::Vec<u8> {
    let mut req = block::blockdev::BlockRequest::new_read(start, blocks, 512);
    disk.submit_sync(&mut req).expect("read test disk");
    req.buffer
}

#[test]
fn block_discard_family_is_handled_before_enotty_fallback() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (file, disk) = mk_block_file("vdblkdiscard", OpenFlags::O_RDWR, 8);
    let mut range = [0u64, 512u64];
    write_disk(disk.as_ref(), 0, 2, 0xA5);

    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKDISCARD, range.as_mut_ptr() as u64), Some(0));
    let after_discard = read_disk(disk.as_ref(), 0, 2);
    assert!(after_discard[..512].iter().all(|&b| b == 0));
    assert!(after_discard[512..].iter().all(|&b| b == 0xA5));

    range = [512, 512];
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64), Some(0));
    let after_zeroout = read_disk(disk.as_ref(), 0, 2);
    assert!(after_zeroout.iter().all(|&b| b == 0));

    let mut zeroes: u32 = u32::MAX;
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKDISCARDZEROES, &mut zeroes as *mut u32 as u64), Some(0));
    assert_eq!(zeroes, 0);
    block::registry::unregister("vdblkdiscard");
    reset();
}

#[test]
fn block_discard_family_matches_linux_admission_order() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ro_file, _disk) = mk_block_file("vdblkrodiscard", OpenFlags::O_RDONLY, 8);
    let mut range = [0u64, 512u64];

    assert_eq!(blk::handle_blk_ioctl(&ro_file, uapi::BLKDISCARD, range.as_mut_ptr() as u64),
        Some(-(Errno::Ebadf.as_i32() as i64)));
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1,
        "BLKDISCARD copies the range before the write-open gate");

    userbuf::reset();
    assert_eq!(blk::handle_blk_ioctl(&ro_file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64),
        Some(-(Errno::Ebadf.as_i32() as i64)));
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 0,
        "BLKZEROOUT checks write-open before copying the range");

    userbuf::reset();
    let (rw_file, _disk2) = mk_block_file("vdblksecure", OpenFlags::O_RDWR, 8);
    assert_eq!(blk::handle_blk_ioctl(&rw_file, uapi::BLKSECDISCARD, range.as_mut_ptr() as u64),
        Some(-(Errno::Eopnotsupp.as_i32() as i64)));
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 0,
        "unsupported BLKSECDISCARD reports capability absence before usercopy");
    block::registry::unregister("vdblkrodiscard");
    block::registry::unregister("vdblksecure");
    reset();
}

#[test]
fn block_zeroout_uses_logical_block_alignment_not_only_abi_sector_alignment() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (file, _disk) = mk_block_file_with_block_size("vdblkzero4k", OpenFlags::O_RDWR,
        TEST_FOUR_KIB_BLOCK_BYTES, TEST_FOUR_KIB_BLOCK_COUNT);
    let mut range = [MISALIGNED_ZEROOUT_BYTES, LOGICAL_BLOCK_ZEROOUT_BYTES];
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    range = [0, LOGICAL_BLOCK_ZEROOUT_BYTES];
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKZEROOUT, range.as_mut_ptr() as u64), Some(0));
    block::registry::unregister("vdblkzero4k");
    reset();
}

#[test]
fn block_geometry_ioctls_still_report_registered_disk_shape() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (file, _disk) = mk_block_file("vdblkgeometry", OpenFlags::O_RDONLY, 8);
    let mut bytes: u64 = 0;
    let mut sectors: u64 = 0;
    let mut logical: u32 = 0;
    let mut soft: u32 = 0;
    let mut readonly: u32 = u32::MAX;

    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKGETSIZE64, &mut bytes as *mut u64 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKGETSIZE, &mut sectors as *mut u64 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKSSZGET, &mut logical as *mut u32 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKBSZGET, &mut soft as *mut u32 as u64), Some(0));
    assert_eq!(blk::handle_blk_ioctl(&file, uapi::BLKROGET, &mut readonly as *mut u32 as u64), Some(0));

    assert_eq!(bytes, 4096);
    assert_eq!(sectors, 8);
    assert_eq!(logical, 512);
    assert_eq!(soft, 512);
    assert_eq!(readonly, 0);
    block::registry::unregister("vdblkgeometry");
    reset();
}

#[test]
fn fioclex_and_fionclex_update_fdtable_close_on_exec() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
fn regular_fionread_reports_negative_size_minus_position_past_eof() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 12);
    file.set_pos(20);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out: i32 = 99;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, &mut out as *mut i32 as u64), Some(0));
    assert_eq!(out, -8);
    reset();
}

#[test]
fn socket_fionread_rejects_null_out_pointer_instead_of_succeeding() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file_with_fop(FileType::Socket, OpenFlags::O_RDWR, 0, RemapOps::new(Ok(0)))).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    let file = file_for(&fdt, fd);
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, 0), None);
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::FIONREAD, 0), Some(-(Errno::Efault.as_i32() as i64)));
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn fibmap_requires_rawio_and_writes_bmap_result() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(IoctlOps::default());
    *ops.attr.lock().unwrap() = FileAttr { flags: 0x10 | 0x80 | uapi::FS_CASEFOLD_FL, fsx_extsize: 64, fsx_nextents: 3, fsx_cowextsize: 128, ..Default::default() };
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDWR, 0, Arc::clone(&ops));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut xattr = [0u8; 28];
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSGETXATTR, xattr.as_mut_ptr() as u64), Some(0));
    assert_eq!(u32::from_ne_bytes(xattr[0..4].try_into().unwrap()), 0x08 | 0x40 | uapi::FS_XFLAG_CASEFOLD);
    assert_eq!(u32::from_ne_bytes(xattr[4..8].try_into().unwrap()), 64);
    assert_eq!(u32::from_ne_bytes(xattr[8..12].try_into().unwrap()), 3);
    assert_eq!(u32::from_ne_bytes(xattr[16..20].try_into().unwrap()), 128);
    xattr[0..4].copy_from_slice(&(0x10u32 | 0x80u32 | uapi::FS_XFLAG_EXTSIZE | uapi::FS_XFLAG_COWEXTSIZE).to_ne_bytes());
    xattr[4..8].copy_from_slice(&256u32.to_ne_bytes());
    xattr[8..12].copy_from_slice(&7u32.to_ne_bytes());
    xattr[12..16].copy_from_slice(&42u32.to_ne_bytes());
    xattr[16..20].copy_from_slice(&512u32.to_ne_bytes());
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64), Some(0));
    assert_eq!(*ops.attr.lock().unwrap(), FileAttr {
        flags: 0x20 | 0x40 | uapi::FS_CASEFOLD_FL,
        fsx_xflags: 0x10 | 0x80 | uapi::FS_XFLAG_EXTSIZE | uapi::FS_XFLAG_COWEXTSIZE,
        fsx_extsize: 256,
        fsx_nextents: 7,
        fsx_projid: 42,
        fsx_cowextsize: 512,
    });
    reset();
}

#[test]
fn fsxattr_set_rejects_extsize_hint_on_non_regular_file() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(IoctlOps::default());
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops_type(FileType::Directory, OpenFlags::O_RDWR, 0, Arc::clone(&ops));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut xattr = [0u8; 28];
    xattr[0..4].copy_from_slice(&uapi::FS_XFLAG_EXTSIZE.to_ne_bytes());
    xattr[4..8].copy_from_slice(&64u32.to_ne_bytes());
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64), Some(-(Errno::Einval.as_i32() as i64)));
    assert_eq!(*ops.attr.lock().unwrap(), FileAttr::default());
    reset();
}

#[test]
fn unsupported_fileattr_ioctls_return_enotty() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDWR, 0);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut flags = 0u32;
    let mut xattr = [0u8; 28];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_GETFLAGS, &mut flags as *mut u32 as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_SETFLAGS, &flags as *const u32 as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSGETXATTR, xattr.as_mut_ptr() as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    reset();
}

#[test]
fn getfsuuid_copies_superblock_uuid_or_enotty_without_one() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

#[test]
fn getfssysfspath_uses_superblock_sysfs_name_or_enotty() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let empty = mk_file_with_sysfs_name(None);
    let empty_fd = fdt.alloc(Arc::clone(&empty)).unwrap();
    let file = mk_file_with_sysfs_name(Some("vda1"));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out = [0xAAu8; 129];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &empty, &fdt, empty_fd, uapi::FS_IOC_GETFSSYSFSPATH, out.as_mut_ptr() as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_GETFSSYSFSPATH, out.as_mut_ptr() as u64), Some(0));
    assert_eq!(out[0], b"sysfsnamefs/vda1".len() as u8);
    assert_eq!(&out[1..17], b"sysfsnamefs/vda1");
    assert_eq!(out[17], 0);
    assert!(out[18..].iter().all(|b| *b == 0));
    reset();
}

#[test]
fn ficlone_bad_source_fd_precedes_destination_mode_checks() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 0);
    let fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, fd, uapi::FICLONE, 99),
        Some(-(Errno::Ebadf.as_i32() as i64)));
    reset();
}

#[test]
fn ficlone_zero_length_expands_to_source_eof_like_linux() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(20));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDWR, 0, remap.clone());
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONE, src_fd as u64), Some(0));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(0, 0, 20, 0)]);
    reset();
}

#[test]
fn ficlonerange_rejects_unshortenable_range_past_source_eof_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(1));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDWR, 0, remap.clone());
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 12, src_length: 16, dest_offset: 0 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn ficlone_uses_linux_vfs_admission_and_reports_missing_remap_op() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let src = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 20);
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDWR, 0);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONE, src_fd as u64),
        Some(-(Errno::Eopnotsupp.as_i32() as i64)));
    reset();
}

#[test]
fn ficlonerange_copies_struct_and_rejects_short_backend_clone() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(9));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDWR, 0);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 3, src_length: 10, dest_offset: 5 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(3, 5, 10, 0)]);
    reset();
}

#[test]
fn fideduperange_writes_per_destination_linux_statuses() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(4));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst_ok = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDWR, 20, remap.clone());
    let dst_no_remap = mk_file(FileType::Regular, OpenFlags::O_RDWR, 20);
    let dst_ok_fd = fdt.alloc(dst_ok).unwrap();
    let dst_no_remap_fd = fdt.alloc(dst_no_remap).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut range = FileDedupeRangeOne {
        src_offset: 2,
        src_length: 4,
        dest_count: 2,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_ok_fd as i64, dest_offset: 6, bytes_deduped: 99, status: -99, reserved: 0 },
            FileDedupeRangeInfo { dest_fd: dst_no_remap_fd as i64, dest_offset: 8, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &src, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 4);
    assert_eq!(range.info[0].status, 0);
    assert_eq!(range.info[1].bytes_deduped, 0);
    assert_eq!(range.info[1].status, -(Errno::Einval.as_i32()));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(2, 6, 4, 3)]);
    reset();
}

fn file_for(fdt: &FdTable, fd: i32) -> Arc<File> {
    fdt.get(fd).expect("fd installed")
}
