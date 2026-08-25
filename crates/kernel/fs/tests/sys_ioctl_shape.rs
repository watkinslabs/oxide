// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
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

#[path = "../../syscalls/src/ioctl_uapi.rs"]
mod ioctl_uapi;
use ioctl_uapi as uapi;
#[path = "../../syscalls/src/ioctl_user/mod.rs"]
mod ioctl_user;
#[path = "../../syscalls/src/ioctl_owner.rs"]
mod ioctl_owner_mod;
use ioctl_owner_mod::{ioctl_file, ioctl_owner, IoctlOwner};

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
    fallocate_calls: Mutex<Vec<(u32, u64, u64)>>,
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

    fn fallocate(&self, _inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
        self.fallocate_calls.lock().unwrap().push((mode, off, len));
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
    let fs_ty = vfs::fs::FsType::new("uuidfs", 0x1600, vfs::fs::FsFlags::empty(), Box::new(|_, _, _, _, _, _| Err(VfsError::Enotty)));
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
    let fs_ty = vfs::fs::FsType::new("sysfsnamefs", 0x1601, vfs::fs::FsFlags::empty(), Box::new(|_, _, _, _, _, _| Err(VfsError::Enotty)));
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

#[path = "sys_ioctl_shape/tests/block.rs"]
mod block_tests;
#[path = "sys_ioctl_shape/tests/common.rs"]
mod common_tests;
#[path = "sys_ioctl_shape/tests/fileattr.rs"]
mod fileattr_tests;
#[path = "sys_ioctl_shape/tests/remap.rs"]
mod remap_tests;

fn file_for(fdt: &FdTable, fd: i32) -> Arc<File> {
    fdt.get(fd).expect("fd installed")
}
