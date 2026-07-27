extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FileType, InodeBuilder, LookupFlags, VfsPath, default_file_ops, default_inode_ops, mk_mode};

mod namei_common {
    pub fn fsid_to_dev(fsid: u64) -> u64 { vfs::fsid_to_dev(fsid) }
}

mod pathresolve {
    use super::*;

    pub const AT_FDCWD: i32 = -100;

    static NEXT: Mutex<Option<Result<VfsPath, i64>>> = Mutex::new(None);
    pub static CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static LAST_DIRFD: AtomicI32 = AtomicI32::new(0);
    pub static LAST_PATH_PTR: AtomicU64 = AtomicU64::new(0);
    pub static LAST_NO_FOLLOW_FINAL: AtomicBool = AtomicBool::new(false);
    pub static LAST_FOLLOW: AtomicBool = AtomicBool::new(false);

    pub fn reset() {
        *NEXT.lock().unwrap() = None;
        CALLS.store(0, Ordering::SeqCst);
        LAST_DIRFD.store(0, Ordering::SeqCst);
        LAST_PATH_PTR.store(0, Ordering::SeqCst);
        LAST_NO_FOLLOW_FINAL.store(false, Ordering::SeqCst);
        LAST_FOLLOW.store(false, Ordering::SeqCst);
    }

    pub fn set_result(r: Result<VfsPath, i64>) {
        *NEXT.lock().unwrap() = Some(r);
    }

    pub fn resolve_at_lookup(dirfd: i32, path_ptr: u64, flags: LookupFlags) -> Result<VfsPath, i64> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_DIRFD.store(dirfd, Ordering::SeqCst);
        LAST_PATH_PTR.store(path_ptr, Ordering::SeqCst);
        LAST_NO_FOLLOW_FINAL.store(flags.no_follow_final, Ordering::SeqCst);
        LAST_FOLLOW.store(flags.follow, Ordering::SeqCst);
        NEXT.lock().unwrap().take().expect("test resolver result")
    }
}

mod userbuf {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static VALIDATE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static VALIDATE_LEN: AtomicU64 = AtomicU64::new(0);

    pub fn reset() {
        VALIDATE_CALLS.store(0, Ordering::SeqCst);
        VALIDATE_LEN.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        VALIDATE_CALLS.fetch_add(1, Ordering::SeqCst);
        VALIDATE_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

#[path = "../../syscalls/src/stat_common.rs"]
mod stat_common;

#[path = "../../syscalls/src/004_stat.rs"]
mod s004_stat;

#[path = "../../syscalls/src/006_lstat.rs"]
mod lstat_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x6000);

const TEST_PATH_PTR: u64 = 0x4444_0000;
const TEST_UID: u32 = 2000;
const TEST_GID: u32 = 2001;
const TEST_FSID: u64 = 0x0606;
const TEST_SIZE: u64 = 0x42;
const TEST_BLOCKS: u64 = 3;

fn args(path: u64, buf: u64) -> SyscallArgs {
    SyscallArgs { a0: path, a1: buf, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn reset() {
    pathresolve::reset();
    userbuf::reset();
}

fn mk_path(kind: FileType, mode: u16, size: u64) -> VfsPath {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(kind, mode), default_inode_ops(), default_file_ops())
        .owner(TEST_UID, TEST_GID)
        .fsid(TEST_FSID)
        .size(size)
        .blocks(TEST_BLOCKS)
        .build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    VfsPath { mnt_id: 0, dentry, inode, last_component: None }
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
}

fn u64_at(buf: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

fn i64_at(buf: &[u8], off: usize) -> i64 {
    i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

fn assert_lstat_lookup(path_ptr: u64) {
    assert_eq!(pathresolve::CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(pathresolve::LAST_DIRFD.load(Ordering::SeqCst), pathresolve::AT_FDCWD);
    assert_eq!(pathresolve::LAST_PATH_PTR.load(Ordering::SeqCst), path_ptr);
    assert!(pathresolve::LAST_NO_FOLLOW_FINAL.load(Ordering::SeqCst));
    assert!(!pathresolve::LAST_FOLLOW.load(Ordering::SeqCst));
}

#[test]
fn sys_lstat_path_resolution_error_precedes_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    pathresolve::set_result(Err(-(Errno::Enoent.as_i32() as i64)));

    assert_eq!(lstat_syscall::sys_lstat(&args(TEST_PATH_PTR, 0)), -(Errno::Enoent.as_i32() as i64));
    assert_lstat_lookup(TEST_PATH_PTR);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_lstat_conversion_precedes_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    pathresolve::set_result(Ok(mk_path(FileType::Regular, 0o644, i64::MAX as u64 + 1)));

    assert_eq!(lstat_syscall::sys_lstat(&args(TEST_PATH_PTR, 0)), -(Errno::Eoverflow.as_i32() as i64));
    assert_lstat_lookup(TEST_PATH_PTR);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_lstat_valid_path_faults_only_at_copyout_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    pathresolve::set_result(Ok(mk_path(FileType::Regular, 0o644, TEST_SIZE)));

    assert_eq!(lstat_syscall::sys_lstat(&args(TEST_PATH_PTR, 0)), -(Errno::Efault.as_i32() as i64));
    assert_lstat_lookup(TEST_PATH_PTR);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_LEN.load(Ordering::SeqCst), stat_common::STAT_BYTES);
    reset();
}

#[test]
fn sys_lstat_writes_final_symlink_metadata_without_following() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ino = NEXT_INO.load(Ordering::Relaxed);
    pathresolve::set_result(Ok(mk_path(FileType::Symlink, 0o777, TEST_SIZE)));
    let mut buf = [0u8; stat_common::STAT_BYTES_X86_64 as usize];

    assert_eq!(lstat_syscall::sys_lstat(&args(TEST_PATH_PTR, buf.as_mut_ptr() as u64)), 0);
    assert_lstat_lookup(TEST_PATH_PTR);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_LEN.load(Ordering::SeqCst), stat_common::STAT_BYTES);
    assert_eq!(u64_at(&buf, 0), vfs::fsid_to_dev(TEST_FSID));
    assert_eq!(u64_at(&buf, 8), ino);
    assert_eq!(u32_at(&buf, 24), mk_mode(FileType::Symlink, 0o777));
    assert_eq!(u32_at(&buf, 28), TEST_UID);
    assert_eq!(u32_at(&buf, 32), TEST_GID);
    assert_eq!(i64_at(&buf, 48), TEST_SIZE as i64);
    assert_eq!(i64_at(&buf, 64), TEST_BLOCKS as i64);
    reset();
}
