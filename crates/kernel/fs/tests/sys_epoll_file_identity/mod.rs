#![allow(dead_code)]
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, KResult, OpenFlags, default_inode_ops, mk_mode};

mod userbuf {
    use syscall::errno::Errno;
    pub fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> { validate_user_buf_readable(ptr, len, align) }
    pub fn validate_user_buf_readable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> { if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) } }
    pub fn validate_user_buf_writable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> { if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) } }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x8100);
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLET: u32 = 1 << 31;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLWAKEUP: u32 = 1 << 29;
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLPRI: u32 = 0x2;
const EPOLLHUP: u32 = 0x10;

struct PollOps(Arc<AtomicU32>);
impl FileOps for PollOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
    fn poll(&self, _inode: &Inode) -> u32 { self.0.load(Ordering::Acquire) }
}
fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}
fn reset() { CURRENT.store(ptr::null_mut(), Ordering::Release); sched::set_current_hook(hooked_current); }
fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x8100, "epoll-test", SchedClass::Normal { weight: 1024 })));
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}
fn mk_poll_file(mask: Arc<AtomicU32>) -> Arc<File> { mk_poll_file_with_source(mask, Arc::new(vfs::PollSubscribers::new())) }
fn mk_poll_file_with_source(mask: Arc<AtomicU32>, source: Arc<vfs::PollSubscribers>) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(PollOps(mask))).poll_subs_arc(source).build();
    File::new(inode.clone(), Dentry::new_root(inode), OpenFlags::O_RDWR)
}
fn epoll_event(events: u32, data: u64) -> [u8; 12] {
    let mut ev = [0u8; 12]; ev[..4].copy_from_slice(&events.to_ne_bytes()); ev[4..12].copy_from_slice(&data.to_ne_bytes()); ev
}
fn read_epoll_event(ev: &[u8; 12]) -> (u32, u64) {
    let mut e = [0u8; 4]; let mut d = [0u8; 8]; e.copy_from_slice(&ev[..4]); d.copy_from_slice(&ev[4..12]); (u32::from_ne_bytes(e), u64::from_ne_bytes(d))
}
fn args(a0: u64, a1: u64, a2: u64, a3: u64) -> SyscallArgs { SyscallArgs { a0, a1, a2, a3, a4: 0, a5: 0 } }

#[path = "tests/identity.rs"] mod identity;
#[path = "tests/lifecycle.rs"] mod lifecycle;
#[path = "tests/validation.rs"] mod validation;
