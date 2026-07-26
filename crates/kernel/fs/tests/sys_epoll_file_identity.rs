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

    pub fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
        validate_user_buf_readable(ptr, len, align)
    }
    pub fn validate_user_buf_readable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
    pub fn validate_user_buf_writable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
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
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store leaked Task pointers and clear the hook before returning.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x8100, "epoll-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_poll_file(mask: Arc<AtomicU32>) -> Arc<File> {
    mk_poll_file_with_source(mask, Arc::new(vfs::PollSubscribers::new()))
}

fn mk_poll_file_with_source(mask: Arc<AtomicU32>, source: Arc<vfs::PollSubscribers>) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(PollOps(mask))).poll_subs_arc(source).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn epoll_event(events: u32, data: u64) -> [u8; 12] {
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&events.to_ne_bytes());
    ev[4..12].copy_from_slice(&data.to_ne_bytes());
    ev
}

fn read_epoll_event(ev: &[u8; 12]) -> (u32, u64) {
    let mut e = [0u8; 4];
    let mut d = [0u8; 8];
    e.copy_from_slice(&ev[..4]);
    d.copy_from_slice(&ev[4..12]);
    (u32::from_ne_bytes(e), u64::from_ne_bytes(d))
}

fn args(a0: u64, a1: u64, a2: u64, a3: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2, a3, a4: 0, a5: 0 }
}

#[test]
fn duplicate_fd_preserves_epoll_interest_after_fd_reuse() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));

    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    assert_eq!(epfd, 0);

    let old_mask = Arc::new(AtomicU32::new(0));
    let old_fd = fdt.alloc(mk_poll_file(Arc::clone(&old_mask))).unwrap();
    assert_eq!(old_fd, 1);
    let old_dup = fdt.dup(old_fd).unwrap();
    assert_eq!(old_dup, 2);

    let mut add = epoll_event(vfs::POLL_IN, 0x1002_68d0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 1, old_fd as u64, add.as_mut_ptr() as u64)), 0);

    assert_eq!(fdt.close(old_fd), Ok(()));
    let reused_mask = Arc::new(AtomicU32::new(0));
    let reused_fd = fdt.alloc(mk_poll_file(reused_mask)).unwrap();
    assert_eq!(reused_fd, old_fd);
    let mut add_reused = epoll_event(vfs::POLL_IN, 0x2002_68d0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 1, reused_fd as u64, add_reused.as_mut_ptr() as u64)), 0,
        "same fd number with a different open file description is a distinct epoll key");
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 2, reused_fd as u64, 0)), 0,
        "DEL removes the current fd/file key without deleting the old dup-kept interest");

    old_mask.store(vfs::POLL_IN, Ordering::Release);
    let mut out = [0u8; 12];
    let n = fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0));
    assert_eq!(n, 1, "epoll entry must poll the original file, not the reused fd slot");
    assert_eq!(read_epoll_event(&out), (vfs::POLL_IN, 0x1002_68d0));
    reset();
}

#[test]
fn epoll_rejects_direct_self_add() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(fdt);

    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut add = epoll_event(vfs::POLL_IN, 1);
    assert_eq!(
        fs::epoll::sys_epoll_ctl(&args(epfd as u64, 1, epfd as u64, add.as_mut_ptr() as u64)),
        -(Errno::Einval.as_i32() as i64));
    reset();
}

#[test]
fn unrelated_global_wake_does_not_retrigger_epollet_ready_file() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));

    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(vfs::POLL_IN));
    let fd = fdt.alloc(mk_poll_file(ready)).unwrap();
    let mut add = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0001);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64,
        add.as_mut_ptr() as u64)), 0);

    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(read_epoll_event(&out), (vfs::POLL_IN, 0x8100_0001));
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);

    fs::epoll::GLOBAL_EPOLL_GEN.fetch_add(1, Ordering::AcqRel);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0,
        "a keyless wake is not a not-ready-to-ready transition for this epitem");

    let file = fdt.get(fd).unwrap();
    file.poll_subscribers().unwrap().notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1,
        "the watched file's own transition callback queues a fresh ET event");
    reset();
}

#[test]
fn inbound_source_event_does_not_retrigger_epollet_pollout() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));

    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(vfs::POLL_OUT));
    let source = Arc::new(vfs::PollSubscribers::new());
    let fd = fdt.alloc(mk_poll_file_with_source(ready, Arc::clone(&source))).unwrap();
    let mut add = epoll_event(vfs::POLL_OUT | EPOLLET, 0x8100_0003);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64,
        add.as_mut_ptr() as u64)), 0);

    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    source.notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0,
        "an inbound-data notification is not a new writable edge");
    reset();
}

#[test]
fn signalfd_registers_current_tasks_pending_source() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let creator = install_current_with_fdt(Arc::clone(&fdt));
    let sig = sched::signum::Signum::Sigusr1;

    let sig_inode = fs::signalfd::make_signalfd_inode(sig.bit());
    let sig_dentry = Dentry::new_root(Arc::clone(&sig_inode));
    let sigfd = fdt.alloc(File::new(sig_inode, sig_dentry, OpenFlags::O_NONBLOCK)).unwrap();
    let consumer = install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut sig_add = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0002);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, sigfd as u64,
        sig_add.as_mut_ptr() as u64)), 0);

    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0,
        "signalfd starts empty");
    creator.sigpending.fetch_or(sig.bit(), Ordering::Release);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0,
        "the creator's pending source must not drive an inherited signalfd registration");
    consumer.sigpending.fetch_or(sig.bit(), Ordering::Release);
    assert_ne!(consumer.sigpending.load(Ordering::Acquire) & sig.bit(), 0);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1,
        "SignalPending transition must queue the signalfd epitem");
    assert_eq!(read_epoll_event(&out), (vfs::POLL_IN, 0x8100_0002));
    reset();
}

#[test]
fn shared_source_keeps_one_subscription_per_epitem() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));

    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(0));
    let source = Arc::new(vfs::PollSubscribers::new());
    let fd1 = fdt.alloc(mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source))).unwrap();
    let fd2 = fdt.alloc(mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source))).unwrap();
    let mut add1 = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0011);
    let mut add2 = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0012);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd1 as u64, add1.as_mut_ptr() as u64)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd2 as u64, add2.as_mut_ptr() as u64)), 0);

    ready.store(vfs::POLL_IN, Ordering::Release);
    source.notify_mask(vfs::POLL_IN);
    let mut out = [0u8; 24];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 2, 0)), 2,
        "one shared source callback must queue both epitems");

    ready.store(0, Ordering::Release);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 2, fd1 as u64, 0)), 0);
    ready.store(vfs::POLL_IN, Ordering::Release);
    source.notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 2, 0)), 1,
        "DEL of one epitem must leave the other's subscription installed");
    assert_eq!(read_epoll_event((&out[..12]).try_into().unwrap()), (vfs::POLL_IN, 0x8100_0012));
    reset();
}

#[test]
fn epoll_oneshot_disarms_until_mod() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(vfs::POLL_IN));
    let fd = fdt.alloc(mk_poll_file(ready)).unwrap();
    let mut event = epoll_event(vfs::POLL_IN | EPOLLONESHOT, 0x8100_0020);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64,
        event.as_mut_ptr() as u64)), 0);
    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_MOD, fd as u64,
        event.as_mut_ptr() as u64)), 0);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    reset();
}

#[test]
fn epoll_rejects_nested_cycle() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(fdt);
    let a = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let b = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut event = epoll_event(vfs::POLL_IN, 0x8100_0030);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(a as u64, EPOLL_CTL_ADD, b as u64,
        event.as_mut_ptr() as u64)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(b as u64, EPOLL_CTL_ADD, a as u64,
        event.as_mut_ptr() as u64)), -(Errno::Eloop.as_i32() as i64));
    reset();
}

#[test]
fn final_file_reference_drop_unlinks_epoll_interest() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(0));
    let source = Arc::new(vfs::PollSubscribers::new());
    let fd = fdt.alloc(mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source))).unwrap();
    let mut event = epoll_event(vfs::POLL_IN, 0x8100_0040);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64,
        event.as_mut_ptr() as u64)), 0);
    assert_eq!(fdt.close(fd), Ok(()));
    ready.store(vfs::POLL_IN, Ordering::Release);
    source.notify_mask(vfs::POLL_IN);
    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    reset();
}

#[test]
fn non_fd_file_reference_delays_epoll_unlink() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(0));
    let source = Arc::new(vfs::PollSubscribers::new());
    let file = mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source));
    let held = Arc::clone(&file);
    let fd = fdt.alloc(file).unwrap();
    let mut event = epoll_event(vfs::POLL_IN, 0x8100_0050);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64,
        event.as_mut_ptr() as u64)), 0);
    assert_eq!(fdt.close(fd), Ok(()));
    ready.store(vfs::POLL_IN, Ordering::Release);
    source.notify_mask(vfs::POLL_IN);
    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1,
        "an in-flight file reference delays final fput and eventpoll teardown");
    drop(held);
    source.notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    reset();
}

#[test]
fn epoll_ctl_add_duplicate_fd_is_eexist() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap();
    let mut add = epoll_event(vfs::POLL_IN, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)),
        -(Errno::Eexist.as_i32() as i64), "re-adding the same fd/file key must be EEXIST");
    reset();
}

#[test]
fn epoll_ctl_mod_and_del_of_unregistered_fd_is_enoent() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap();
    let mut ev = epoll_event(vfs::POLL_IN, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_MOD, fd as u64, ev.as_mut_ptr() as u64)),
        -(Errno::Enoent.as_i32() as i64), "MOD of an fd never ADDed must be ENOENT");
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, fd as u64, 0)),
        -(Errno::Enoent.as_i32() as i64), "DEL of an fd never ADDed must be ENOENT");
    reset();
}

#[test]
fn epoll_hup_is_reported_even_when_not_requested() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    // Only EPOLLOUT requested; the file reports HUP (peer gone) with no OUT bit.
    let ready = Arc::new(AtomicU32::new(EPOLLHUP));
    let fd = fdt.alloc(mk_poll_file(ready)).unwrap();
    let mut add = epoll_event(vfs::POLL_OUT, 0x8100_0060);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64,
        add.as_mut_ptr() as u64)), 0);
    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1,
        "EPOLLHUP must be reported even though only EPOLLOUT was requested");
    let (revents, _) = read_epoll_event(&out);
    assert_eq!(revents, EPOLLHUP, "unrequested HUP is OR'd into revents, no OUT bit present");
    reset();
}

#[test]
fn epoll_exclusive_rejects_mod() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap();
    let mut add = epoll_event(vfs::POLL_IN | EPOLLEXCLUSIVE, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0);
    let mut modev = epoll_event(vfs::POLL_IN | EPOLLEXCLUSIVE, 2);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_MOD, fd as u64, modev.as_mut_ptr() as u64)),
        -(Errno::Einval.as_i32() as i64), "EPOLLEXCLUSIVE is always EINVAL on EPOLL_CTL_MOD");
    reset();
}

#[test]
fn epoll_exclusive_rejects_nested_epoll_target() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(fdt);
    let outer = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let inner = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut add = epoll_event(vfs::POLL_IN | EPOLLEXCLUSIVE, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(outer as u64, EPOLL_CTL_ADD, inner as u64, add.as_mut_ptr() as u64)),
        -(Errno::Einval.as_i32() as i64), "EPOLLEXCLUSIVE on a nested epoll fd is always EINVAL");
    reset();
}

#[test]
fn epoll_exclusive_rejects_bits_outside_ok_mask() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap();
    // EPOLLPRI is NOT in Linux's EPOLLEXCLUSIVE_OK_BITS (IN|OUT|ERR|HUP|WAKEUP|ET|EXCLUSIVE).
    let mut add = epoll_event(vfs::POLL_IN | EPOLLPRI | EPOLLEXCLUSIVE, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)),
        -(Errno::Einval.as_i32() as i64), "EPOLLPRI combined with EPOLLEXCLUSIVE must be EINVAL");
    // EPOLLWAKEUP and EPOLLET are allowed alongside EPOLLEXCLUSIVE.
    let mut ok = epoll_event(vfs::POLL_IN | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE, 2);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, ok.as_mut_ptr() as u64)), 0,
        "EPOLLWAKEUP|EPOLLET are within EPOLLEXCLUSIVE_OK_BITS");
    reset();
}

#[test]
fn epoll_wait_maxevents_out_of_range_is_einval() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(fdt);
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 0, 0)),
        -(Errno::Einval.as_i32() as i64), "maxevents == 0 is EINVAL");
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, u32::MAX as u64, 0)),
        -(Errno::Einval.as_i32() as i64), "maxevents beyond EP_MAX_EVENTS is EINVAL");
    reset();
}

#[test]
fn epoll_ctl_bad_event_pointer_takes_precedence_over_bad_fds() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(fdt);
    // epfd (9999) and fd (9998) are both invalid, AND the event pointer is
    // NULL: Linux copies the user `epoll_event` in before resolving either
    // fd, so EFAULT wins over EBADF here.
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(9999, EPOLL_CTL_ADD, 9998, 0)),
        -(Errno::Efault.as_i32() as i64), "a bad event pointer is EFAULT even with bad epfd/fd");
    reset();
}
