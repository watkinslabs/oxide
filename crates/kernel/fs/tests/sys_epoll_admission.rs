// Verified `epoll_ctl(2)` admission against the live interest list: the EPERM
// a target with no readiness operation gets, the unconditional EINVAL the
// epoll file gets on itself, the per-user watch ceiling and its release, the
// stored-mask contract, and the `/proc/<pid>/fdinfo` interest dump.
#![allow(dead_code)]
extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, KResult, OpenFlags,
          default_inode_ops, mk_mode};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x9100);

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLIN: u32 = vfs::POLL_IN;
const EPOLLERR: u32 = vfs::POLL_ERR;
const EPOLLHUP: u32 = vfs::POLL_HUP;

/// A backend with a readiness operation: it names a wait source.
struct PollOps(Arc<AtomicU32>);
impl FileOps for PollOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> { Ok(b.len()) }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
    fn poll(&self, _i: &Inode) -> u32 { self.0.load(Ordering::Acquire) }
}

/// A backend with NO readiness operation — the shape of a regular file or a
/// directory, which is what `epoll_ctl` answers EPERM for.
struct PlainOps;
impl FileOps for PlainOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> { Ok(b.len()) }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store leaked Task pointers and clear the hook before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    vfs::epoll_limits::set_max_user_watches(vfs::epoll_limits::EPOLL_DEFAULT_MAX_USER_WATCHES);
}

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    install_current_as(fdt, 0)
}

/// Distinct uid per test: the watch counter is process-global and the hosted
/// harness runs the tests in one process.
fn install_current_as(fdt: Arc<FdTable>, uid: u32) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x9100, "epoll-adm", SchedClass::Normal { weight: 1024 })));
    task.creds.ruid.store(uid, Ordering::Release);
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_pollable() -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(PollOps(Arc::new(AtomicU32::new(0)))))
        .poll_subs_arc(Arc::new(vfs::PollSubscribers::new())).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn mk_unpollable() -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(PlainOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn epoll_event(events: u32, data: u64) -> [u8; 12] {
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&events.to_ne_bytes());
    ev[4..12].copy_from_slice(&data.to_ne_bytes());
    ev
}

fn args(a0: u64, a1: u64, a2: u64, a3: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2, a3, a4: 0, a5: 0 }
}

fn fdinfo_of(fdt: &FdTable, fd: i64) -> String {
    let file = fdt.get(fd as i32).unwrap();
    let mut out: Vec<u8> = Vec::new();
    file.inode().fdinfo_extra(&mut out);
    String::from_utf8(out.to_vec()).unwrap()
}

#[test]
fn adding_a_target_with_no_readiness_operation_is_eperm() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let fd = fdt.alloc(mk_unpollable()).unwrap();
    let mut ev = epoll_event(EPOLLIN, 7);
    for op in [EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL] {
        assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, op, fd as u64, ev.as_mut_ptr() as u64)),
                   -(Errno::Eperm.as_i32() as i64),
                   "op {op}: a regular file has no ->poll, so epoll_ctl is EPERM");
    }
    // A pollable target on the same epoll is admitted, proving the EPERM is
    // about the target and not about the epoll instance.
    let ok_fd = fdt.alloc(mk_pollable()).unwrap();
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, ok_fd as u64, ev.as_mut_ptr() as u64)), 0);
    reset();
}

#[test]
fn deleting_the_epoll_file_from_itself_is_einval_not_enoent() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, epfd as u64, 0)),
               -(Errno::Einval.as_i32() as i64),
               "the self-check is unconditional; DEL must not fall through to the ENOENT lookup");
    // An unwatched ORDINARY fd still gets ENOENT, so the EINVAL above is
    // specific to the self case.
    let fd = fdt.alloc(mk_pollable()).unwrap();
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, fd as u64, 0)),
               -(Errno::Enoent.as_i32() as i64));
    reset();
}

#[test]
fn the_per_user_watch_ceiling_reports_enospc_and_is_released_by_del() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_as(Arc::clone(&fdt), 92_001);
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let a = fdt.alloc(mk_pollable()).unwrap();
    let b = fdt.alloc(mk_pollable()).unwrap();
    let mut ev = epoll_event(EPOLLIN, 1);
    vfs::epoll_limits::set_max_user_watches(1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, a as u64, ev.as_mut_ptr() as u64)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, b as u64, ev.as_mut_ptr() as u64)),
               -(Errno::Enospc.as_i32() as i64), "past fs.epoll.max_user_watches");
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, a as u64, 0)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, b as u64, ev.as_mut_ptr() as u64)), 0,
               "removing an interest returns exactly one slot");
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, b as u64, 0)), 0);
    reset();
}

#[test]
fn closing_the_epoll_file_returns_every_watch_charge() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_as(Arc::clone(&fdt), 92_002);
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let a = fdt.alloc(mk_pollable()).unwrap();
    let mut ev = epoll_event(EPOLLIN, 1);
    vfs::epoll_limits::set_max_user_watches(1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, a as u64, ev.as_mut_ptr() as u64)), 0);
    fdt.close(epfd as i32).unwrap();
    let ep2 = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(ep2 as u64, EPOLL_CTL_ADD, a as u64, ev.as_mut_ptr() as u64)), 0,
               "the closed instance's interests must not leak their charges");
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(ep2 as u64, EPOLL_CTL_DEL, a as u64, 0)), 0);
    reset();
}

#[test]
fn a_stored_interest_always_carries_err_and_hup_and_shows_up_in_fdinfo() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let fd = fdt.alloc(mk_pollable()).unwrap();
    let mut ev = epoll_event(EPOLLIN, 0xDEAD_BEEF);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, ev.as_mut_ptr() as u64)), 0);
    let text = fdinfo_of(&fdt, epfd);
    let line = text.lines().next().expect("one interest, one fdinfo line");
    assert!(line.starts_with("tfd:"), "line shape: {line}");
    assert!(line.contains(&alloc::format!("tfd: {:8}", fd)), "names the watched fd: {line}");
    assert!(line.contains(&alloc::format!("events: {:8x}", EPOLLIN | EPOLLERR | EPOLLHUP)),
            "the stored mask carries ERR|HUP the caller never asked for: {line}");
    assert!(line.contains("data:         deadbeef"), "carries the caller's data word: {line}");
    // A DEL removes the line entirely.
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, fd as u64, 0)), 0);
    assert_eq!(fdinfo_of(&fdt, epfd), "", "a removed interest leaves no fdinfo line");
    reset();
}

#[test]
fn a_chain_longer_than_the_nesting_budget_is_eloop_from_either_end() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    // Six epoll instances; nest them one inside the next until the budget is
    // spent. e0 watches e1 watches e2 ... — Linux admits four links.
    let eps: Vec<i64> = (0..6).map(|_| fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0))).collect();
    let mut ev = epoll_event(EPOLLIN, 0);
    let mut linked = 0usize;
    for w in eps.windows(2) {
        let rv = fs::epoll::sys_epoll_ctl(&args(w[0] as u64, EPOLL_CTL_ADD, w[1] as u64, ev.as_mut_ptr() as u64));
        if rv == 0 { linked += 1; continue; }
        assert_eq!(rv, -(Errno::Eloop.as_i32() as i64), "an over-long chain is ELOOP");
        break;
    }
    assert_eq!(linked, 4, "exactly EP_MAX_NESTS links are admitted, then ELOOP");
    reset();
}

#[test]
fn nesting_is_rejected_when_the_destination_is_already_deeply_watched() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));
    // Build a 3-link chain ABOVE `dst`: top -> b -> c -> dst.
    let top = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let b   = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let c   = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let dst = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut ev = epoll_event(EPOLLIN, 0);
    for (outer, inner) in [(top, b), (b, c), (c, dst)] {
        assert_eq!(fs::epoll::sys_epoll_ctl(&args(outer as u64, EPOLL_CTL_ADD, inner as u64, ev.as_mut_ptr() as u64)), 0);
    }
    // Two more epolls below: a chain of depth 1 hanging off `leaf`.
    let leaf  = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let below = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(leaf as u64, EPOLL_CTL_ADD, below as u64, ev.as_mut_ptr() as u64)), 0);
    // dst already sits 3 deep from the top; adding a 1-deep subtree under it
    // would make a 5-link chain. Counting only downward depth would admit it.
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(dst as u64, EPOLL_CTL_ADD, leaf as u64, ev.as_mut_ptr() as u64)),
               -(Errno::Eloop.as_i32() as i64),
               "the chain above the destination counts against the same budget");
    reset();
}

#[test]
fn a_completed_pwait_puts_the_callers_signal_mask_back() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let original = 0x0000_0000_0000_00F0u64;
    task.sigmask.store(original, Ordering::Release);
    let temp = 0x0000_0000_0000_0F00u64;
    let mask_bytes = temp.to_ne_bytes();
    let mut out = [0u8; 12];
    let a = SyscallArgs {
        a0: epfd as u64, a1: out.as_mut_ptr() as u64, a2: 1, a3: 0,
        a4: mask_bytes.as_ptr() as u64, a5: 8,
    };
    assert_eq!(fs::epoll::sys_epoll_pwait(&a), 0, "a zero timeout returns immediately");
    assert_eq!(task.sigmask.load(Ordering::Acquire), original,
               "a wait that was not interrupted restores the caller's mask on return");
    // A wrong sigsetsize is rejected before any mask is touched.
    let bad = SyscallArgs { a5: 4, ..a };
    assert_eq!(fs::epoll::sys_epoll_pwait(&bad), -(Errno::Einval.as_i32() as i64));
    assert_eq!(task.sigmask.load(Ordering::Acquire), original);
    reset();
}
