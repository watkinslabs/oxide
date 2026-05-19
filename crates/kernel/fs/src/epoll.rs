// epoll surface per Linux 2.6.0. v1: EpollInode holds an interest
// list (Vec<EpollEntry>) under a Spinlock. epoll_ctl mutates;
// epoll_wait scans entries, reports any whose fd is still open as
// ready (level-triggered) and returns up to maxevents records.
// Real readiness predicates land when the wait infrastructure is
// in place; v1 keeps libuv / tokio happy past the create+ctl boundary.





use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

// Park / wake plumbing lives in `sched::live` so net/IPC layers
// (which don't depend on `fs`) can trigger epoll wakeups without a
// circular crate edge. See `sched::live::EPOLL_GLOBAL_WAIT` and
// `sched::live::notify_epoll_waiters`.

const EPOLL_INO_BASE: Ino = 0x7400_0000;
const EPOLL_INO_MASK: Ino = 0x00FF_FFFF;

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

#[cfg(target_arch = "x86_64")]
const EPOLL_EVENT_SIZE: usize = 12;
#[cfg(target_arch = "aarch64")]
const EPOLL_EVENT_SIZE: usize = 16;

#[cfg(target_arch = "x86_64")]
const EPOLL_DATA_OFF: usize = 4;
#[cfg(target_arch = "aarch64")]
const EPOLL_DATA_OFF: usize = 8;

#[derive(Clone, Copy)]
pub struct EpollEntry { pub fd: i32, pub events: u32, pub data: u64 }

pub struct EpollInode {
    pub id:      u32,
    pub entries: Spinlock<Vec<EpollEntry>, TaskListClass>,
}

static EPOLLS: Spinlock<Vec<Arc<EpollInode>>, TaskListClass>
    = Spinlock::new(Vec::new());
static NEXT_EPOLL_ID: AtomicU32 = AtomicU32::new(0);

impl EpollInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let id = NEXT_EPOLL_ID.fetch_add(1, Ordering::Relaxed);
        let arc = Arc::new(Self { id, entries: Spinlock::new(Vec::new()) });
        let mut g = EPOLLS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || Arc::clone(&arc)); }
        else { g[id as usize] = Arc::clone(&arc); }
        arc
    }
}

impl Inode for EpollInode {
    fn ino(&self) -> Ino { EPOLL_INO_BASE | (self.id as Ino & EPOLL_INO_MASK) }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// # C: O(1)
fn epoll_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<EpollInode>> {
    let ino = file.inode().ino();
    if (ino & 0xFF00_0000) != EPOLL_INO_BASE { return None; }
    let id = (ino & EPOLL_INO_MASK) as usize;
    EPOLLS.lock().get(id).cloned()
}

/// `sys_epoll_create(size)` / `sys_epoll_create1(flags)`.
/// # C: O(N_fds)
pub fn sys_epoll_create1(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    const EPOLL_CLOEXEC: u64 = 0o2_000_000;
    let flags = args.a0;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = EpollInode::new() as InodeRef;
    let dentry = Dentry::new(None, "epoll".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc(file) {
        Ok(fd) => {
            if (flags & EPOLL_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `sys_epoll_ctl(epfd, op, fd, event*)`.
/// # C: O(N_entries)
pub fn sys_epoll_ctl(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let epfd = args.a0 as i32;
    let op   = args.a1 as i32;
    let fd   = args.a2 as i32;
    let evp  = args.a3;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let epfile = match fdt.get(epfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let ep = match epoll_inode_of(&epfile) {
        Some(i) => i, None => return -(Errno::Einval.as_i32() as i64),
    };
    let (events, data) = if op == EPOLL_CTL_DEL {
        (0u32, 0u64)
    } else {
        if evp == 0 || evp >= hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: evp validated; CPL=0 reads through caller's AS.
        unsafe {
            let ev = core::ptr::read_volatile(evp as *const u32);
            let da = core::ptr::read_volatile((evp + EPOLL_DATA_OFF as u64) as *const u64);
            (ev, da)
        }
    };
    let mut list = ep.entries.lock();
    match op {
        EPOLL_CTL_ADD => {
            if list.iter().any(|e| e.fd == fd) {
                return -(Errno::Eexist.as_i32() as i64);
            }
            list.push(EpollEntry { fd, events, data });
            0
        }
        EPOLL_CTL_MOD => {
            for e in list.iter_mut() {
                if e.fd == fd { e.events = events; e.data = data; return 0; }
            }
            -(Errno::Enoent.as_i32() as i64)
        }
        EPOLL_CTL_DEL => {
            let n = list.len();
            list.retain(|e| e.fd != fd);
            if list.len() == n { -(Errno::Enoent.as_i32() as i64) } else { 0 }
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// `sys_epoll_wait(epfd, events*, maxevents, timeout)` /
/// `sys_epoll_pwait(epfd, events*, maxevents, timeout, sigmask, sz)`.
/// Level-triggered scan over the epoll's interest set. When the
/// scan returns zero ready entries:
///   * timeout == 0  → return 0 immediately (non-blocking poll)
///   * timeout != 0  → park on the global epoll waitlist + schedule;
///     wake on any fd-state-change `notify_pollers()` call; re-scan
///     after wake and return whatever's ready (caller's loop re-
///     enters if it still needs more events).
/// Without the park-on-empty path, a daemon polling for input
/// (dhcpcd's privsep child) starves the rest of the UP runqueue
/// and the producer never gets to send.
/// # C: O(N_entries) per scan; one park+wake per blocked round-trip.
pub fn sys_epoll_wait(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let epfd = args.a0 as i32;
    let evp  = args.a1;
    let maxevents = args.a2 as i32;
    let timeout   = args.a3 as i32;
    if maxevents <= 0 { return -(Errno::Einval.as_i32() as i64); }
    if evp == 0 || evp >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let epfile = match fdt.get(epfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let ep = match epoll_inode_of(&epfile) {
        Some(i) => i, None => return -(Errno::Einval.as_i32() as i64),
    };
    // First scan: report any already-ready entries without parking.
    let out = scan_once(&ep, &fdt, evp, maxevents);
    if out > 0 || timeout == 0 {
        return out as i64;
    }
    // B47: honour the caller's timeout (ms). Without this, dhcpcd's
    // eloop blocks forever on its 10 s lease-attempt poll because
    // we'd just park-on-empty and never wake. timeout < 0 means
    // wait forever (epoll_wait(2)).
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::TimerOps;
        let now = || {
            #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
            #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
        };
        let deadline_ns: Option<u64> = if timeout < 0 {
            None
        } else {
            Some(now().saturating_add((timeout as u64).saturating_mul(1_000_000)))
        };
        loop {
            // Park + wait for a wakeup. tick_yield will wake periodically
            // on the timer IRQ even if nobody notified the wait list,
            // which lets us re-check the deadline and any newly-ready fds.
            // SAFETY: process ctx; preempt-off across the syscall; WaitList::park bumps Arc + marks Sleeping; tick_yield yields. UP single-CPU.
            unsafe {
                sched::live::EPOLL_GLOBAL_WAIT.park();
                sched::live::tick_yield();
            }
            let out2 = scan_once(&ep, &fdt, evp, maxevents);
            if out2 > 0 { return out2 as i64; }
            if let Some(d) = deadline_ns {
                if now() >= d { return 0; }
            }
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        // Hosted tests: no runqueue. Return 0 (no events) so the
        // hosted-test single-shot path completes.
        0
    }
}

/// One non-blocking scan over an epoll's interest list. Writes
/// ready events into the user-supplied buffer; returns the count.
/// # C: O(N_entries)
fn scan_once(ep: &Arc<EpollInode>, fdt: &Arc<vfs::FdTable>, evp: u64, maxevents: i32) -> i32 {
    let snapshot: Vec<EpollEntry> = ep.entries.lock().clone();
    let mut out = 0i32;
    for e in snapshot.iter() {
        if out >= maxevents { break; }
        let f = match fdt.get(e.fd) { Ok(f) => f, Err(_) => continue };
        let ready = f.inode().poll() & e.events;
        if ready == 0 { continue; }
        let dst = evp + (out as u64) * (EPOLL_EVENT_SIZE as u64);
        // SAFETY: evp validated by caller; per-record stride within user buffer sized for maxevents records; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(dst as *mut u32, ready);
            core::ptr::write_volatile((dst + EPOLL_DATA_OFF as u64) as *mut u64, e.data);
        }
        out += 1;
    }
    out
}
