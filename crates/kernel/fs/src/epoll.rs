// epoll surface per Linux 2.6.0. v1: EpollInode holds an interest
// list (Vec<EpollEntry>) under a Spinlock. epoll_ctl mutates;
// epoll_wait scans entries, reports any whose fd is still open as
// ready (level-triggered) and returns up to maxevents records.
// Real readiness predicates land when the wait infrastructure is
// in place; v1 keeps libuv / tokio happy past the create+ctl boundary.





use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};

// Park / wake plumbing lives in `sched::live` so net/IPC layers
// (which don't depend on `fs`) can trigger epoll wakeups without a
// circular crate edge. See `sched::live::EPOLL_GLOBAL_WAIT` and
// `sched::live::notify_epoll_waiters`.

const EPOLL_INO_BASE: Ino = 0x7400_0000;
const EPOLL_INO_MASK: Ino = 0x00FF_FFFF;

/// DIAG bound: cap on `[epoll-lvl]` lines so the busy-loop trace can't flood.
/// Gated behind the off-by-default `debug-epoll` feature (NOT `debug-boot`),
/// so it ships only when explicitly diagnosing a level-triggered epoll spin.
#[cfg(feature = "debug-epoll")]
static EPOLL_DIAG_N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

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

#[derive(Clone)]
pub struct EpollEntry {
    pub fd: i32,
    pub events: u32,
    pub data: u64,
    /// EPOLLET edge tracking: ready bits already edge-delivered and still
    /// ready. A level-ready fd (e.g. /proc/self/mountinfo, always POLLIN)
    /// registered with EPOLLET must fire only on a not-ready→ready edge,
    /// once — not every scan. Without this, systemd's sd-event (which uses
    /// EPOLLET) busy-looped epoll_pwait forever on always-ready fds.
    pub et_seen: u32,
    /// Weak ref to the watched inode, captured at ADD, so EpollInode::poll()
    /// (nested-epoll readiness) can scan entries WITHOUT an fd_table — a
    /// nested epoll fd is POLLIN-readable only when one of its entries would
    /// fire. Without poll(), EpollInode used the default always-ready poll →
    /// any parent epoll (e.g. Go's netpoller watching a fsnotify watcher
    /// epoll) spun forever.
    pub inode: Option<alloc::sync::Weak<vfs::Inode>>,
    /// Watched fd's PollSubscribers generation at the last report. A later scan
    /// seeing a higher gen knows a real readiness event fired since — a fresh
    /// EPOLLET edge — even if et_seen still holds the bit (userspace drained with
    /// no intervening scan). Fixes EPOLLET losing an edge on accept/read.
    pub last_gen: u64,
    /// GLOBAL_EPOLL_GEN at the last report — covers readiness delivered via the
    /// global broadcast fallback (wake_peer_subs when the peer end-subs slot is
    /// empty), which does NOT bump the per-inode gen.
    pub last_ggen: u64,
}

/// EPOLLET — edge-triggered (Linux `EPOLLET` = 1<<31).
const EPOLLET: u32 = 0x8000_0000;

/// Per-inode epoll state (Linux `i_private`).
pub struct EpollData {
    pub id:      u32,
    pub entries: Spinlock<Vec<EpollEntry>, TaskListClass>,
    /// F181: per-EpollData WaitList (Arc'd so subscribers can hold
    /// Weak). epoll_wait parks here; F181-aware event sites wake
    /// only the EpollData that subscribed via `epoll_ctl(ADD)`.
    /// Kernel-only — hosted tests don't run the scheduler.
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: Arc<sched::live::WaitList>,
}

static EPOLLS: Spinlock<Vec<Arc<EpollData>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// F181: broadcast wake registered with sched at boot via
/// `install_epoll_broadcast`. Walks every live EpollData and
/// wakes its per-instance waitlist. Kernel-only — hosted tests
/// don't run epoll_wait.
/// # C: O(N_epoll_instances)
/// Global readiness-event generation, bumped on every GLOBAL epoll broadcast
/// (`broadcast_wake_all_epolls`, i.e. the `wake_peer_subs` fallback / any keyless
/// wake). An EPOLLET entry whose per-inode PollSubscribers gen did NOT advance
/// (the readiness event was delivered via the global fallback, not a targeted
/// notify) still learns an edge fired if THIS counter advanced since its last
/// report — closing the last EPOLLET lost-edge path (intermittent: dbus-broker
/// occasionally never reads polkit's AUTH when the connected-socket wake took the
/// fallback, so polkit's RequestName never completes → 45s Type=dbus timeout).
pub static GLOBAL_EPOLL_GEN: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "oxide-kernel")]
pub fn broadcast_wake_all_epolls() {
    GLOBAL_EPOLL_GEN.fetch_add(1, Ordering::AcqRel);
    let snapshot: Vec<Arc<EpollData>> = EPOLLS.lock().iter().cloned().collect();
    for ep in snapshot { ep.waiters.wake_all(); }
}

/// One-shot boot wiring: tell sched how to broadcast epoll wakes
/// without taking a fs dependency.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn install_epoll_broadcast() {
    sched::live::set_epoll_broadcast_hook(broadcast_wake_all_epolls);
}
static NEXT_EPOLL_ID: AtomicU32 = AtomicU32::new(0);

/// `make_epoll_inode()` — a CharDev pseudo-inode; registered in the global
/// table so epoll_ctl/wait reach its state by id. # C: O(1)
pub fn make_epoll_inode() -> InodeRef {
    let id = NEXT_EPOLL_ID.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(EpollData {
        id,
        entries: Spinlock::new(Vec::new()),
        #[cfg(target_os = "oxide-kernel")]
        waiters: Arc::new(sched::live::WaitList::new()),
    });
    {
        let mut g = EPOLLS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || Arc::clone(&data)); }
        else { g[id as usize] = Arc::clone(&data); }
    }
    InodeBuilder::new(EPOLL_INO_BASE | (id as Ino & EPOLL_INO_MASK),
        mk_mode(FileType::CharDev, 0), default_inode_ops(), Arc::new(EpollFileOps))
        .private(data)
        .build()
}

/// `i_fop` for an epoll inode. # C: O(1)
struct EpollFileOps;
impl FileOps for EpollFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
    /// A nested epoll fd is POLLIN-readable iff one of its entries WOULD fire
    /// (mirrors scan_once, read-only). Without this the default always-ready
    /// poll made any PARENT epoll watching this one (e.g. Go's netpoller over
    /// an fsnotify watcher epoll) spin in epoll_pwait forever. # C: O(N_entries)
    fn poll(&self, inode: &Inode) -> u32 {
        let d = match inode.private::<EpollData>() { Some(d) => d, None => return 0 };
        let list = d.entries.lock();
        for e in list.iter() {
            let inode = match e.inode.as_ref().and_then(|w| w.upgrade()) {
                Some(i) => i, None => continue,
            };
            let ready = inode.poll() & e.events;
            let fires = if e.events & EPOLLET != 0 {
                (ready & !e.et_seen) != 0
            } else {
                ready != 0
            };
            if fires { return vfs::POLL_IN; }
        }
        0
    }
}

/// F181: EpollData is the wake-callback recipient registered by
/// per-fd subscribers. `notify` wakes its WaitList directly —
/// no fan-out, no global broadcast.
#[cfg(target_os = "oxide-kernel")]
impl vfs::EpollNotify for EpollData {
    fn notify(&self) { self.waiters.wake_all(); }
}

/// # C: O(1)
fn epoll_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<EpollData>> {
    let ino = file.inode().ino();
    if (ino & 0xFF00_0000) != EPOLL_INO_BASE { return None; }
    let id = (ino & EPOLL_INO_MASK) as usize;
    EPOLLS.lock().get(id).cloned()
}

/// `sys_epoll_create(size)` / `sys_epoll_create1(flags)`.
/// # C: O(N_fds)
pub fn sys_epoll_create1(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
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
    let inode = make_epoll_inode();
    let dentry = vfs::dcache::d_alloc_pseudo("[eventpoll]", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
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
    // F181: resolve target fd → InodeRef so we can register / drop
    // the epoll on the inode's PollSubscribers when supported.
    let target_inode = fdt.get(fd).ok().map(|f| f.inode().clone());
    let mut list = ep.entries.lock();
    match op {
        EPOLL_CTL_ADD => {
            if list.iter().any(|e| e.fd == fd) {
                return -(Errno::Eexist.as_i32() as i64);
            }
            // debug-syscost DIAG: which fds dbus-broker ADDs to its epoll +
            // their ino (0x534f434b tag = socket) + events (0x80000000 = EPOLLET).
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
            {
                let is_db = sched::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("dbus-broker")) }).unwrap_or(false);
                if is_db {
                    klog::write_raw(b"[EPADD fd="); klog::write_dec_u64(fd as u64);
                    klog::write_raw(b" ino="); klog::write_hex_u64(target_inode.as_ref().map(|i| i.ino()).unwrap_or(0));
                    klog::write_raw(b" ev="); klog::write_hex_u64(events as u64);
                    klog::write_raw(b"]\n");
                }
            }
            list.push(EpollEntry { fd, events, data, et_seen: 0, last_gen: 0, last_ggen: 0,
                inode: target_inode.as_ref().map(Arc::downgrade) });
            // F181: targeted-wake subscribe if the inode supports it.
            #[cfg(target_os = "oxide-kernel")]
            if let Some(inode) = target_inode.as_ref() {
                if let Some(subs) = inode.poll_subscribers() {
                    let weak: alloc::sync::Weak<dyn vfs::EpollNotify> =
                        alloc::sync::Arc::downgrade(&(Arc::clone(&ep) as Arc<dyn vfs::EpollNotify>));
                    subs.subscribe(ep.id, weak);
                }
            }
            0
        }
        EPOLL_CTL_MOD => {
            for e in list.iter_mut() {
                if e.fd == fd { e.events = events; e.data = data; e.et_seen = 0; return 0; }
            }
            -(Errno::Enoent.as_i32() as i64)
        }
        EPOLL_CTL_DEL => {
            let n = list.len();
            list.retain(|e| e.fd != fd);
            if list.len() == n { return -(Errno::Enoent.as_i32() as i64); }
            #[cfg(target_os = "oxide-kernel")]
            if let Some(inode) = target_inode.as_ref() {
                if let Some(subs) = inode.poll_subscribers() {
                    subs.unsubscribe(ep.id);
                }
            }
            0
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
    let timeout = args.a3 as i32;
    let timeout_ns = if timeout < 0 {
        None
    } else {
        Some((timeout as u64).saturating_mul(1_000_000))
    };
    sys_epoll_wait_timeout(args, timeout_ns)
}

/// `sys_epoll_pwait2(epfd, events*, maxevents, timeout*, sigmask, sigsetsize)`.
/// Unlike epoll_wait/epoll_pwait, arg4 is a pointer to `struct timespec`.
pub fn sys_epoll_pwait2(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let timeout_ns = if args.a3 == 0 {
        None
    } else {
        if args.a3 >= hal::USER_VA_END || args.a3.saturating_add(16) > hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: timespec pointer range validated above; CPL=0 reads through caller's AS.
        let (sec, nsec) = unsafe {
            (
                core::ptr::read_volatile(args.a3 as *const i64),
                core::ptr::read_volatile((args.a3 + 8) as *const i64),
            )
        };
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return -(Errno::Einval.as_i32() as i64);
        }
        Some((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
    };
    sys_epoll_wait_timeout(args, timeout_ns)
}

fn sys_epoll_wait_timeout(args: &syscall::SyscallArgs, timeout_ns: Option<u64>) -> i64 {
    use syscall::errno::Errno;
    let epfd = args.a0 as i32;
    let evp  = args.a1;
    let maxevents = args.a2 as i32;
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
    if out > 0 || timeout_ns == Some(0) {
        return out as i64;
    }
    // B47: honour the caller's timeout. Without this, dhcpcd's
    // eloop blocks forever on its 10 s lease-attempt poll because
    // we'd just park-on-empty and never wake. None means wait forever.
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::TimerOps;
        let now = || {
            #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
            #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
        };
        let deadline_ns = timeout_ns.map(|ns| now().saturating_add(ns));
        // Safety-net re-scan interval. Even with timeout < 0 (block
        // forever), park with a bounded deadline so the per-tick
        // `tick_wake_expired` scanner rouses us periodically to re-scan
        // for *level-ready* fds whose readiness posts no active wake to
        // this epoll's waitlist — notably timerfd expiry (systemd's
        // RestartSec → getty respawn) and signalfd. Targeted fd-event /
        // signal wakes still fire immediately; this only bounds the
        // worst-case latency when nothing else wakes us. 20 ms is
        // imperceptible at the console and fine for systemd's timers.
        const RESCAN_NS: u64 = 20_000_000;
        // debug-wakelat: total time this epoll_wait spends blocked; a long
        // wait that ends with ready fds means the arrival edge was slow.
        #[cfg(feature = "debug-wakelat")]
        let wl_start = now();
        #[cfg(feature = "debug-wakelat")]
        let wl_tid = sched::current().map(|c| c.tid).unwrap_or(0);
        loop {
            // Park until the nearest of: the caller's deadline (if any)
            // and the next safety-net re-scan.
            let rescan_at = now().saturating_add(RESCAN_NS);
            let park_dl = match deadline_ns {
                Some(d) => core::cmp::min(d, rescan_at),
                None => rescan_at,
            };
            // debug-wakelat: claim the correlation slot + tag KIND_EPOLL so
            // the ttwu→switch-in latency for this park cycle is measured.
            #[cfg(feature = "debug-wakelat")]
            sched::live::wakelat::note_wait(wl_tid, sched::live::wakelat::KIND_EPOLL);
            // SAFETY: process ctx; preempt-off across the syscall; park_with_deadline bumps Arc + marks Sleeping + stamps the wake deadline; park_yield yields WITHOUT halting the CPU (this task is now Sleeping, so the idle task provides the halt/IRQ-window and the scheduler drains all other roused waiters at full speed — the gnome session-setup wake-latency fix). UP single-CPU.
            unsafe {
                ep.waiters.park_with_deadline(park_dl);
                sched::live::park_yield();
            }
            let out2 = scan_once(&ep, &fdt, evp, maxevents);
            if out2 > 0 {
                #[cfg(feature = "debug-wakelat")]
                sched::live::wakelat::note_blocked(
                    wl_tid, sched::live::wakelat::KIND_EPOLL,
                    now().saturating_sub(wl_start), out2 as u64);
                return out2 as i64;
            }
            if let Some(d) = deadline_ns {
                if now() >= d { return 0; }
            }
            // Linux `ep_poll`: a pending signal aborts the wait with -EINTR so
            // the syscall-return dispatch tail can run the handler OR the
            // SIG_DFL terminate. Without this an epoll_wait-parked task
            // re-scanned + re-parked forever, so a SIGTERM/SIGKILL never took
            // effect — udev's single-shot workers idle in epoll_wait were
            // UNKILLABLE (measured: 8 workers stuck in nr#232, state Sleeping,
            // survived SIGKILL), so udevd's event_timeout kills failed, the
            // queue never drained, and logind/gdm (also epoll-driven) hung on
            // D-Bus. SIGKILL/SIGSTOP are always deliverable (unmaskable).
            if let Some(cur) = sched::current() {
                use core::sync::atomic::Ordering;
                const FORCED: u64 = (1u64 << 8) | (1u64 << 18); // SIGKILL(9) | SIGSTOP(19)
                let pending = cur.sigpending.load(Ordering::Acquire);
                let masked  = cur.sigmask.load(Ordering::Acquire);
                if (pending & !masked) | (pending & FORCED) != 0 {
                    return -(syscall::errno::Errno::Eintr.as_i32() as i64);
                }
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
fn scan_once(ep: &Arc<EpollData>, fdt: &Arc<vfs::FdTable>, evp: u64, maxevents: i32) -> i32 {
    // Compute readiness + apply EPOLLET edge tracking under the lock, then
    // write results to user memory after releasing it (no user writes while
    // holding the spinlock). For an EPOLLET entry we report only bits that
    // newly became ready since the last edge — a perpetually-ready fd fires
    // once, not every scan (the fix for systemd's epoll_pwait busy-loop).
    let mut reports: Vec<(u32, u64)> = Vec::new();
    {
        let mut list = ep.entries.lock();
        for e in list.iter_mut() {
            if reports.len() as i32 >= maxevents { break; }
            let f = match fdt.get(e.fd) { Ok(f) => f, Err(_) => continue };
            // poll_file passes the per-fd read cursor so append-only streams
            // (/dev/kmsg) report POLL_IN only with unread data — the default
            // always-ready poll() busy-loops journald's epoll otherwise.
            let raw_poll = f.poll();
            let ready = raw_poll & e.events;
            // debug-syscost DIAG: dbus-broker's scan of a LISTENER socket (ino tag
            // 0x534f434b; raw poll bit0=POLLIN set iff accept_q non-empty). Shows
            // whether the ready listener is even evaluated by dbus-broker's epoll,
            // its events mask (0x80000000=EPOLLET), et_seen, and computed `ready`.
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
            if (f.inode().ino() & 0xffff_ffff_0000_0000) == 0x534f_434b_0000_0000 && (raw_poll & 0x1) != 0 {
                let is_db = sched::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("dbus-broker")) }).unwrap_or(false);
                if is_db {
                    klog::write_raw(b"[LSCAN fd="); klog::write_dec_u64(e.fd as u64);
                    klog::write_raw(b" raw="); klog::write_hex_u64(raw_poll as u64);
                    klog::write_raw(b" ev="); klog::write_hex_u64(e.events as u64);
                    klog::write_raw(b" rdy="); klog::write_hex_u64(ready as u64);
                    klog::write_raw(b" seen="); klog::write_hex_u64(e.et_seen as u64);
                    klog::write_raw(b"]\n");
                }
            }
            if e.events & EPOLLET != 0 {
                // A readiness EVENT (notify/notify_mask on the fd's PollSubscribers)
                // since our last report is itself a fresh EPOLLET edge — even when
                // the bit stayed level-set and no scan saw it drop (userspace drained
                // via accept-until-EAGAIN / read-until-EAGAIN between scans). Without
                // this, a connection queued while et_seen still holds EPOLLIN gives
                // new_edges==0 and is never reported → dbus-broker never accepts the
                // late client (polkit) → 45s Type=dbus timeout → no greeter.
                let cur_gen = f.inode().poll_subscribers().map(|s| s.generation()).unwrap_or(e.last_gen);
                let cur_ggen = GLOBAL_EPOLL_GEN.load(Ordering::Acquire);
                let gen_edge = (cur_gen != e.last_gen || cur_ggen != e.last_ggen) && ready != 0;
                e.last_gen = cur_gen;
                e.last_ggen = cur_ggen;
                // Drop edges that went not-ready so a later re-ready re-fires.
                e.et_seen &= ready;
                let new_edges = ready & !e.et_seen;
                if new_edges == 0 && !gen_edge { continue; }
                e.et_seen |= ready;
            } else if ready == 0 {
                continue;
            } else {
                // DIAG (`debug-epoll`): a level-triggered fd reporting ready
                // every scan is what spins systemd's event loop ("Looping too
                // fast"). Log the first N so the culprit fd/type/name shows.
                #[cfg(feature = "debug-epoll")]
                {
                    let n = EPOLL_DIAG_N.fetch_add(1, Ordering::Relaxed);
                    if n < 200 {
                        klog::write_raw(b"[epoll-lvl] fd=");
                        klog::write_dec_u64(e.fd as u64);
                        klog::write_raw(b" type=");
                        klog::write_dec_u64(f.inode().file_type() as u64);
                        klog::write_raw(b" poll=");
                        klog::write_hex_u64(f.inode().poll() as u64);
                        klog::write_raw(b" want=");
                        klog::write_hex_u64(e.events as u64);
                        klog::write_raw(b" name=");
                        klog::write_raw(f.dentry().name().as_bytes());
                        klog::write_raw(b"\n");
                    }
                }
            }
            reports.push((ready, e.data));
        }
    }
    let mut out = 0i32;
    for (revents, data) in reports.iter() {
        let dst = evp + (out as u64) * (EPOLL_EVENT_SIZE as u64);
        // SAFETY: evp validated by caller; per-record stride within user buffer sized for maxevents records; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(dst as *mut u32, *revents);
            core::ptr::write_volatile((dst + EPOLL_DATA_OFF as u64) as *mut u64, *data);
        }
        out += 1;
    }
    out
}
