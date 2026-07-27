// timerfd surface per Linux timerfd_create(2): TimerfdInode stores
// clockid, expiry_ns, interval_ns, and realtime cancel generation.
// read returns u64 expiration count and re-arms periodic timers.








use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

#[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
#[path = "timerfd/debug.rs"]
mod debug;

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
struct WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    const fn new() -> Self { Self }
    fn wake_all(&self) {}
    // SAFETY: hosted tests do not install a live scheduler or invoke blocking reads.
    unsafe fn park_interruptible_with_deadline(&self, _deadline_ns: u64) { unreachable!("timerfd wait under hosted"); }
}

mod ids {
    use vfs::Ino;
    pub(crate) const INO_BASE: Ino = 0x7300_0000;
    pub(crate) const INO_MASK: Ino = 0x00FF_FFFF;
}
const CLOCK_REALTIME:       u64 = 0;
const CLOCK_MONOTONIC:      u64 = 1;
const CLOCK_BOOTTIME:       u64 = 7;
const CLOCK_REALTIME_ALARM: u64 = 8;
const CLOCK_BOOTTIME_ALARM: u64 = 9;
const TFD_TIMER_ABSTIME:      u64 = 1;
const TFD_TIMER_CANCEL_ON_SET: u64 = 2;

/// Global timerfd table — id → Arc<TimerfdData>. Lets settime/gettime
/// reach the inode state by extracting `id` from the inode marker without
/// a downcast on the inode.
static TIMERFDS: Spinlock<Vec<Arc<TimerfdData>>, TaskListClass>
    = Spinlock::new(Vec::new());
static NEXT_TIMERFD_ID: AtomicU32 = AtomicU32::new(0);

#[inline]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Per-inode timerfd state (Linux `i_private`). # C: O(1)
pub struct TimerfdData {
    pub id:           u32,
    pub clockid:      u64,
    pub expiry_ns:    AtomicU64,
    pub interval_ns:  AtomicU64,
    pub cancel_gen:   AtomicU64,
    read_waiters:     WaitList,
}

fn timerfd_clock_known(clockid: u64) -> bool {
    matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME
        | CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM)
}

fn timerfd_realtime_clock(clockid: u64) -> bool {
    matches!(clockid, CLOCK_REALTIME | CLOCK_REALTIME_ALARM)
}

fn timerfd_alarm_clock(clockid: u64) -> bool {
    matches!(clockid, CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM)
}

fn timerfd_namespace_clock(clockid: u64) -> Option<nscg::time_ns::TimeNsClock> {
    match clockid {
        CLOCK_MONOTONIC => Some(nscg::time_ns::TimeNsClock::Monotonic),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Some(nscg::time_ns::TimeNsClock::Boottime),
        _ => None,
    }
}

fn realtime_deadline(value: u64, now_mono: u64, now_real: u64) -> u64 {
    if value <= now_real { now_mono } else { now_mono.saturating_add(value - now_real) }
}

fn deadline_from_value(clockid: u64, flags: u64, value: u64, now_mono: u64) -> u64 {
    if value == 0 { return 0; }
    if (flags & TFD_TIMER_ABSTIME) == 0 { return now_mono.saturating_add(value); }
    if timerfd_realtime_clock(clockid) {
        let now_real = vfs::inode_times::realtime_now_ns();
        realtime_deadline(value, now_mono, now_real)
    } else {
        value
    }
}

/// `make_timerfd_inode()` — a CharDev pseudo-inode whose `read` yields the
/// expiration count. Registered in the global table so settime/gettime reach
/// it by id. # C: O(1)
pub fn make_timerfd_inode(clockid: u64) -> InodeRef {
    let id = NEXT_TIMERFD_ID.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(TimerfdData {
        id,
        clockid,
        expiry_ns:   AtomicU64::new(0),
        interval_ns: AtomicU64::new(0),
        cancel_gen: AtomicU64::new(0),
        read_waiters: WaitList::new(),
    });
    {
        let mut g = TIMERFDS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || Arc::clone(&data)); }
        else { g[id as usize] = Arc::clone(&data); }
    }
    InodeBuilder::new(ids::INO_BASE | (id as Ino & ids::INO_MASK),
        mk_mode(FileType::CharDev, 0), default_inode_ops(), Arc::new(TimerfdFileOps))
        .private(data)
        .poll_subs(vfs::PollSubscribers::new())
        .build()
}

/// `i_fop` for a timerfd inode. # C: O(1)
struct TimerfdFileOps;
impl FileOps for TimerfdFileOps {
    /// POLLIN only once the timer has expired. The default always-ready
    /// poll made systemd's sd-event (which arms timerfds) busy-loop
    /// epoll_pwait forever — see signalfd::poll.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let d = match inode.private::<TimerfdData>() { Some(d) => d, None => return 0 };
        let cg = d.cancel_gen.load(Ordering::Acquire);
        if cg != 0 && cg != sched::clock::realtime_change_generation() { return vfs::POLL_IN; }
        let expiry = d.expiry_ns.load(Ordering::Acquire);
        let now = monotonic_ns();
        if expiry != 0 && now >= expiry {
            #[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
            debug::event(b"ready", d.id, d.clockid, 0, expiry, now);
            vfs::POLL_IN
        } else { 0 }
    }
    fn poll_deadline_ns(&self, file: &vfs::File) -> Option<u64> {
        let d = file.inode().private::<TimerfdData>()?;
        let expiry = d.expiry_ns.load(Ordering::Acquire);
        if expiry == 0 { None } else { Some(expiry) }
    }
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = match inode.private::<TimerfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        loop {
            match timerfd_take_expirations(d, monotonic_ns(), buf) {
                Ok(Some(n)) => {
                    if let Some(s) = inode.poll_subscribers() { s.notify_mask(vfs::POLL_IN); }
                    return Ok(n);
                }
                Err(e) => return Err(e),
                Ok(None) => {}
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                let deadline = d.expiry_ns.load(Ordering::Acquire);
                // SAFETY: process context; this timerfd's deadline scanner wakes the parked reader.
                unsafe { d.read_waiters.park_interruptible_with_deadline(deadline); }
                // SAFETY: reader published Sleeping through its wait list and holds no locks.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = inode.private::<TimerfdData>().ok_or(VfsError::Einval)?;
        match timerfd_take_expirations(d, monotonic_ns(), buf)? {
            Some(n) => {
                if let Some(s) = inode.poll_subscribers() { s.notify_mask(vfs::POLL_IN); }
                Ok(n)
            }
            None => Err(VfsError::Eagain),
        }
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

fn timerfd_take_expirations(d: &TimerfdData, now: u64, buf: &mut [u8]) -> KResult<Option<usize>> {
    let cg = d.cancel_gen.load(Ordering::Acquire);
    if cg != 0 && cg != sched::clock::realtime_change_generation() {
        d.cancel_gen.store(0, Ordering::Release);
        return Err(VfsError::Ecanceled);
    }
    let expiry = d.expiry_ns.load(Ordering::Acquire);
    if expiry == 0 || now < expiry { return Ok(None); }
    let interval = d.interval_ns.load(Ordering::Acquire);
    let count = if interval == 0 { 1 } else { ((now - expiry) / interval) + 1 };
    let next = if interval == 0 { 0 } else {
        expiry.saturating_add(interval.saturating_mul(count))
    };
    d.expiry_ns.store(next, Ordering::Release);
    buf[..8].copy_from_slice(&count.to_le_bytes());
    Ok(Some(8))
}

/// Lookup the TimerfdData bound to an fd's inode-number marker.
/// # C: O(1)
fn timerfd_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<TimerfdData>> {
    let ino = file.inode().ino();
    if (ino & !ids::INO_MASK) != ids::INO_BASE { return None; }
    let id = (ino & ids::INO_MASK) as usize;
    TIMERFDS.lock().get(id).cloned()
}

/// `sys_timerfd_create(clockid, flags)`. Allocates a fresh TimerfdInode fd.
/// # C: O(N_fds)
pub fn sys_timerfd_create(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    const TFD_NONBLOCK: u64 = 0o0_004_000;
    const TFD_CLOEXEC:  u64 = 0o2_000_000;
    let clockid = args.a0;
    let flags = args.a1;
    if !timerfd_clock_known(clockid) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if timerfd_alarm_clock(clockid) && !cur_has_cap(sched::cap::WAKE_ALARM) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = make_timerfd_inode(clockid);
    #[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
    if let Some(d) = inode.private::<TimerfdData>() {
        debug::event(b"create", d.id, clockid, flags, 0, monotonic_ns());
    }
    let dentry = vfs::dcache::d_alloc_pseudo("[timerfd]", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDONLY;
    if (flags & TFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & TFD_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `sys_timerfd_settime(fd, flags, new, old)`. Decodes the timerfd
/// id from the file's inode marker, looks up the Arc, and writes
/// expiry_ns + interval_ns from new->{it_value, it_interval}.
/// `old` (if non-NULL) gets the previous remaining + interval.
/// # C: O(1)
pub fn sys_timerfd_settime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let flags = args.a1;
    let new = args.a2;
    let old = args.a3;
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = match timerfd_inode_of(&file) {
        Some(i) => i, None => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(new, 32, 1) { return rv; }
    if old != 0 {
        if let Err(rv) = validate_user_buf_writable(old, 32, 1) { return rv; }
    }
    let now = monotonic_ns();
    if old != 0 {
        let i = inode.interval_ns.load(Ordering::Acquire);
        let e = inode.expiry_ns.load(Ordering::Acquire);
        let remain = if e > now { e - now } else { 0 };
        let (i_s, i_n) = sched::clock::ns_to_timespec(i);
        let (r_s, r_n) = sched::clock::ns_to_timespec(remain);
        // SAFETY: old validated writable for one itimerspec object.
        unsafe {
            core::ptr::write_unaligned( old        as *mut i64, i_s as i64);
            core::ptr::write_unaligned((old +  8)  as *mut i64, i_n as i64);
            core::ptr::write_unaligned((old + 16)  as *mut i64, r_s as i64);
            core::ptr::write_unaligned((old + 24)  as *mut i64, r_n as i64);
        }
    }
    // SAFETY: new validated readable for one itimerspec object.
    let (is, ins, vs, vns) = unsafe {
        let a = core::ptr::read_unaligned( new        as *const i64);
        let b = core::ptr::read_unaligned((new +  8)  as *const i64);
        let c = core::ptr::read_unaligned((new + 16)  as *const i64);
        let d = core::ptr::read_unaligned((new + 24)  as *const i64);
        (a, b, c, d)
    };
    // Decode both timespecs via the shared `ktime_set`-clamped conversion
    // (`syscall::time::timespec_to_ns`): negative secs / out-of-range nsec is
    // EINVAL like before, but a huge-but-syntactically-valid `tv_sec` now
    // clamps to `KTIME_MAX_NS` (Linux's own `ktime_t` ceiling) instead of
    // propagating an arbitrary multi-hundred-year value into `expiry_ns` —
    // the bare `saturating_mul` this replaced had no upper bound at all.
    let interval = match syscall::time::timespec_to_ns(is, ins) {
        Ok(ns) => ns,
        Err(_) => {
            #[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
            debug::bad_value(inode.id, inode.clockid, flags, is, ins, vs, vns);
            return -(Errno::Einval.as_i32() as i64);
        }
    };
    let value = match syscall::time::timespec_to_ns(vs, vns) {
        Ok(ns) => ns,
        Err(_) => {
            #[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
            debug::bad_value(inode.id, inode.clockid, flags, is, ins, vs, vns);
            return -(Errno::Einval.as_i32() as i64);
        }
    };
    #[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
    debug::spec(inode.id, inode.clockid, flags, is, ins, vs, vns);
    let host_value = if (flags & TFD_TIMER_ABSTIME) != 0 && value != 0 {
        match timerfd_namespace_clock(inode.clockid) {
            Some(clock) => {
                let owner = match cur.namespace_snapshot() {
                    Some(snapshot) => snapshot.time,
                    None => return -(Errno::Eio.as_i32() as i64),
                };
                match nscg::time_ns::absolute_to_host(&owner, clock, value) {
                    Ok(value) => value,
                    Err(_) => return -(Errno::Eio.as_i32() as i64),
                }
            }
            None => value,
        }
    } else { value };
    inode.interval_ns.store(interval, Ordering::Release);
    // TFD_TIMER_ABSTIME (flags bit 0): host_value is an ABSOLUTE host-domain
    // deadline after any TIME namespace translation. Without honoring it, `now+value`
    // pushes the expiry ~uptime into the future → it never fires. Go's
    // runtime timers (newer Go) + systemd arm timerfds this way, so the
    // bug livelocked every Go app (duf/glow/micro) in epoll_pwait. Relative
    // mode (flags clear) keeps `now + value`.
    let expiry = deadline_from_value(inode.clockid, flags, host_value, now);
    let cancel_gen = if (flags & TFD_TIMER_CANCEL_ON_SET) != 0
        && (flags & TFD_TIMER_ABSTIME) != 0
        && timerfd_realtime_clock(inode.clockid)
        && value != 0
    { sched::clock::realtime_change_generation() } else { 0 };
    inode.cancel_gen.store(cancel_gen, Ordering::Release);
    inode.expiry_ns.store(expiry, Ordering::Release);
    inode.read_waiters.wake_all();
    #[cfg(any(feature = "debug-boot", feature = "debug-mutter-timer-verbose"))]
    debug::event(b"arm", inode.id, inode.clockid, flags, expiry, now);
    if let Some(subs) = file.poll_subscribers() { subs.notify_mask(vfs::POLL_IN); }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_namespace_clock_routes_only_linux_virtualized_timerfd_clocks() {
        assert_eq!(timerfd_namespace_clock(CLOCK_MONOTONIC),
            Some(nscg::time_ns::TimeNsClock::Monotonic));
        assert_eq!(timerfd_namespace_clock(CLOCK_BOOTTIME),
            Some(nscg::time_ns::TimeNsClock::Boottime));
        assert_eq!(timerfd_namespace_clock(CLOCK_BOOTTIME_ALARM),
            Some(nscg::time_ns::TimeNsClock::Boottime));
        assert_eq!(timerfd_namespace_clock(CLOCK_REALTIME), None);
        assert_eq!(timerfd_namespace_clock(CLOCK_REALTIME_ALARM), None);
    }

    #[test]
    fn deadline_keeps_relative_values_and_maps_realtime_to_host_monotonic() {
        assert_eq!(deadline_from_value(CLOCK_MONOTONIC, 0, 7, 11), 18);
        assert_eq!(deadline_from_value(CLOCK_BOOTTIME, TFD_TIMER_ABSTIME, 7, 11), 7);
        assert_eq!(realtime_deadline(25, 11, 18), 18);
        assert_eq!(realtime_deadline(17, 11, 18), 11);
    }

    /// B1432: `sys_timerfd_settime` decodes `{tv_sec, tv_nsec}` via
    /// `syscall::time::timespec_to_ns` BEFORE calling `deadline_from_value` —
    /// this proves the full pipeline (decode-then-fold-into-a-CLOCK_REALTIME
    /// deadline) stays sane end to end: a malformed timespec (huge tv_sec,
    /// same order of magnitude as the reported ~527-year `wakeup_deadline_ns`)
    /// clamps at the decode step to `KTIME_MAX_NS`, and `realtime_deadline`
    /// then folds that clamped value into a bounded monotonic deadline —
    /// never an arbitrary multi-hundred-year value the deadline scanner can
    /// never reach. A normal near-term absolute target converts to the exact
    /// expected small relative delay.
    #[test]
    fn absolute_realtime_pipeline_clamps_malformed_tv_sec_and_converts_normal_ones() {
        use syscall::time::{timespec_to_ns, KTIME_MAX_NS};
        let now_mono = 1_000_000_000; // 1s uptime
        let now_real = 1_774_000_000_000_000_000; // a plausible 2026-ish epoch ns

        // Malformed: tv_sec ~16.66e9 (the exact magnitude the bug report saw).
        let malformed = timespec_to_ns(16_661_643_624, 155_194_468).unwrap();
        assert_eq!(malformed, KTIME_MAX_NS);
        let dl = realtime_deadline(malformed, now_mono, now_real);
        // Bounded by KTIME_MAX_NS + now_mono, never an unbounded/arbitrary value.
        assert_eq!(dl, now_mono + (KTIME_MAX_NS - now_real));
        assert!(dl < u64::MAX);

        // Normal: fire 30s from "now" on the same realtime clock.
        let normal = timespec_to_ns((now_real / 1_000_000_000) as i64 + 30, 0).unwrap();
        let dl_normal = realtime_deadline(normal, now_mono, now_real);
        assert_eq!(dl_normal, now_mono + 30_000_000_000);
    }

    #[test]
    fn nonblocking_unexpired_timerfd_read_is_eagain() {
        let inode = make_timerfd_inode(CLOCK_MONOTONIC);
        let d = inode.private::<TimerfdData>().unwrap();
        d.expiry_ns.store(u64::MAX, Ordering::Release);
        let mut buf = [0u8; 8];
        assert_eq!(TimerfdFileOps.read_nonblock(&inode, 0, &mut buf), Err(VfsError::Eagain));
    }

    #[test]
    fn periodic_read_preserves_deadline_phase_and_reports_all_missed_ticks() {
        let d = TimerfdData {
            id: 0, clockid: CLOCK_MONOTONIC,
            expiry_ns: AtomicU64::new(10), interval_ns: AtomicU64::new(10),
            cancel_gen: AtomicU64::new(0), read_waiters: WaitList::new(),
        };
        let mut buf = [0u8; 8];
        assert_eq!(timerfd_take_expirations(&d, 35, &mut buf), Ok(Some(8)));
        assert_eq!(u64::from_le_bytes(buf), 3);
        assert_eq!(d.expiry_ns.load(Ordering::Acquire), 40);
    }
}

fn cur_has_cap(cap: u32) -> bool {
    sched::current().map(|c| c.has_cap(cap)).unwrap_or(false)
}

/// `sys_timerfd_gettime(fd, value)`. Reports remaining + interval.
/// # C: O(1)
pub fn sys_timerfd_gettime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let value = args.a1;
    if let Err(rv) = validate_user_buf_writable(value, 32, 1) { return rv; }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = match timerfd_inode_of(&file) {
        Some(i) => i, None => return -(Errno::Einval.as_i32() as i64),
    };
    let now = monotonic_ns();
    let i = inode.interval_ns.load(Ordering::Acquire);
    let e = inode.expiry_ns.load(Ordering::Acquire);
    let remain = if e > now { e - now } else { 0 };
    let (i_s, i_n) = sched::clock::ns_to_timespec(i);
    let (r_s, r_n) = sched::clock::ns_to_timespec(remain);
    // SAFETY: value validated writable for one itimerspec object.
    unsafe {
        core::ptr::write_unaligned( value        as *mut i64, i_s as i64);
        core::ptr::write_unaligned((value +  8)  as *mut i64, i_n as i64);
        core::ptr::write_unaligned((value + 16)  as *mut i64, r_s as i64);
        core::ptr::write_unaligned((value + 24)  as *mut i64, r_n as i64);
    }
    0
}
