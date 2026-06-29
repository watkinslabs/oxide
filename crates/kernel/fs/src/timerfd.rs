// timerfd surface per Linux 2.6.25. v1: TimerfdInode stores
// expiry_ns + interval_ns. read returns u64 expiration count
// (1 if expired since last read; 0 otherwise) and re-arms for
// periodic timers. settime updates the slots.








use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};

const TIMERFD_INO_BASE: Ino = 0x7300_0000;
const TIMERFD_INO_MASK: Ino = 0x00FF_FFFF;

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
    pub expiry_ns:    AtomicU64,
    pub interval_ns:  AtomicU64,
    pub last_read_ns: AtomicU64,
}

/// `make_timerfd_inode()` — a CharDev pseudo-inode whose `read` yields the
/// expiration count. Registered in the global table so settime/gettime reach
/// it by id. # C: O(1)
pub fn make_timerfd_inode() -> InodeRef {
    let id = NEXT_TIMERFD_ID.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(TimerfdData {
        id,
        expiry_ns:   AtomicU64::new(0),
        interval_ns: AtomicU64::new(0),
        last_read_ns: AtomicU64::new(0),
    });
    {
        let mut g = TIMERFDS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || Arc::clone(&data)); }
        else { g[id as usize] = Arc::clone(&data); }
    }
    InodeBuilder::new(TIMERFD_INO_BASE | (id as Ino & TIMERFD_INO_MASK),
        mk_mode(FileType::CharDev, 0), default_inode_ops(), Arc::new(TimerfdFileOps))
        .private(data)
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
        let expiry = d.expiry_ns.load(Ordering::Acquire);
        if expiry != 0 && monotonic_ns() >= expiry { vfs::POLL_IN } else { 0 }
    }
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = match inode.private::<TimerfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        let now = monotonic_ns();
        let expiry = d.expiry_ns.load(Ordering::Acquire);
        if expiry == 0 || now < expiry {
            // No expirations yet — Linux blocks; v1 returns EAGAIN-shape (Ok(0)).
            return Ok(0);
        }
        let interval = d.interval_ns.load(Ordering::Acquire);
        let last = d.last_read_ns.load(Ordering::Acquire);
        let count = if interval == 0 { 1 } else {
            // periodic: expirations since last read
            let base = if last >= expiry { last } else { expiry };
            ((now - base) / interval) + 1
        };
        d.last_read_ns.store(now, Ordering::Release);
        if interval == 0 { d.expiry_ns.store(0, Ordering::Release); }
        else { d.expiry_ns.store(now.saturating_add(interval), Ordering::Release); }
        buf[..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Lookup the TimerfdData bound to an fd's inode-number marker.
/// # C: O(1)
fn timerfd_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<TimerfdData>> {
    let ino = file.inode().ino();
    if (ino & 0xFF00_0000) != TIMERFD_INO_BASE { return None; }
    let id = (ino & TIMERFD_INO_MASK) as usize;
    TIMERFDS.lock().get(id).cloned()
}

/// `sys_timerfd_create(clockid, flags)`. Allocates a fresh TimerfdInode fd.
/// # C: O(N_fds)
pub fn sys_timerfd_create(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    const TFD_NONBLOCK: u64 = 0o0_004_000;
    const TFD_CLOEXEC:  u64 = 0o2_000_000;
    let flags = args.a1;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = make_timerfd_inode();
    let dentry = vfs::dcache::d_alloc_pseudo("[timerfd]", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDONLY;
    if (flags & TFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc(file) {
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
    const TFD_TIMER_ABSTIME: u64 = 1;
    let fd = args.a0 as i32;
    let flags = args.a1;
    let new = args.a2;
    let old = args.a3;
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
    if old != 0 && old < hal::USER_VA_END {
        let i = inode.interval_ns.load(Ordering::Acquire);
        let e = inode.expiry_ns.load(Ordering::Acquire);
        let remain = if e > now { e - now } else { 0 };
        let (i_s, i_n) = sched::clock::ns_to_timespec(i);
        let (r_s, r_n) = sched::clock::ns_to_timespec(remain);
        // SAFETY: old validated; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( old        as *mut u64, i_s);
            core::ptr::write_volatile((old +  8)  as *mut u64, i_n);
            core::ptr::write_volatile((old + 16)  as *mut u64, r_s);
            core::ptr::write_volatile((old + 24)  as *mut u64, r_n);
        }
    }
    if new != 0 && new < hal::USER_VA_END {
        // SAFETY: new validated; CPL=0 reads through caller's AS.
        let (is, ins, vs, vns) = unsafe {
            let a = core::ptr::read_volatile( new        as *const u64);
            let b = core::ptr::read_volatile((new +  8)  as *const u64);
            let c = core::ptr::read_volatile((new + 16)  as *const u64);
            let d = core::ptr::read_volatile((new + 24)  as *const u64);
            (a, b, c, d)
        };
        let interval = is.saturating_mul(1_000_000_000).saturating_add(ins);
        let value    = vs.saturating_mul(1_000_000_000).saturating_add(vns);
        inode.interval_ns.store(interval, Ordering::Release);
        // TFD_TIMER_ABSTIME (flags bit 0): it_value is an ABSOLUTE time against
        // the timerfd's clock (our monotonic). Without honoring it, `now+value`
        // pushes the expiry ~uptime into the future → it never fires. Go's
        // runtime timers (newer Go) + systemd arm timerfds this way, so the
        // bug livelocked every Go app (duf/glow/micro) in epoll_pwait. Relative
        // mode (flags clear) keeps `now + value`.
        let expiry = if value == 0 {
            0
        } else if (flags & TFD_TIMER_ABSTIME) != 0 {
            value
        } else {
            now.saturating_add(value)
        };
        inode.expiry_ns.store(expiry, Ordering::Release);
    }
    0
}

/// `sys_timerfd_gettime(fd, value)`. Reports remaining + interval.
/// # C: O(1)
pub fn sys_timerfd_gettime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let value = args.a1;
    if value == 0 || value >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
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
    let now = monotonic_ns();
    let i = inode.interval_ns.load(Ordering::Acquire);
    let e = inode.expiry_ns.load(Ordering::Acquire);
    let remain = if e > now { e - now } else { 0 };
    let (i_s, i_n) = sched::clock::ns_to_timespec(i);
    let (r_s, r_n) = sched::clock::ns_to_timespec(remain);
    // SAFETY: value validated; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( value        as *mut u64, i_s);
        core::ptr::write_volatile((value +  8)  as *mut u64, i_n);
        core::ptr::write_volatile((value + 16)  as *mut u64, r_s);
        core::ptr::write_volatile((value + 24)  as *mut u64, r_n);
    }
    0
}
