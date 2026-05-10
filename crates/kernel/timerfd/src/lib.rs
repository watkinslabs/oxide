// timerfd surface per Linux 2.6.25. v1: TimerfdInode stores
// expiry_ns + interval_ns. read returns u64 expiration count
// (1 if expired since last read; 0 otherwise) and re-arms for
// periodic timers. settime updates the slots.






#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const TIMERFD_INO_BASE: Ino = 0x7300_0000;
const TIMERFD_INO_MASK: Ino = 0x00FF_FFFF;

/// Global timerfd table — id → Arc<TimerfdInode>. Lets settime/gettime
/// reach the inode by extracting `id` from the inode marker without
/// an Any-downcast on the trait object.
static TIMERFDS: Spinlock<Vec<Arc<TimerfdInode>>, TaskListClass>
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

pub struct TimerfdInode {
    pub id:           u32,
    pub expiry_ns:    AtomicU64,
    pub interval_ns:  AtomicU64,
    pub last_read_ns: AtomicU64,
}

impl TimerfdInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let id = NEXT_TIMERFD_ID.fetch_add(1, Ordering::Relaxed);
        let arc = Arc::new(Self {
            id,
            expiry_ns:   AtomicU64::new(0),
            interval_ns: AtomicU64::new(0),
            last_read_ns: AtomicU64::new(0),
        });
        let mut g = TIMERFDS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || Arc::clone(&arc)); }
        else { g[id as usize] = Arc::clone(&arc); }
        arc
    }
}

impl Inode for TimerfdInode {
    fn ino(&self) -> Ino { TIMERFD_INO_BASE | (self.id as Ino & TIMERFD_INO_MASK) }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let now = monotonic_ns();
        let expiry = self.expiry_ns.load(Ordering::Acquire);
        if expiry == 0 || now < expiry {
            // No expirations yet — Linux blocks; v1 returns EAGAIN-shape (Ok(0)).
            return Ok(0);
        }
        let interval = self.interval_ns.load(Ordering::Acquire);
        let last = self.last_read_ns.load(Ordering::Acquire);
        let count = if interval == 0 { 1 } else {
            // periodic: expirations since last read
            let base = if last >= expiry { last } else { expiry };
            ((now - base) / interval) + 1
        };
        self.last_read_ns.store(now, Ordering::Release);
        if interval == 0 { self.expiry_ns.store(0, Ordering::Release); }
        else { self.expiry_ns.store(now.saturating_add(interval), Ordering::Release); }
        buf[..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Lookup the TimerfdInode bound to an fd's inode-number marker.
/// # C: O(1)
fn timerfd_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<TimerfdInode>> {
    let ino = file.inode().ino();
    if (ino & 0xFF00_0000) != TIMERFD_INO_BASE { return None; }
    let id = (ino & TIMERFD_INO_MASK) as usize;
    TIMERFDS.lock().get(id).cloned()
}

/// `sys_timerfd_create(clockid, flags)`. Allocates a fresh TimerfdInode fd.
/// # C: O(N_fds)
pub fn kernel_sys_timerfd_create(_args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = TimerfdInode::new() as InodeRef;
    let dentry = Dentry::new(None, "timerfd".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_timerfd_settime(fd, flags, new, old)`. Decodes the timerfd
/// id from the file's inode marker, looks up the Arc, and writes
/// expiry_ns + interval_ns from new->{it_value, it_interval}.
/// `old` (if non-NULL) gets the previous remaining + interval.
/// # C: O(1)
pub fn kernel_sys_timerfd_settime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let _flags = args.a1;
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
        inode.expiry_ns.store(if value == 0 { 0 } else { now.saturating_add(value) }, Ordering::Release);
    }
    0
}

/// `sys_timerfd_gettime(fd, value)`. Reports remaining + interval.
/// # C: O(1)
pub fn kernel_sys_timerfd_gettime(args: &syscall::SyscallArgs) -> i64 {
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
