// perf_event_open per `27`/`37` — first cut for v2 phase 30.
//
// Linux perf_event_open returns an fd whose read(fd, buf, len)
// drains sample data and whose ioctl tweaks counter state. v1
// implementation:
//   * perf_event_open(attr, pid, cpu, group_fd, flags) returns an fd
//     backed by a PerfEventInode.
//   * read(fd) returns one u64 sample = current rdtsc (x86_64) or
//     the monotonic-ns clock (aarch64). Programs that probe perf
//     counters (perf stat, top, ps) get monotonically increasing
//     samples instead of -ENOSYS.
//   * ioctl PERF_EVENT_IOC_ENABLE / DISABLE / RESET / REFRESH admit.
//   * mmap on the fd is not yet wired (perf ring buffer requires
//     MAP_SHARED page-cache substrate); falls through to the
//     existing mmap path which gives an anonymous mapping that
//     userspace can still read into.






#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as PerfLockClass};

const PERF_EVENT_IOC_ENABLE:  u64 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;
const PERF_EVENT_IOC_REFRESH: u64 = 0x2402;
const PERF_EVENT_IOC_RESET:   u64 = 0x2403;
const PERF_EVENT_IOC_PERIOD:  u64 = 0x40082404;

pub struct PerfState {
    pub enabled: bool,
    pub period:  u64,
    pub samples: u64,
}

pub struct PerfEventInode {
    pub state: Spinlock<PerfState, PerfLockClass>,
    pub start_ns: AtomicU64,
}

impl PerfEventInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        use hal::TimerOps;
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let now: u64 = 0;
        Arc::new(Self {
            state: Spinlock::new(PerfState { enabled: true, period: 0, samples: 0 }),
            start_ns: AtomicU64::new(now),
        })
    }

    fn current_sample(&self) -> u64 {
        use hal::TimerOps;
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let now: u64 = 0;
        now.saturating_sub(self.start_ns.load(Ordering::Acquire))
    }
}

impl vfs::Inode for PerfEventInode {
    fn ino(&self) -> vfs::Ino {
        // High-bits tag distinct from socket / io_uring / pipe / uffd inodes.
        0x5045_5246_0000_0000u64 | (self as *const _ as u64 & 0xFFFF_FFFF) as vfs::Ino
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    /// read returns the single u64 sample (elapsed monotonic ns
    /// since open). Repeated reads see monotonically increasing
    /// values — sufficient for `perf stat`-class probes.
    fn read(&self, _o: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let mut g = self.state.lock();
        if !g.enabled { return Ok(0); }
        let v = self.current_sample();
        g.samples = g.samples.wrapping_add(1);
        buf[..8].copy_from_slice(&v.to_le_bytes());
        Ok(8)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// `perf_event_open(attr, pid, cpu, group_fd, flags)` — slot 298.
/// # C: O(1)
pub fn kernel_sys_perf_event_open(_args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let inode = PerfEventInode::new();
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode_ref: vfs::InodeRef = inode as vfs::InodeRef;
    let dentry = Dentry::new(None, "[perf]".to_string(), inode_ref.clone());
    let file = File::new(inode_ref, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

fn as_perf(inode: &vfs::InodeRef) -> Option<Arc<PerfEventInode>> {
    if (inode.ino() & 0xFFFF_FFFF_0000_0000) != 0x5045_5246_0000_0000 {
        return None;
    }
    let raw = Arc::into_raw(inode.clone());
    // SAFETY: ino tag check above confirms PerfEventInode; Arc::clone bumped refcount before into_raw, from_raw consumes balanced count.
    Some(unsafe { Arc::from_raw(raw as *const PerfEventInode) })
}

/// ioctl on a perf fd. Routes from the generic ioctl dispatcher.
/// # C: O(1)
pub fn handle_perf_ioctl(inode: &vfs::InodeRef, req: u64, _arg: u64) -> i64 {
    let perf = match as_perf(inode) { Some(p) => p, None => return -(syscall::errno::Errno::Enotty.as_i32() as i64) };
    let mut g = perf.state.lock();
    match req {
        PERF_EVENT_IOC_ENABLE  => { g.enabled = true;  0 }
        PERF_EVENT_IOC_DISABLE => { g.enabled = false; 0 }
        PERF_EVENT_IOC_RESET   => { g.samples = 0;     0 }
        PERF_EVENT_IOC_REFRESH => 0,
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    }
}
