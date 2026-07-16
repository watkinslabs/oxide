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






#![allow(dead_code)]


use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as PerfLockClass};
use vfs::{FileOps, Inode, InodeBuilder, InodeRef, KResult, default_inode_ops, mk_mode};

mod ids {
    pub(crate) const INO_TAG: vfs::Ino = 0x5045_5246_0000_0000;
    pub(crate) const INO_ID_MASK: vfs::Ino = 0xFFFF_FFFF;
}

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

/// Per-inode perf-event state (Linux `i_private`). # C: O(1)
pub struct PerfData {
    pub state: Spinlock<PerfState, PerfLockClass>,
    pub start_ns: AtomicU64,
}

/// PerfData ino tag (high bits distinct from socket/io_uring/pipe/uffd).
static NEXT_PERF_INO: AtomicU64 = AtomicU64::new(1);

fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// `make_perf_event_inode()` — a Regular pseudo-inode whose `read` yields the
/// elapsed-ns sample. # C: O(1)
pub fn make_perf_event_inode() -> InodeRef {
    let ino = ids::INO_TAG | (NEXT_PERF_INO.fetch_add(1, Ordering::Relaxed) & ids::INO_ID_MASK);
    InodeBuilder::new(ino, mk_mode(vfs::FileType::Regular, 0),
        default_inode_ops(), Arc::new(PerfFileOps))
        .private(Arc::new(PerfData {
            state: Spinlock::new(PerfState { enabled: true, period: 0, samples: 0 }),
            start_ns: AtomicU64::new(now_ns()),
        }))
        .build()
}

/// `i_fop` for a perf-event inode. # C: O(1)
struct PerfFileOps;
impl FileOps for PerfFileOps {
    /// read returns the single u64 sample (elapsed monotonic ns
    /// since open). Repeated reads see monotonically increasing
    /// values — sufficient for `perf stat`-class probes.
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<PerfData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        let mut g = d.state.lock();
        if !g.enabled { return Ok(0); }
        let v = now_ns().saturating_sub(d.start_ns.load(Ordering::Acquire));
        g.samples = g.samples.wrapping_add(1);
        buf[..8].copy_from_slice(&v.to_le_bytes());
        Ok(8)
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(vfs::VfsError::Einval) }
}

/// `perf_event_open(attr, pid, cpu, group_fd, flags)` — slot 298.
/// # C: O(1)
pub fn sys_perf_event_open(_args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    let inode_ref = make_perf_event_inode();
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::dcache::d_alloc_pseudo("[perf_event]", inode_ref.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode_ref, dentry, OpenFlags::O_RDWR);
    match fdt.alloc_limit(file, cur.nofile_soft()) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

fn as_perf(inode: &vfs::InodeRef) -> Option<Arc<PerfData>> {
    inode.i_private().clone().downcast::<PerfData>().ok()
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
