// Per-phase timing inside a syscall (`debug-syscost`).
//
// The kernel-wide profile says which syscall costs the most; it cannot say
// which part of one does. Three attempts to answer that by reading the code
// picked the wrong part each time, so the answer is measured here instead.
//
// A phase is a named span a syscall stamps around a step it wants attributed.
// Spans of the same syscall must not overlap; nesting one inside another
// double-counts the inner span's time in the outer, which is exactly what the
// report should show for a step that contains another.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

const NS_PER_MS: u64 = 1_000_000;

/// Named phases. Kept as a flat list rather than per-syscall tables: the set is
/// small, and a shared list makes two syscalls that share a step (a path walk,
/// say) comparable in one column.
pub const PH_GETNAME: usize = 0;
pub const PH_RESOLVE: usize = 1;
pub const PH_OPEN: usize = 2;
pub const PH_INSTALL: usize = 3;
pub const PH_GETATTR: usize = 4;
pub const PH_STAT_OUT: usize = 5;
pub const PH_SEND_IMPORT: usize = 6;
pub const PH_SEND_PREPARE: usize = 7;
pub const PH_SEND_PAYLOAD: usize = 8;
pub const PH_SEND_TRANSPORT: usize = 9;
const PHASES: usize = 10;
const NAME: [&[u8]; PHASES] =
    [b"getname", b"resolve", b"open", b"install-fd", b"getattr", b"stat-writeback",
     b"send-import", b"send-prepare", b"send-payload", b"send-transport"];

static NS:  [AtomicU64; PHASES] = [const { AtomicU64::new(0) }; PHASES];
static CNT: [AtomicU64; PHASES] = [const { AtomicU64::new(0) }; PHASES];
/// Spans that slept, kept apart from the rest. A phase that waits on the
/// device is not expensive code — charging its wall time to the path walk said
/// `resolve` cost 57 us a call while the whole syscall averaged 9.9 us on CPU.
static BLK_NS:  [AtomicU64; PHASES] = [const { AtomicU64::new(0) }; PHASES];
static BLK_CNT: [AtomicU64; PHASES] = [const { AtomicU64::new(0) }; PHASES];

/// # C: O(1)
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Scoped stamp: the span runs from construction to drop, so an early return
/// out of the middle of a phase still records it.
pub struct Phase(usize, u64, u64);

/// This task's accumulated on-CPU time, or 0 with no current task. A change
/// across the span means the span slept. # C: O(1)
fn exec_ns() -> u64 {
    match sched::live::current() {
        Some(t) => t.sum_exec_runtime_ns.load(Ordering::Relaxed),
        None => 0,
    }
}

impl Phase {
    /// # C: O(1)
    #[inline]
    pub fn start(which: usize) -> Self { Phase(which, now_ns(), exec_ns()) }
}

impl Drop for Phase {
    fn drop(&mut self) {
        let dt = now_ns().saturating_sub(self.1);
        if self.0 >= PHASES { return; }
        if exec_ns() == self.2 {
            NS[self.0].fetch_add(dt, Ordering::Relaxed);
            CNT[self.0].fetch_add(1, Ordering::Relaxed);
        } else {
            BLK_NS[self.0].fetch_add(dt, Ordering::Relaxed);
            BLK_CNT[self.0].fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Emit the phase table beside the per-syscall one. # C: O(PHASES)
pub fn dump() {
    for i in 0..PHASES {
        let c = CNT[i].load(Ordering::Relaxed);
        if c == 0 && BLK_CNT[i].load(Ordering::Relaxed) == 0 { continue; }
        if c == 0 { continue; }
        let n = NS[i].load(Ordering::Relaxed);
        klog::write_raw(b"  phase ");    klog::write_raw(NAME[i]);
        klog::write_raw(b" cnt=");       klog::write_dec_u64(c);
        klog::write_raw(b" ms=");        klog::write_dec_u64(n / NS_PER_MS);
        klog::write_raw(b" avg_ns=");    klog::write_dec_u64(n / c);
        let bc = BLK_CNT[i].load(Ordering::Relaxed);
        if bc != 0 {
            let bn = BLK_NS[i].load(Ordering::Relaxed);
            klog::write_raw(b" | slept=");   klog::write_dec_u64(bc);
            klog::write_raw(b" ms=");        klog::write_dec_u64(bn / NS_PER_MS);
            klog::write_raw(b" avg_us=");    klog::write_dec_u64((bn / bc) / 1000);
        }
        klog::write_raw(b"\n");
    }
}
