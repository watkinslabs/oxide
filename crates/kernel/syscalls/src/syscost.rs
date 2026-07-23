// debug-syscost: non-distorting per-syscall cumulative wall-time profiler for a
// single target process (polkitd), to pin WHERE its 45s init wall-clock goes
// (ppoll/futex wait vs read I/O vs mmap vs nanosleep vs compute). Atomic adds
// per nr; NO per-call klog — dumps a top-N histogram every DUMP_EVERY calls.
// Wall-time per syscall includes blocking, which is the point: a wait-bound
// process shows its time in the syscall it blocks in.
#![cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]

use core::sync::atomic::{AtomicU64, Ordering};

const N: usize = 460; // covers x86_64 nr space we use
static COST_NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static COST_CNT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static CALLS: AtomicU64 = AtomicU64::new(0);
const DUMP_EVERY: u64 = 800;

/// True iff the current task's exe is polkitd (bounded to one process).
fn is_target() -> bool {
    sched::live::current()
        .map(|c| c.with_exe_path(|p| p.map(|s| s.contains("polkit")).unwrap_or(false)))
        .unwrap_or(false)
}

/// Read a monotonic ns timestamp. # C: O(1)
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Snapshot before dispatch. Returns (start_ns, is_target) so `record` can skip
/// the timestamp read entirely for non-target tasks (zero cost off-target).
#[inline]
pub fn start() -> Option<u64> {
    if is_target() { Some(now_ns()) } else { None }
}

/// Accumulate `now - start` into COST_NS[nr]; dump the histogram every
/// DUMP_EVERY target calls.
#[inline]
pub fn record(nr: u64, start: Option<u64>) {
    let s = match start { Some(s) => s, None => return };
    let nr = nr as usize;
    if nr >= N { return; }
    let dt = now_ns().saturating_sub(s);
    COST_NS[nr].fetch_add(dt, Ordering::Relaxed);
    COST_CNT[nr].fetch_add(1, Ordering::Relaxed);
    if CALLS.fetch_add(1, Ordering::Relaxed) + 1 >= DUMP_EVERY {
        CALLS.store(0, Ordering::Relaxed);
        dump();
    }
}

/// Emit the top-14 syscalls by cumulative wall-time for polkitd.
fn dump() {
    // Simple selection of the 14 largest by total ns.
    let mut idx: [usize; 14] = [usize::MAX; 14];
    let mut val: [u64; 14] = [0; 14];
    for i in 0..N {
        let t = COST_NS[i].load(Ordering::Relaxed);
        if t == 0 { continue; }
        // insert into the top list if larger than the current smallest
        let mut min_j = 0;
        for j in 1..14 { if val[j] < val[min_j] { min_j = j; } }
        if t > val[min_j] { val[min_j] = t; idx[min_j] = i; }
    }
    klog::write_raw(b"[SYSCOST polkitd top-by-total-ms]\n");
    // print in descending order (selection sort on the 14)
    for _ in 0..14 {
        let mut best = 0;
        for j in 1..14 { if val[j] > val[best] { best = j; } }
        if val[best] == 0 { break; }
        let i = idx[best];
        let cnt = COST_CNT[i].load(Ordering::Relaxed);
        klog::write_raw(b"  nr=");   klog::write_dec_u64(i as u64);
        klog::write_raw(b" total_ms="); klog::write_dec_u64(val[best] / 1_000_000);
        klog::write_raw(b" cnt=");   klog::write_dec_u64(cnt);
        klog::write_raw(b" avg_us=");
        klog::write_dec_u64(if cnt > 0 { (val[best] / 1000) / cnt } else { 0 });
        klog::write_raw(b"\n");
        val[best] = 0;
    }
}
