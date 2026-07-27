// debug-syscost: per-syscall profiler that separates KERNEL PATH CPU cost from
// BLOCKING wait, kernel-wide (every task, not one process).
//
// Wall-time alone cannot answer "are our syscalls slow?": a `ppoll` that sleeps
// 5s and a `getpid` that burns 5s of CPU both read as "5s in a syscall". The
// discriminator is `sum_exec_runtime_ns`, which advances ONLY when the task is
// switched off-CPU (`schedule/switch.rs` `update_curr`). Unchanged across
// dispatch => the task never left the CPU => elapsed wall IS on-CPU kernel time.
// Changed => the call blocked or was preempted, and its wall time is off-CPU.
//
// So COST_CPU_* is a hard lower bound on real kernel work, uncontaminated by
// waiting, and COST_BLK_* is the wait. `nr=39 getpid` showing a large
// cpu_avg_ns is a kernel-path defect; a syscall that cannot block showing any
// blk_cnt indicts preemption instead.
#![cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]

use core::sync::atomic::{AtomicU64, Ordering};

/// x86_64 nr space we use; aarch64 nrs also land below this.
const N: usize = 460;
/// Dump cadence, in recorded calls. Large: this profiles every task, so a small
/// cadence would drown the log and distort what it measures.
const DUMP_EVERY: u64 = 200_000;
/// Rows per histogram dump.
const TOP_N: usize = 16;
const NS_PER_US: u64 = 1_000;
const NS_PER_MS: u64 = 1_000_000;

/// On-CPU ns for calls that never context-switched.
static COST_CPU_NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static COST_CPU_CNT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
/// Wall ns for calls that did switch (blocked or were preempted).
static COST_BLK_NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static COST_BLK_CNT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static CALLS: AtomicU64 = AtomicU64::new(0);

/// Monotonic ns timestamp. # C: O(1)
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Pre-dispatch snapshot: (start_ns, sum_exec_runtime_ns). `None` when there is
/// no current task (early boot), so `record` stays a single branch.
/// # C: O(1)
#[inline]
pub fn start() -> Option<(u64, u64)> {
    let t = sched::live::current()?;
    Some((now_ns(), t.sum_exec_runtime_ns.load(Ordering::Relaxed)))
}

/// Bucket the call by whether it left the CPU, then dump every `DUMP_EVERY`.
/// # C: O(1) amortised; O(N*TOP_N) on a dump
#[inline]
pub fn record(nr: u64, start: Option<(u64, u64)>) {
    let (t0, exec0) = match start { Some(s) => s, None => return };
    let nr = nr as usize;
    if nr >= N { return; }
    let dt = now_ns().saturating_sub(t0);
    // Re-read from the CURRENT task: after a switch we are back on the same
    // task, so this is the same counter, advanced by the off-CPU accounting.
    let exec1 = match sched::live::current() {
        Some(t) => t.sum_exec_runtime_ns.load(Ordering::Relaxed),
        None => return,
    };
    if exec1 == exec0 {
        COST_CPU_NS[nr].fetch_add(dt, Ordering::Relaxed);
        COST_CPU_CNT[nr].fetch_add(1, Ordering::Relaxed);
    } else {
        COST_BLK_NS[nr].fetch_add(dt, Ordering::Relaxed);
        COST_BLK_CNT[nr].fetch_add(1, Ordering::Relaxed);
    }
    if CALLS.fetch_add(1, Ordering::Relaxed) + 1 >= DUMP_EVERY {
        CALLS.store(0, Ordering::Relaxed);
        dump();
    }
}

/// Sum a counter array. # C: O(N)
fn total(a: &[AtomicU64; N]) -> u64 {
    let mut s = 0u64;
    for e in a.iter() { s = s.saturating_add(e.load(Ordering::Relaxed)); }
    s
}

/// Emit one histogram row. # C: O(1)
fn row(nr: usize) {
    let ccnt = COST_CPU_CNT[nr].load(Ordering::Relaxed);
    let cns  = COST_CPU_NS[nr].load(Ordering::Relaxed);
    let bcnt = COST_BLK_CNT[nr].load(Ordering::Relaxed);
    let bns  = COST_BLK_NS[nr].load(Ordering::Relaxed);
    klog::write_raw(b"  nr=");        klog::write_dec_u64(nr as u64);
    klog::write_raw(b" cpu_cnt=");    klog::write_dec_u64(ccnt);
    klog::write_raw(b" cpu_ms=");     klog::write_dec_u64(cns / NS_PER_MS);
    klog::write_raw(b" cpu_avg_ns="); klog::write_dec_u64(if ccnt > 0 { cns / ccnt } else { 0 });
    klog::write_raw(b" blk_cnt=");    klog::write_dec_u64(bcnt);
    klog::write_raw(b" blk_ms=");     klog::write_dec_u64(bns / NS_PER_MS);
    klog::write_raw(b" blk_avg_us="); klog::write_dec_u64(if bcnt > 0 { (bns / bcnt) / NS_PER_US } else { 0 });
    klog::write_raw(b"\n");
}

/// Top-`TOP_N` syscalls by cumulative ON-CPU ns, plus the kernel-wide averages
/// that settle whether per-syscall path cost is the boot-time problem.
fn dump() {
    let cpu_total = total(&COST_CPU_NS);
    let cpu_calls = total(&COST_CPU_CNT);
    let blk_total = total(&COST_BLK_NS);
    let blk_calls = total(&COST_BLK_CNT);
    klog::write_raw(b"[SYSCOST] all-tasks cpu_calls=");
    klog::write_dec_u64(cpu_calls);
    klog::write_raw(b" cpu_total_ms=");  klog::write_dec_u64(cpu_total / NS_PER_MS);
    klog::write_raw(b" cpu_avg_ns=");
    klog::write_dec_u64(if cpu_calls > 0 { cpu_total / cpu_calls } else { 0 });
    klog::write_raw(b" | blk_calls=");   klog::write_dec_u64(blk_calls);
    klog::write_raw(b" blk_total_ms=");  klog::write_dec_u64(blk_total / NS_PER_MS);
    klog::write_raw(b"\n");
    // Selection of the TOP_N largest by on-CPU total, then emitted descending.
    let mut idx: [usize; TOP_N] = [usize::MAX; TOP_N];
    let mut val: [u64; TOP_N] = [0; TOP_N];
    for i in 0..N {
        let t = COST_CPU_NS[i].load(Ordering::Relaxed);
        if t == 0 { continue; }
        let mut min_j = 0;
        for j in 1..TOP_N { if val[j] < val[min_j] { min_j = j; } }
        if t > val[min_j] { val[min_j] = t; idx[min_j] = i; }
    }
    for _ in 0..TOP_N {
        let mut best = 0;
        for j in 1..TOP_N { if val[j] > val[best] { best = j; } }
        if val[best] == 0 { break; }
        row(idx[best]);
        val[best] = 0;
    }
}
