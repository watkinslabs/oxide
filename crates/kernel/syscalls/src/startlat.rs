// debug-startlat: names WHERE a service's start-up latency goes.
//
// `debug-syscost` answers "are our syscalls slow on average"; it cannot answer
// "which ONE call ate 40 of the 106 seconds between `Starting foo.service` and
// the daemon's first log line". This does: it times every dispatch and prints a
// record ONLY when a single call exceeded `SLOW_NS`, with the caller's tid, tgid
// and exe path. Volume is bounded by construction (a healthy boot has a handful
// of legitimately-long calls: `ppoll`, `wait4`, `accept`), so it can ride a
// live-gnome boot without the instrument changing the result (B1474).
//
// Diagnostic only — off unless `--features debug-startlat` is passed.
#![cfg(all(target_os = "oxide-kernel", feature = "debug-startlat"))]

use core::sync::atomic::{AtomicU64, Ordering};

/// Report threshold. Below this a call is not a start-up-latency suspect.
const SLOW_NS: u64 = 50_000_000;
/// Hard cap on emitted records, so a pathological boot cannot turn the probe
/// into the serial flood it exists to avoid.
const MAX_RECORDS: u64 = 6000;
const NS_PER_MS: u64 = 1_000_000;

static RECORDS: AtomicU64 = AtomicU64::new(0);

/// Monotonic ns timestamp. # C: O(1)
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Pre-dispatch `(wall_ns, task on-CPU ns)`. The second half is the
/// discriminator: `sum_exec_runtime_ns` advances only while the task is on a
/// CPU, so a long call whose on-CPU delta matches its wall time is real kernel
/// work, and one whose delta is ~0 was waiting (I/O, runqueue, or a genuine
/// block). Same source `debug-syscost` uses. # C: O(1)
#[inline]
pub fn start() -> (u64, u64) {
    let cpu = sched::live::current()
        .map(|t| t.sum_exec_runtime_ns.load(Ordering::Relaxed)).unwrap_or(0);
    (now_ns(), cpu)
}

/// Emit a record when this one call exceeded `SLOW_NS`.
/// # C: O(1) on the fast path; O(len(exe)) on a report
#[inline]
pub fn record(nr: u64, start: (u64, u64), rv: i64) {
    let (t0, cpu0) = start;
    let dt = now_ns().saturating_sub(t0);
    if dt < SLOW_NS { return; }
    if RECORDS.fetch_add(1, Ordering::Relaxed) >= MAX_RECORDS { return; }
    let cur = match sched::live::current() { Some(c) => c, None => return };
    klog::write_raw(b"[SLOWSYS nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" ms=");
    klog::write_dec_u64(dt / NS_PER_MS);
    // `sum_exec_runtime_ns` only advances when the task is switched OFF a CPU,
    // so an unchanged counter means the call never left the CPU and its whole
    // wall time was kernel work; a changed one means it blocked or was
    // preempted, and `cpu_ms` is what it actually ran. Same discriminator
    // `debug-syscost` uses.
    let cpu_ns = cur.sum_exec_runtime_ns.load(Ordering::Relaxed).saturating_sub(cpu0);
    klog::write_raw(b" left_cpu=");
    klog::write_dec_u64(if cpu_ns == 0 { 0 } else { 1 });
    klog::write_raw(b" cpu_ms=");
    klog::write_dec_u64(cpu_ns / NS_PER_MS);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(cur.tid as u64);
    klog::write_raw(b" tgid=");
    klog::write_dec_u64(cur.tgid.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" rv=");
    if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
    else { klog::write_dec_u64(rv as u64); }
    klog::write_raw(b" exe=");
    cur.with_exe_path(|p| klog::write_raw(p.unwrap_or("?").as_bytes()));
    klog::write_raw(b"]\n");
}
