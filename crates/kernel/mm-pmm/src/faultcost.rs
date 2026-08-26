// Page-fault path profiler (`debug-faultcost`), the fault-side twin of the
// syscall profiler.
//
// A syscall profile cannot see a fault: demand paging, COW and file-backed
// fill run on the architecture's fault vector, not through the syscall
// dispatcher. Process start-up is dominated by faulting in an executable and
// its libraries, so a boot can be fault-bound while every syscall looks cheap.
//
// Counts and totals only — no per-address history — so the probe itself stays
// two clock reads and two relaxed adds.

use core::sync::atomic::{AtomicU64, Ordering};

/// Dump cadence: faults between reports.
const DUMP_EVERY: u64 = 50_000;
const NS_PER_MS: u64 = 1_000_000;

static FAULTS:      AtomicU64 = AtomicU64::new(0);
static SINCE_DUMP:  AtomicU64 = AtomicU64::new(0);
static RESOLVED_NS: AtomicU64 = AtomicU64::new(0);
static RESOLVED:    AtomicU64 = AtomicU64::new(0);
static REJECTED_NS: AtomicU64 = AtomicU64::new(0);
static REJECTED:    AtomicU64 = AtomicU64::new(0);

/// Four architectural fault classes, indexed `(present << 1) | write`:
/// 0 read-not-present, 1 write-not-present, 2 read-protection, 3 write-protection.
const CLASSES: usize = 4;
static CLASS_NS:  [AtomicU64; CLASSES] = [const { AtomicU64::new(0) }; CLASSES];
static CLASS_CNT: [AtomicU64; CLASSES] = [const { AtomicU64::new(0) }; CLASSES];
const CLASS_NAME: [&[u8]; CLASSES] = [b"rd-absent", b"wr-absent", b"rd-prot", b"wr-prot"];

static FILL_NS:  AtomicU64 = AtomicU64::new(0);
static FILL_CNT: AtomicU64 = AtomicU64::new(0);

/// Record one filesystem page-cache fill (the coalesced device read a fault
/// miss triggers). Called by the filesystem so the fault profile can separate
/// "the page had to be read" from "the page was already cached and the fault
/// path itself is what costs". # C: O(1)
#[inline]
pub fn note_fill(ns: u64) {
    FILL_NS.fetch_add(ns, Ordering::Relaxed);
    FILL_CNT.fetch_add(1, Ordering::Relaxed);
}

/// # C: O(1)
pub fn stamp() -> u64 { now_ns() }

/// # C: O(1)
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Entry stamp. # C: O(1)
#[inline]
pub fn start() -> u64 { now_ns() }

/// Close one fault and dump on the cadence. `handled` separates a fault the
/// address space resolved from one that falls through to the signal path.
/// # C: O(1) amortised
#[inline]
pub fn record(t0: u64, handled: bool, class: usize) {
    let dt = now_ns().saturating_sub(t0);
    if class < CLASSES {
        CLASS_NS[class].fetch_add(dt, Ordering::Relaxed);
        CLASS_CNT[class].fetch_add(1, Ordering::Relaxed);
    }
    FAULTS.fetch_add(1, Ordering::Relaxed);
    if handled {
        RESOLVED.fetch_add(1, Ordering::Relaxed);
        RESOLVED_NS.fetch_add(dt, Ordering::Relaxed);
    } else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        REJECTED_NS.fetch_add(dt, Ordering::Relaxed);
    }
    if SINCE_DUMP.fetch_add(1, Ordering::Relaxed) + 1 >= DUMP_EVERY {
        SINCE_DUMP.store(0, Ordering::Relaxed);
        dump();
    }
}

/// Emit the running totals. # C: O(1)
fn dump() {
    let rc = RESOLVED.load(Ordering::Relaxed);
    let rn = RESOLVED_NS.load(Ordering::Relaxed);
    let xc = REJECTED.load(Ordering::Relaxed);
    let xn = REJECTED_NS.load(Ordering::Relaxed);
    klog::write_raw(b"[FAULTCOST] resolved=");   klog::write_dec_u64(rc);
    klog::write_raw(b" resolved_ms=");           klog::write_dec_u64(rn / NS_PER_MS);
    klog::write_raw(b" resolved_avg_ns=");       klog::write_dec_u64(if rc > 0 { rn / rc } else { 0 });
    klog::write_raw(b" | rejected=");            klog::write_dec_u64(xc);
    klog::write_raw(b" rejected_ms=");           klog::write_dec_u64(xn / NS_PER_MS);
    klog::write_raw(b" rejected_avg_ns=");       klog::write_dec_u64(if xc > 0 { xn / xc } else { 0 });
    klog::write_raw(b"\n");
    let fc = FILL_CNT.load(Ordering::Relaxed);
    if fc > 0 {
        let fns = FILL_NS.load(Ordering::Relaxed);
        klog::write_raw(b"  fs-fill cnt=");   klog::write_dec_u64(fc);
        klog::write_raw(b" ms=");             klog::write_dec_u64(fns / NS_PER_MS);
        klog::write_raw(b" avg_ns=");         klog::write_dec_u64(fns / fc);
        klog::write_raw(b"\n");
    }
    for i in 0..CLASSES {
        let c = CLASS_CNT[i].load(Ordering::Relaxed);
        if c == 0 { continue; }
        let n = CLASS_NS[i].load(Ordering::Relaxed);
        klog::write_raw(b"  ");           klog::write_raw(CLASS_NAME[i]);
        klog::write_raw(b" cnt=");        klog::write_dec_u64(c);
        klog::write_raw(b" ms=");         klog::write_dec_u64(n / NS_PER_MS);
        klog::write_raw(b" avg_ns=");     klog::write_dec_u64(n / c);
        klog::write_raw(b"\n");
    }
}
