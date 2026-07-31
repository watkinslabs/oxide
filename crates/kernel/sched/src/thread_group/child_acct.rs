// Linux `signal_struct`'s c* counters: everything a PROCESS has accumulated
// from its reaped children. `getrusage(RUSAGE_CHILDREN)` and `times(2)`'s
// `tms_cutime`/`tms_cstime` read them, and a reaped child folds its own set in
// so a whole subtree's cost reaches the ancestor that measures it.
//
// Process-wide, not per-thread, for the same reason `rlimits`/`pgid` are: any
// thread of a process may reap a child, and every sibling must then see that
// child's cost. Held per-`Task`, a `time` builtin running on one thread
// reported zero for a child another thread reaped.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::rusage::Rusage;

/// Accumulated resource use of every child this process has reaped.
#[derive(Default)]
pub struct ChildAcct {
    utime_ns:  AtomicU64,
    stime_ns:  AtomicU64,
    maxrss_kb: AtomicU64,
    minflt:    AtomicU64,
    majflt:    AtomicU64,
    inblock:   AtomicU64,
    oublock:   AtomicU64,
    nvcsw:     AtomicU64,
    nivcsw:    AtomicU64,
}

impl ChildAcct {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            utime_ns:  AtomicU64::new(0), stime_ns: AtomicU64::new(0),
            maxrss_kb: AtomicU64::new(0),
            minflt:    AtomicU64::new(0), majflt:   AtomicU64::new(0),
            inblock:   AtomicU64::new(0), oublock:  AtomicU64::new(0),
            nvcsw:     AtomicU64::new(0), nivcsw:   AtomicU64::new(0),
        }
    }

    /// Fold one departing child's `RUSAGE_BOTH` (its own counters plus those it
    /// had already accumulated from ITS children) into this process's totals.
    /// Every counter sums; the resident-set high-water mark takes the max.
    /// # C: O(1)
    pub fn accrue(&self, r: Rusage) {
        self.utime_ns.fetch_add(r.utime_ns, Ordering::AcqRel);
        self.stime_ns.fetch_add(r.stime_ns, Ordering::AcqRel);
        self.minflt.fetch_add(r.minflt, Ordering::Relaxed);
        self.majflt.fetch_add(r.majflt, Ordering::Relaxed);
        self.inblock.fetch_add(r.inblock, Ordering::Relaxed);
        self.oublock.fetch_add(r.oublock, Ordering::Relaxed);
        self.nvcsw.fetch_add(r.nvcsw, Ordering::Relaxed);
        self.nivcsw.fetch_add(r.nivcsw, Ordering::Relaxed);
        self.maxrss_kb.fetch_max(r.maxrss_kb, Ordering::Relaxed);
    }

    /// The `getrusage(RUSAGE_CHILDREN)` answer. # C: O(1)
    pub fn snapshot(&self) -> Rusage {
        Rusage {
            utime_ns:  self.utime_ns.load(Ordering::Acquire),
            stime_ns:  self.stime_ns.load(Ordering::Acquire),
            maxrss_kb: self.maxrss_kb.load(Ordering::Relaxed),
            minflt:    self.minflt.load(Ordering::Relaxed),
            majflt:    self.majflt.load(Ordering::Relaxed),
            inblock:   self.inblock.load(Ordering::Relaxed),
            oublock:   self.oublock.load(Ordering::Relaxed),
            nvcsw:     self.nvcsw.load(Ordering::Relaxed),
            nivcsw:    self.nivcsw.load(Ordering::Relaxed),
        }
    }

    /// `times(2)` `tms_cutime` / `tms_cstime`, in ns. # C: O(1)
    pub fn cpu_ns(&self) -> (u64, u64) {
        (self.utime_ns.load(Ordering::Acquire), self.stime_ns.load(Ordering::Acquire))
    }
}
