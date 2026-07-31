// Linux `signal_struct`'s OWN-process counters: `nvcsw`, `nivcsw`, `min_flt`,
// `maj_flt`, `inblock`, `oublock`. Distinct from `child_acct`'s `c*` set,
// which holds what REAPED CHILDREN cost.
//
// Linux answers `RUSAGE_SELF` as `signal_struct`'s counters (the dead threads'
// residue) PLUS a walk of every live thread. We charge the group counter at
// the same instant as the per-task counter, so the group total already covers
// live and dead threads alike and `RUSAGE_SELF` needs no thread walk. Same
// shape `ThreadGroup::charge_cpu` already uses for process CPU time, and it
// keeps one owner per question: the per-task atomics answer `RUSAGE_THREAD`,
// this answers `RUSAGE_SELF`. Neither is derived from the other, so they
// cannot drift; a thread exiting removes nothing from either.
//
// Byte counters are stored as BYTES and converted to 512-byte block-I/O
// operations only at the `struct rusage` boundary, matching Linux's
// `ioac.read_bytes >> 9`.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::rusage::{bytes_to_blocks, Rusage};

/// Whole-process fault / block-I/O / context-switch counters.
#[derive(Default)]
pub struct GroupAcct {
    min_flt:        AtomicU64,
    maj_flt:        AtomicU64,
    io_read_bytes:  AtomicU64,
    io_write_bytes: AtomicU64,
    nvcsw:          AtomicU64,
    nivcsw:         AtomicU64,
    /// Peak resident set of this process, in PAGES (Linux `signal_struct::maxrss`
    /// is likewise a page count; `ru_maxrss` scales it to KiB).
    hiwater_rss_pages: AtomicU64,
}

impl GroupAcct {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            min_flt:       AtomicU64::new(0), maj_flt:        AtomicU64::new(0),
            io_read_bytes: AtomicU64::new(0), io_write_bytes: AtomicU64::new(0),
            nvcsw:         AtomicU64::new(0), nivcsw:         AtomicU64::new(0),
            hiwater_rss_pages: AtomicU64::new(0),
        }
    }

    /// # C: O(1)
    /// # Ctx: fault
    pub fn charge_fault(&self, major: bool) {
        if major { self.maj_flt.fetch_add(1, Ordering::Relaxed); }
        else     { self.min_flt.fetch_add(1, Ordering::Relaxed); }
    }

    /// # C: O(1)
    pub fn charge_io_read(&self, bytes: u64) { self.io_read_bytes.fetch_add(bytes, Ordering::Relaxed); }

    /// # C: O(1)
    pub fn charge_io_write(&self, bytes: u64) { self.io_write_bytes.fetch_add(bytes, Ordering::Relaxed); }

    /// `voluntary` = the task gave the CPU up by blocking (Linux `nvcsw`);
    /// otherwise it was preempted while still runnable (`nivcsw`). # C: O(1)
    pub fn charge_ctxsw(&self, voluntary: bool) {
        if voluntary { self.nvcsw.fetch_add(1, Ordering::Relaxed); }
        else         { self.nivcsw.fetch_add(1, Ordering::Relaxed); }
    }

    /// Raise the process's resident-set high-water mark. Linux keeps the live
    /// peak on the `mm` and latches it here as each `mm` is dropped, so a
    /// process that execve's or whose thread exits does not lose the peak.
    /// # C: O(1)
    pub fn raise_hiwater_rss(&self, pages: u64) { self.hiwater_rss_pages.fetch_max(pages, Ordering::Relaxed); }

    /// Latched peak resident pages. The CURRENT `mm`'s live peak is folded in
    /// by the `getrusage` producer, exactly as Linux's `setmax_mm_hiwater_rss`
    /// does after reading `signal_struct::maxrss`. # C: O(1)
    pub fn hiwater_rss_pages(&self) -> u64 { self.hiwater_rss_pages.load(Ordering::Relaxed) }

    /// The non-CPU half of `RUSAGE_SELF`. CPU time comes from
    /// `ThreadGroup::cpu_sample`, and `maxrss_kb` from the caller folding
    /// `hiwater_rss_pages` with the live `mm`. # C: O(1)
    pub fn snapshot(&self) -> Rusage {
        Rusage {
            utime_ns: 0, stime_ns: 0, maxrss_kb: 0,
            minflt:  self.min_flt.load(Ordering::Relaxed),
            majflt:  self.maj_flt.load(Ordering::Relaxed),
            inblock: bytes_to_blocks(self.io_read_bytes.load(Ordering::Relaxed)),
            oublock: bytes_to_blocks(self.io_write_bytes.load(Ordering::Relaxed)),
            nvcsw:   self.nvcsw.load(Ordering::Relaxed),
            nivcsw:  self.nivcsw.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faults_and_switches_land_in_the_linux_named_counter() {
        let g = GroupAcct::new();
        g.charge_fault(false); g.charge_fault(false); g.charge_fault(true);
        g.charge_ctxsw(true);  g.charge_ctxsw(false); g.charge_ctxsw(false);
        let s = g.snapshot();
        assert_eq!((s.minflt, s.majflt), (2, 1));
        assert_eq!((s.nvcsw, s.nivcsw), (1, 2));
    }

    #[test]
    fn block_io_is_charged_in_bytes_and_reported_in_512_byte_sectors() {
        let g = GroupAcct::new();
        g.charge_io_read(4096); g.charge_io_read(511);
        g.charge_io_write(1024);
        let s = g.snapshot();
        // 4607 bytes >> 9 == 8; a sub-sector remainder never rounds up.
        assert_eq!(s.inblock, 8);
        assert_eq!(s.oublock, 2);
    }

    #[test]
    fn the_high_water_mark_only_ever_rises() {
        let g = GroupAcct::new();
        g.raise_hiwater_rss(40);
        g.raise_hiwater_rss(12);
        assert_eq!(g.hiwater_rss_pages(), 40);
        g.raise_hiwater_rss(41);
        assert_eq!(g.hiwater_rss_pages(), 41);
    }

    #[test]
    fn cpu_time_and_maxrss_are_not_this_owners_to_answer() {
        let g = GroupAcct::new();
        g.charge_fault(true);
        let s = g.snapshot();
        assert_eq!((s.utime_ns, s.stime_ns, s.maxrss_kb), (0, 0, 0));
    }
}
