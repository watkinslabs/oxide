// Program run statistics and the descriptor-held global collection switch.

use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

static ENABLED: AtomicI32 = AtomicI32::new(0);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub run_time_ns: u64,
    pub run_cnt: u64,
}

/// Program-owned count and elapsed-time total. Each word is atomic because
/// runs may arrive from hard-IRQ as well as task context.
pub struct ProgStats {
    run_time_ns: AtomicU64,
    run_cnt: AtomicU64,
}

impl ProgStats {
    /// Empty counters for a newly loaded program. # C: O(1)
    pub const fn new() -> Self {
        Self { run_time_ns: AtomicU64::new(0), run_cnt: AtomicU64::new(0) }
    }

    /// Run `f`, charging one execution only when collection was enabled at
    /// entry. # C: O(f + 1)
    pub fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        self.run_decided(holds() > 0, monotonic_ns, f)
    }

    /// One non-tearing information-record sample. # C: O(1)
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            run_time_ns: self.run_time_ns.load(Ordering::Relaxed),
            run_cnt: self.run_cnt.load(Ordering::Relaxed),
        }
    }

    fn run_decided<T>(
        &self,
        enabled: bool,
        mut now: impl FnMut() -> u64,
        f: impl FnOnce() -> T,
    ) -> T {
        if !enabled { return f(); }
        let start = now();
        let result = f();
        let duration = now().wrapping_sub(start);
        self.run_cnt.fetch_add(1, Ordering::Relaxed);
        self.run_time_ns.fetch_add(duration, Ordering::Relaxed);
        result
    }
}

pub(crate) fn holds() -> i32 { ENABLED.load(Ordering::Acquire) }
pub(crate) fn hold() { ENABLED.fetch_add(1, Ordering::AcqRel); }
pub(crate) fn release() { ENABLED.fetch_sub(1, Ordering::AcqRel); }

fn monotonic_ns() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    { sched::live::timer_list::now_ns() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::cell::Cell;
    use super::*;

    #[test]
    fn disabled_runs_do_not_sample_or_change_program_counters() {
        let stats = ProgStats::new();
        let sampled = Cell::new(0);
        assert_eq!(stats.run_decided(false, || { sampled.set(sampled.get() + 1); 9 }, || 17), 17);
        assert_eq!(sampled.get(), 0);
        assert_eq!(stats.snapshot(), Snapshot::default());
    }

    #[test]
    fn enabled_runs_accumulate_one_count_and_the_full_elapsed_time() {
        let stats = ProgStats::new();
        let sample = Cell::new(4u64);
        let now = || { let v = sample.get(); sample.set(v + 6); v };
        assert_eq!(stats.run_decided(true, now, || Some(23)), Some(23));
        assert_eq!(stats.snapshot(), Snapshot { run_time_ns: 6, run_cnt: 1 });
    }

    #[test]
    fn loaded_program_runner_reaches_its_owned_counter() {
        let inode = crate::bpf::make_bpf_prog_inode(
            crate::bpf::uapi::prog_type::SOCKET_FILTER,
            vec![0x95, 0, 0, 0, 0, 0, 0, 0],
        );
        let prog = inode.private::<crate::bpf::BpfProgInode>().unwrap();
        hold();
        let answer = crate::bpf_interp::run_program_with_state(
            prog, &[], &[], &[], &mut crate::bpf_interp::HelperState::default(),
        );
        release();
        assert_eq!(answer, Some(0));
        assert_eq!(prog.stats.snapshot().run_cnt, 1);
    }
}
