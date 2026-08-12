// The ORDER an LDT install must happen in, with nothing arch-specific in it.
//
// Three steps, and the order between the last two is the whole safety
// argument. The reference publishes the new table, calls its LDT flush on
// every CPU in the mm's cpumask and WAITS, and only then frees the old
// table. Swapping the last two — freeing before the converge — hands the
// buddy allocator a page that a sibling CPU's LDTR still names, which is a
// descriptor-table use-after-free: the sibling keeps executing with
// descriptors read out of recycled memory, and nothing faults until the
// contents change under it.
//
// Written as a trait so the ordering is one ungated function with hosted
// tests that can actually FAIL, rather than a comment beside a `lldt` in a
// kernel-only file where no test compiles.

/// The four things an install has to be able to do, with the arch and the
/// allocator abstracted away.
pub trait LdtInstallOps {
    /// The displaced table, whatever the caller's representation of it is.
    type Old;

    /// Swap the new table in and publish its (base, entry-count) pair.
    /// Returns the table that was displaced.
    fn publish(&mut self) -> Self::Old;

    /// CPUs that may currently be running this mm — the reference's
    /// `mm_cpumask`. Read AFTER publication: a CPU that joins the mm later
    /// reads the already-published table, so it needs no call.
    fn cpumask(&mut self) -> cpu::CpuMask;

    /// Reload LDTR on every CPU in `targets` AND on this one, returning only
    /// once each has finished. A caller that cannot wait must not call this
    /// function at all — the free below would be unguarded.
    fn converge(&mut self, targets: cpu::CpuMask);

    /// Release the displaced table.
    fn free_old(&mut self, old: Self::Old);
}

/// Publish, converge, then free — in that order, always.
/// # C: O(1) plus the converge's IPI round-trip
pub fn install_and_converge<O: LdtInstallOps>(ops: &mut O) {
    let old = ops.publish();
    let targets = ops.cpumask();
    ops.converge(targets);
    ops.free_old(old);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    enum Ev { Publish, Cpumask, Converge(u64), Free }

    struct Fake { mask: u64, log: Vec<Ev> }

    impl LdtInstallOps for Fake {
        type Old = u32;
        fn publish(&mut self) -> u32 { self.log.push(Ev::Publish); 0x01D }
        fn cpumask(&mut self) -> cpu::CpuMask { self.log.push(Ev::Cpumask); cpu::CpuMask::from_words(&[self.mask]) }
        fn converge(&mut self, t: cpu::CpuMask) { self.log.push(Ev::Converge(t.low_word())); }
        fn free_old(&mut self, _old: u32) { self.log.push(Ev::Free); }
    }

    fn run(mask: u64) -> Vec<Ev> {
        let mut f = Fake { mask, log: Vec::new() };
        install_and_converge(&mut f);
        f.log
    }

    #[test]
    fn the_old_table_is_freed_only_after_the_converge() {
        let log = run(0b1010);
        let converge = log.iter().position(|e| matches!(e, Ev::Converge(_))).expect("no converge");
        let free = log.iter().position(|e| matches!(e, Ev::Free)).expect("no free");
        assert!(converge < free,
            "the displaced table was freed before every CPU reloaded LDTR: {:?}", log);
    }

    #[test]
    fn the_new_table_is_published_before_anyone_is_asked_to_reload_it() {
        let log = run(0b1010);
        let publish = log.iter().position(|e| matches!(e, Ev::Publish)).expect("no publish");
        let converge = log.iter().position(|e| matches!(e, Ev::Converge(_))).expect("no converge");
        assert!(publish < converge,
            "a CPU was asked to reload before the new table existed: {:?}", log);
    }

    #[test]
    fn the_converge_targets_the_whole_cpumask() {
        assert_eq!(run(0b1010), [Ev::Publish, Ev::Cpumask, Ev::Converge(0b1010), Ev::Free]);
        assert_eq!(run(u64::MAX), [Ev::Publish, Ev::Cpumask, Ev::Converge(u64::MAX), Ev::Free]);
    }

    #[test]
    fn an_mm_no_cpu_is_running_still_converges_and_still_frees() {
        // An empty mask is not a reason to skip the call: the local CPU's own
        // reload rides the same step, and the free must still happen.
        assert_eq!(run(0), [Ev::Publish, Ev::Cpumask, Ev::Converge(0), Ev::Free]);
    }

    #[test]
    fn every_step_runs_exactly_once() {
        let log = run(0b11);
        assert_eq!(log.iter().filter(|e| matches!(e, Ev::Publish)).count(), 1);
        assert_eq!(log.iter().filter(|e| matches!(e, Ev::Converge(_))).count(), 1);
        assert_eq!(log.iter().filter(|e| matches!(e, Ev::Free)).count(), 1);
    }
}
