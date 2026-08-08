// The whole-system `sync(2)` phase order.
//
// No target gate: this is the ordering CONTRACT, and the contract is what
// regresses. The syscall shim executes the phases; nothing here touches a
// superblock or a device, so the order is checkable under hosted `cargo test`
// where a reordered constant fails immediately instead of at the next power cut.

/// One phase of the whole-system flush, in the order `sync(2)` performs them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncPhase {
    /// Data-integrity inode writeback across every filesystem. First, because
    /// the passes that follow are what make these writes durable: metadata
    /// written after a backend's commit sits in a transaction nobody committed.
    Inodes,
    /// `sync_fs(wait=0)` across every filesystem — kick each backend's commit
    /// without waiting, so all of them are in flight before any is waited on.
    /// Separating this from [`Self::FsWait`] is the entire reason `sync(2)`
    /// iterates the filesystems three times rather than doing one full flush per
    /// filesystem: with N filesystems, the serial form pays N commit latencies
    /// end to end.
    FsNoWait,
    /// `sync_fs(wait=1)` across every filesystem — wait for the commits kicked
    /// above and take the durability barrier each one owes.
    FsWait,
    /// Start writeback of every block device's own cache, after the filesystems
    /// on top of them have handed their writes down.
    BdevNoWait,
    /// Wait for that device-level writeback and take the barrier.
    BdevWait,
}

/// The phase sequence, in order. # C: O(1)
pub const KSYS_SYNC_PHASES: [SyncPhase; 5] = [
    SyncPhase::Inodes,
    SyncPhase::FsNoWait,
    SyncPhase::FsWait,
    SyncPhase::BdevNoWait,
    SyncPhase::BdevWait,
];

impl SyncPhase {
    /// The `wait` argument this phase passes to whatever it drives, or `None`
    /// for the inode pass, which has no such split. # C: O(1)
    pub fn wait(self) -> Option<bool> {
        match self {
            SyncPhase::Inodes     => None,
            SyncPhase::FsNoWait   => Some(false),
            SyncPhase::FsWait     => Some(true),
            SyncPhase::BdevNoWait => Some(false),
            SyncPhase::BdevWait   => Some(true),
        }
    }

    /// Whether this phase sweeps filesystems (as opposed to block devices).
    /// # C: O(1)
    pub fn is_super_phase(self) -> bool {
        matches!(self, SyncPhase::Inodes | SyncPhase::FsNoWait | SyncPhase::FsWait)
    }
}

/// Drive `run` once per phase in order — the shape of `sync(2)`, with the
/// per-phase work supplied by the caller. # C: O(work)
pub fn ksys_sync(mut run: impl FnMut(SyncPhase)) {
    for phase in KSYS_SYNC_PHASES { run(phase); }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// The order itself. Every filesystem is swept for dirty inodes, then every
    /// filesystem is kicked, then every filesystem is waited on, and only then
    /// are the devices underneath flushed.
    #[test]
    fn phases_run_in_the_canonical_order() {
        let mut seen: Vec<SyncPhase> = Vec::new();
        ksys_sync(|p| seen.push(p));
        assert_eq!(seen, &[
            SyncPhase::Inodes,
            SyncPhase::FsNoWait,
            SyncPhase::FsWait,
            SyncPhase::BdevNoWait,
            SyncPhase::BdevWait,
        ]);
    }

    /// The kick strictly precedes the wait, on both levels. Collapsing either
    /// pair into a single waiting pass serialises the commits.
    #[test]
    fn every_nowait_pass_precedes_its_wait_pass() {
        let pos = |want: SyncPhase| KSYS_SYNC_PHASES.iter().position(|p| *p == want).unwrap();
        assert!(pos(SyncPhase::FsNoWait) < pos(SyncPhase::FsWait));
        assert!(pos(SyncPhase::BdevNoWait) < pos(SyncPhase::BdevWait));
    }

    /// Filesystems are entirely finished before the devices under them are
    /// touched: a device barrier taken before the filesystem above it has
    /// committed guarantees nothing about that filesystem.
    #[test]
    fn all_filesystem_phases_precede_all_device_phases() {
        let last_fs = KSYS_SYNC_PHASES.iter().rposition(|p| p.is_super_phase()).unwrap();
        let first_bdev = KSYS_SYNC_PHASES.iter().position(|p| !p.is_super_phase()).unwrap();
        assert!(last_fs < first_bdev);
    }

    /// The inode pass comes first and carries no `wait` split of its own.
    #[test]
    fn inode_writeback_leads_and_has_no_wait_variant() {
        assert_eq!(KSYS_SYNC_PHASES[0], SyncPhase::Inodes);
        assert_eq!(SyncPhase::Inodes.wait(), None);
        assert_eq!(SyncPhase::FsNoWait.wait(), Some(false));
        assert_eq!(SyncPhase::BdevWait.wait(), Some(true));
    }

    /// A device pass exists at all. `sync(2)` without it leaves whatever the
    /// filesystems handed down to the block layer unflushed.
    #[test]
    fn device_passes_are_present() {
        assert!(KSYS_SYNC_PHASES.iter().any(|p| *p == SyncPhase::BdevNoWait));
        assert!(KSYS_SYNC_PHASES.iter().any(|p| *p == SyncPhase::BdevWait));
    }
}
