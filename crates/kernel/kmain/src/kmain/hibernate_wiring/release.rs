//! Bounded disposal of write-side snapshot ownership after machine recovery.

use power::hibernate::snapshot::Snapshot;

use super::{PreparedSnapshotMemory, SnapshotMemory};

type Frame = pmm::setup::KernelHibernateFrame;
type SavedFrame = pmm::setup::KernelHibernateSavedFrame;

const RELEASE_BATCH_BYTES: usize = 1024 * 1024;
const RELEASE_BATCH_PAGES: usize = RELEASE_BATCH_BYTES / hal::PAGE_SIZE_BYTES as usize;

fn drain(mut release: impl FnMut(usize) -> usize, mut resched: impl FnMut()) {
    loop {
        let released = release(RELEASE_BATCH_PAGES);
        if released == 0 { break; }
        resched();
    }
}

/// Release every snapshot frame with process-context reschedule points. # C: O(image pages)
pub fn all(snapshot: &mut Option<Snapshot<Frame>>, memory: &mut Option<SnapshotMemory>,
    prepared: &mut Option<PreparedSnapshotMemory>, arch_state: &mut Option<SavedFrame>)
{
    drain(|count| {
        let from_snapshot = snapshot.as_mut().map_or(0, |owner| owner.release_copied(count));
        let left = count - from_snapshot;
        let from_memory = memory.as_mut().map_or(0, |owner| owner.release_copies(left));
        let left = left - from_memory;
        from_snapshot + from_memory
            + prepared.as_mut().map_or(0, |owner| owner.release_copies(left))
    }, || { sched::live::cond_resched(); });
    *snapshot = None;
    *memory = None;
    *prepared = None;
    *arch_state = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hundred_thousand_pages_have_bounded_reschedule_points() {
        let mut pages = 100_001usize;
        let mut yields = 0usize;
        drain(|count| { let n = count.min(pages); pages -= n; n }, || yields += 1);
        assert_eq!(pages, 0);
        assert_eq!(yields, 100_001usize.div_ceil(RELEASE_BATCH_PAGES));
    }
}
