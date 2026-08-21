//! One physical-image owner, independent of PMM's allocation implementation.
//!
//! PMM supplies topology, a point-in-time free test, and reversible copy-frame
//! ownership.  This module alone decides which original PFNs form the image.

use alloc::vec::Vec;

use crate::decide::{Error, KResult};
use super::bitmap::Bitmap;

pub mod budget;
pub use budget::{Budget, calculate as calculate_budget, retained_capacity};

/// Page-normalized boot-memory classification consumed by snapshot policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    Usable,
    KernelImage,
    Initramfs,
    AcpiNvs,
    AcpiReclaim,
    Reserved,
    Bad,
    Mmio,
}

/// One half-open range from the canonical normalized topology.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Region { pub start_pfn: u64, pub end_pfn: u64, pub kind: MemoryKind }

/// The narrow PMM boundary snapshot construction needs.
pub trait Memory {
    type Frame;

    /// Canonical retained topology, already page normalized and disjoint.
    fn topology(&self) -> &[Region];
    /// Point-in-time buddy/PCP truth captured before any copy allocation.
    fn was_free(&self, pfn: u64) -> bool;
    /// PMM-owned permanent and hibernation-temporary nosave truth.
    fn is_forbidden(&self, pfn: u64) -> bool;
    /// Take one image-owned copy frame preallocated before device quiesce.
    fn take_copy(&mut self) -> KResult<Self::Frame>;
    /// Copy one source PFN into an exclusively owned frame.
    fn copy_into(&self, pfn: u64, frame: &mut Self::Frame) -> KResult<()>;
}

/// One nonzero original PFN and its immutable image-owned copy.
pub struct CopiedPage<F> { pub original_pfn: u64, pub copy: F }

/// Sole owner of one save-side physical image.
pub struct Snapshot<F> {
    copied: Vec<CopiedPage<F>>,
    zero_pfns: Vec<u64>,
    original_pfns: Bitmap,
}

impl<F> Snapshot<F> {
    /// Allocate restored-side metadata capacity before final free-page truth.
    /// The memory adapter separately owns every copy frame before finalizing.
    /// # C: O(capacity allocation)
    pub fn preallocate(capacity: usize, pfn_limit: u64) -> KResult<Self> {
        if capacity == 0 || pfn_limit == 0 { return Err(Error::Nomem); }
        let mut copied = Vec::new();
        copied.try_reserve_exact(capacity).map_err(|_| Error::Nomem)?;
        let original_pfns = Bitmap::new(pfn_limit).map_err(|_| Error::Nomem)?;
        Ok(Self { copied, zero_pfns: Vec::new(), original_pfns })
    }

    /// Immutable copied-page sequence owned by this snapshot. # C: O(1)
    pub fn copied(&self) -> &[CopiedPage<F>] { &self.copied }
    /// Original PFNs represented by zero-fill metadata. # C: O(1)
    pub fn zero_pfns(&self) -> &[u64] { &self.zero_pfns }
    /// Number of original PFNs restored by this image. # C: O(1)
    pub fn image_pages(&self) -> usize { self.copied.len() + self.zero_pfns.len() }
    /// Whether one original PFN is represented in the persisted image. # C: O(1)
    pub fn contains_original_pfn(&self, pfn: u64) -> bool { self.original_pfns.contains(pfn) }

    /// Release at most `count` copied-page owners from the tail. # C: O(count)
    pub fn release_copied(&mut self, count: usize) -> usize {
        let old = self.copied.len();
        self.copied.truncate(old.saturating_sub(count));
        old - self.copied.len()
    }
}

/// Select every source from an adapter whose copy storage is already owned.
/// # C: O(populated topology PFNs)
pub fn prepare<M: Memory>(memory: &mut M) -> KResult<Snapshot<M::Frame>> {
    let capacity = usize::try_from(count_saveable(memory)?).map_err(|_| Error::Nomem)?;
    let mut snapshot = Snapshot::preallocate(capacity, topology_pfn_limit(memory.topology())?)?;
    prepare_into(memory, &mut snapshot)?;
    Ok(snapshot)
}

/// Finalize one early metadata owner against the quiesced allocator view.
/// The copied vector is forbidden to grow here; its backing must already be
/// represented by the final image selection. # C: O(populated topology PFNs)
pub fn prepare_into<M: Memory>(memory: &mut M, snapshot: &mut Snapshot<M::Frame>) -> KResult<()> {
    if !snapshot.copied.is_empty() || !snapshot.zero_pfns.is_empty() { return Err(Error::Inval); }
    validate_topology(memory.topology())?;
    #[cfg(feature = "debug-hibernate")]
    const PROGRESS_PFNS: u64 = 65_536;
    #[cfg(feature = "debug-hibernate")]
    let total = memory.topology().iter().filter(|region| saveable(region.kind))
        .fold(0u64, |pages, region| pages.saturating_add(region.end_pfn - region.start_pfn));
    #[cfg(feature = "debug-hibernate")]
    let mut scanned = 0u64;
    for index in 0..memory.topology().len() {
        let region = memory.topology()[index];
        if !saveable(region.kind) { continue; }
        for pfn in region.start_pfn..region.end_pfn {
            #[cfg(feature = "debug-hibernate")]
            {
                scanned = scanned.saturating_add(1);
                if scanned % PROGRESS_PFNS == 0 {
                    super::log::snapshot_progress(super::log::SnapshotPhase::Select, scanned, total);
                }
            }
            if memory.is_forbidden(pfn) { continue; }
            if region.kind == MemoryKind::Usable && memory.was_free(pfn) { continue; }
            if snapshot.copied.len() == snapshot.copied.capacity() { return Err(Error::Nomem); }
            if !snapshot.original_pfns.claim(pfn).map_err(|_| Error::Inval)? {
                return Err(Error::Inval);
            }
            let copy = memory.take_copy()?;
            snapshot.copied.push(CopiedPage { original_pfn: pfn, copy });
        }
    }
    Ok(())
}

/// Count currently allocated saveable PFNs from the same immutable free and
/// forbidden view used by final image selection. # C: O(populated topology PFNs)
pub fn count_saveable<M: Memory>(memory: &M) -> KResult<u64> {
    validate_topology(memory.topology())?;
    let mut pages = 0u64;
    for region in memory.topology() {
        if !saveable(region.kind) { continue; }
        for pfn in region.start_pfn..region.end_pfn {
            if memory.is_forbidden(pfn) { continue; }
            if region.kind == MemoryKind::Usable && memory.was_free(pfn) { continue; }
            pages = pages.checked_add(1).ok_or(Error::Nomem)?;
        }
    }
    Ok(pages)
}

/// Copy the quiesced physical image into its preallocated frames.
/// # C: O(image pages)
/// # Ctx: IRQ-off, single CPU, syscore suspended
pub fn capture<M: Memory<Frame = F>, F>(snapshot: &mut Snapshot<F>, memory: &M) -> KResult<()> {
    for page in &mut snapshot.copied {
        memory.copy_into(page.original_pfn, &mut page.copy)?;
    }
    Ok(())
}

pub(super) fn saveable(kind: MemoryKind) -> bool {
    matches!(kind, MemoryKind::Usable | MemoryKind::KernelImage | MemoryKind::Initramfs)
}

pub(super) fn validate_topology(regions: &[Region]) -> KResult<()> {
    let mut end = 0u64;
    for (index, region) in regions.iter().enumerate() {
        if region.start_pfn >= region.end_pfn || (index != 0 && region.start_pfn < end) {
            return Err(Error::Inval);
        }
        end = region.end_pfn;
    }
    Ok(())
}

pub(super) fn topology_pfn_limit(regions: &[Region]) -> KResult<u64> {
    validate_topology(regions)?;
    regions.last().map(|region| region.end_pfn).ok_or(Error::Inval)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::Relaxed); }
    }

    struct Fake {
        topology: Vec<Region>,
        free: Vec<u64>,
        forbidden: Vec<u64>,
        pages: Vec<[u8; 4]>,
        copies: Vec<[u8; 4]>,
    }

    #[test]
    fn large_copy_owner_can_be_released_at_bounded_reschedule_points() {
        const PAGES: usize = 100_001;
        const BATCH: usize = 256;
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut copied = Vec::new();
        copied.try_reserve_exact(PAGES).unwrap();
        for pfn in 0..PAGES {
            copied.push(CopiedPage { original_pfn: pfn as u64,
                copy: DropCount(dropped.clone()) });
        }
        let mut snapshot = Snapshot { copied, zero_pfns: Vec::new(),
            original_pfns: Bitmap::new(PAGES as u64).unwrap() };
        let mut points = 0;
        while snapshot.release_copied(BATCH) != 0 { points += 1; }
        assert_eq!(dropped.load(Ordering::Relaxed), PAGES);
        assert_eq!(points, PAGES.div_ceil(BATCH));
    }

    impl Memory for Fake {
        type Frame = [u8; 4];
        fn topology(&self) -> &[Region] { &self.topology }
        fn was_free(&self, pfn: u64) -> bool { self.free.contains(&pfn) }
        fn is_forbidden(&self, pfn: u64) -> bool { self.forbidden.contains(&pfn) }
        fn take_copy(&mut self) -> KResult<Self::Frame> { self.copies.pop().ok_or(Error::Nomem) }
        fn copy_into(&self, pfn: u64, frame: &mut Self::Frame) -> KResult<()> {
            *frame = *self.pages.get(pfn as usize).ok_or(Error::Inval)?;
            Ok(())
        }
    }

    fn fake() -> Fake {
        Fake {
            topology: vec![
                Region { start_pfn: 0, end_pfn: 4, kind: MemoryKind::Usable },
                Region { start_pfn: 4, end_pfn: 5, kind: MemoryKind::Reserved },
                Region { start_pfn: 5, end_pfn: 6, kind: MemoryKind::KernelImage },
                Region { start_pfn: 6, end_pfn: 7, kind: MemoryKind::AcpiNvs },
            ],
            free: vec![1, 3],
            forbidden: vec![],
            pages: vec![[1; 4], [2; 4], [0; 4], [3; 4], [4; 4], [5; 4], [6; 4]],
            copies: vec![[0; 4]; 7],
        }
    }

    #[test]
    fn one_owner_selects_free_zero_reserved_and_kernel_pages() {
        let mut memory = fake();
        let mut snapshot = prepare(&mut memory).unwrap();
        capture(&mut snapshot, &memory).unwrap();
        assert_eq!(snapshot.copied.iter().map(|p| p.original_pfn).collect::<Vec<_>>(), vec![0, 2, 5]);
        assert_eq!(snapshot.copied[0].copy, [1; 4]);
        assert_eq!(snapshot.copied[1].copy, [0; 4]);
        assert_eq!(snapshot.copied[2].copy, [5; 4]);
        assert!(snapshot.zero_pfns.is_empty());
        assert_eq!(snapshot.image_pages(), 3);
    }

    #[test]
    fn treating_reserved_memory_as_saveable_turns_the_oracle_red() {
        let mut memory = fake();
        memory.topology[1].kind = MemoryKind::KernelImage;
        let snapshot = prepare(&mut memory).unwrap();
        assert_eq!(snapshot.copied.iter().map(|p| p.original_pfn).collect::<Vec<_>>(), vec![0, 2, 4, 5]);
        assert_ne!(snapshot.image_pages(), 3, "missing the exclusion must change the image");
    }

    #[test]
    fn removing_one_pmm_forbidden_bit_turns_snapshot_selection_red() {
        let mut excluded = fake();
        excluded.forbidden.push(2);
        let safe = prepare(&mut excluded).unwrap();
        assert_eq!(safe.copied.iter().map(|page| page.original_pfn).collect::<Vec<_>>(), vec![0, 5]);

        let mut missing = fake();
        let unsafe_image = prepare(&mut missing).unwrap();
        assert_eq!(unsafe_image.copied.iter().map(|page| page.original_pfn).collect::<Vec<_>>(),
            vec![0, 2, 5]);
        assert_ne!(unsafe_image.image_pages(), safe.image_pages());
    }

    #[test]
    fn allocated_saved_state_pfn_is_in_persisted_selection() {
        let mut memory = fake();
        let state_pfn = 2;
        let snapshot = prepare(&mut memory).unwrap();
        assert!(snapshot.contains_original_pfn(state_pfn));
        let copied = snapshot.copied().iter().map(|page| page.original_pfn)
            .collect::<Vec<_>>();
        let info = super::super::stream::layout(copied.len() as u64, 0).unwrap();
        let encoded = super::super::stream::encode_pfns(&copied, &[], 0).unwrap();
        let mut persisted = vec![0u64; copied.len()];
        let count = super::super::stream::decode_pfns(&encoded, info, 0, &mut persisted).unwrap();
        assert!(persisted[..count].contains(&state_pfn),
            "saved-state PFN must occur in the persisted PFN stream");

        memory.forbidden.push(state_pfn);
        let broken = prepare(&mut memory).unwrap();
        assert!(!broken.contains_original_pfn(state_pfn),
            "positive control must fail if saved state acquires nosave role");
    }

    #[test]
    fn quiesced_finalize_never_moves_early_metadata_backing() {
        let mut memory = fake();
        let mut snapshot = Snapshot::preallocate(3, 7).unwrap();
        let backing = snapshot.copied.as_ptr();
        prepare_into(&mut memory, &mut snapshot).unwrap();
        assert_eq!(snapshot.copied.as_ptr(), backing);
        assert_eq!(snapshot.copied.capacity(), 3);
    }

    #[test]
    fn allocation_between_preallocation_and_final_truth_is_saved() {
        let mut memory = fake();
        memory.free.push(2);
        let mut snapshot = Snapshot::preallocate(3, 7).unwrap();
        memory.free.retain(|pfn| *pfn != 2);
        prepare_into(&mut memory, &mut snapshot).unwrap();
        assert!(snapshot.contains_original_pfn(2));

        let mut too_late = fake();
        let mut after = Snapshot::preallocate(3, 7).unwrap();
        too_late.free.push(2);
        prepare_into(&mut too_late, &mut after).unwrap();
        assert!(!after.contains_original_pfn(2),
            "a page free in final truth must remain outside this image");
    }

    #[test]
    fn overlapping_topology_is_rejected_before_any_copy() {
        let mut memory = fake();
        memory.topology[1].start_pfn = 3;
        assert!(matches!(prepare(&mut memory), Err(Error::Inval)));
    }

    #[test]
    fn every_memory_kind_has_an_explicit_snapshot_policy() {
        let kinds = [MemoryKind::Usable, MemoryKind::KernelImage, MemoryKind::Initramfs,
            MemoryKind::AcpiNvs, MemoryKind::AcpiReclaim, MemoryKind::Reserved,
            MemoryKind::Bad, MemoryKind::Mmio];
        let mut memory = Fake {
            topology: kinds.iter().enumerate().map(|(pfn, kind)| Region {
                start_pfn: pfn as u64, end_pfn: pfn as u64 + 1, kind: *kind,
            }).collect(),
            free: vec![0, 1, 2], forbidden: vec![], pages: vec![[0; 4]; kinds.len()],
            copies: vec![[0; 4]; kinds.len()],
        };
        let snapshot = prepare(&mut memory).unwrap();
        assert_eq!(snapshot.copied().iter().map(|page| page.original_pfn).collect::<Vec<_>>(),
            vec![1, 2], "only Usable honors free truth; live kernel/initramfs are persisted");

        memory.free.clear();
        let live = prepare(&mut memory).unwrap();
        assert_eq!(live.copied().iter().map(|page| page.original_pfn).collect::<Vec<_>>(),
            vec![0, 1, 2]);
    }

    #[test]
    fn quiesced_finalization_only_consumes_preallocated_copy_frames() {
        for available in 0..3 {
            let mut memory = fake();
            memory.copies.truncate(available);
            let mut snapshot = Snapshot::preallocate(3, 7).unwrap();
            assert_eq!(prepare_into(&mut memory, &mut snapshot), Err(Error::Nomem));
            assert!(memory.copies.is_empty(),
                "finalization may exhaust but never replenish the early pool");
        }
        let mut memory = fake();
        let before = memory.copies.len();
        let mut snapshot = Snapshot::preallocate(3, 7).unwrap();
        prepare_into(&mut memory, &mut snapshot).unwrap();
        assert_eq!(memory.copies.len(), before - snapshot.copied().len());
        for capacity in 1..3 {
            let mut memory = fake();
            let mut undersized = Snapshot::preallocate(capacity, 7).unwrap();
            assert_eq!(prepare_into(&mut memory, &mut undersized), Err(Error::Nomem));
            assert_eq!(undersized.copied.capacity(), capacity,
                "quiesced finalization must not grow metadata");
        }
    }

    #[test]
    fn quiesced_snapshot_diagnostics_never_reach_allocating_consoles() {
        let source = include_str!("log.rs");
        for name in ["snapshot_phase", "snapshot_progress", "snapshot_admission"] {
            let start = source.find(&alloc::format!("pub fn {name}")).unwrap();
            let body = &source[start..];
            let end = body.find("\n}\n").unwrap();
            let body = &body[..end];
            assert!(!body.contains("klog::write_raw("));
            assert!(!body.contains("klog::write_dec_u64("));
            assert!(body.contains("klog::write_primary_raw("));
        }
        let capture = include_str!("snapshot.rs").split("pub fn capture").nth(1).unwrap();
        let capture = capture.split("\n}\n").next().unwrap();
        assert!(!capture.contains("snapshot_progress"),
            "copying cannot mutate saveable log or console state between source pages");
    }
}
