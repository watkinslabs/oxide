// Canonical per-mm facts VMM can observe directly.  Presentation (procfs,
// sysinfo) deliberately lives outside this module.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{KMalloc, Spinlock};

use crate::tree::VmaTree;
use crate::vma::{Vma, VmaBacking, VmaFlags};

/// Snapshot of facts owned by one address space.  `major_faults` and shmem
/// residency are intentionally absent: VMM's FileBacking API does not expose
/// cache misses or a backing-kind identity, so inventing either would be a
/// second source of truth.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VmAccountingSnapshot {
    pub committed_virtual_bytes: u64,
    pub locked_virtual_bytes: u64,
    pub anon_pte_mappings: u64,
    pub file_pte_mappings: u64,
    /// Non-present swap leaves owned by this mm.  This is maintained at the
    /// same checked present↔swap replacement boundary as resident mappings.
    pub swap_pte_mappings: u64,
    pub kernel_pte_mappings: u64,
    pub device_pte_mappings: u64,
    pub root_page_table_frames: u64,
    /// Every live root and intermediate page-table frame owned by this mm.
    /// PMM changes this only at the real typed allocation/free boundary.
    pub page_table_frames: u64,
    pub faults: u64,
    pub mlock_transitions: u64,
}

pub(super) struct VmAccounting {
    committed_virtual_bytes: AtomicU64,
    locked_virtual_bytes: AtomicU64,
    anon_pte_mappings: AtomicU64,
    file_pte_mappings: AtomicU64,
    swap_pte_mappings: AtomicU64,
    kernel_pte_mappings: AtomicU64,
    device_pte_mappings: AtomicU64,
    root_page_table_frames: AtomicU64,
    page_table_frames: AtomicU64,
    faults: AtomicU64,
    mlock_transitions: AtomicU64,
}

#[derive(Clone, Copy)]
enum PteKind { Anon, File, Kernel, Device, None }

impl VmAccounting {
    pub(super) fn new(root_pa: u64) -> Self {
        Self {
            committed_virtual_bytes: AtomicU64::new(0), locked_virtual_bytes: AtomicU64::new(0),
            anon_pte_mappings: AtomicU64::new(0), file_pte_mappings: AtomicU64::new(0), swap_pte_mappings: AtomicU64::new(0),
            kernel_pte_mappings: AtomicU64::new(0), device_pte_mappings: AtomicU64::new(0),
            root_page_table_frames: AtomicU64::new(u64::from(root_pa != 0)),
            page_table_frames: AtomicU64::new(u64::from(root_pa != 0)),
            faults: AtomicU64::new(0), mlock_transitions: AtomicU64::new(0),
        }
    }

    pub(super) fn from_vmas(root_pa: u64, tree: &VmaTree) -> Self {
        let a = Self::new(root_pa);
        for vma in tree.iter() { a.add_vma(vma); }
        a
    }

    pub(super) fn snapshot(&self) -> VmAccountingSnapshot {
        VmAccountingSnapshot {
            committed_virtual_bytes: self.committed_virtual_bytes.load(Ordering::Acquire),
            locked_virtual_bytes: self.locked_virtual_bytes.load(Ordering::Acquire),
            anon_pte_mappings: self.anon_pte_mappings.load(Ordering::Acquire),
            file_pte_mappings: self.file_pte_mappings.load(Ordering::Acquire),
            swap_pte_mappings: self.swap_pte_mappings.load(Ordering::Acquire),
            kernel_pte_mappings: self.kernel_pte_mappings.load(Ordering::Acquire),
            device_pte_mappings: self.device_pte_mappings.load(Ordering::Acquire),
            root_page_table_frames: self.root_page_table_frames.load(Ordering::Acquire),
            page_table_frames: self.page_table_frames.load(Ordering::Acquire),
            faults: self.faults.load(Ordering::Acquire),
            mlock_transitions: self.mlock_transitions.load(Ordering::Acquire),
        }
    }

    fn bytes(vma: &Vma) -> u64 { vma.end.as_u64() - vma.start.as_u64() }
    fn committed(vma: &Vma) -> bool {
        matches!(vma.backing, VmaBacking::Anonymous)
            || (!vma.flags.contains(VmaFlags::SHARED)
                && matches!(vma.backing, VmaBacking::File { .. } | VmaBacking::KernelBytes { .. }))
    }
    pub(super) fn add_vma(&self, vma: &Vma) {
        let n = Self::bytes(vma);
        if Self::committed(vma) { self.committed_virtual_bytes.fetch_add(n, Ordering::AcqRel); }
        if vma.flags.contains(VmaFlags::LOCKED) { self.locked_virtual_bytes.fetch_add(n, Ordering::AcqRel); }
    }
    pub(super) fn remove_vma(&self, vma: &Vma) {
        let n = Self::bytes(vma);
        if Self::committed(vma) { self.committed_virtual_bytes.fetch_sub(n, Ordering::AcqRel); }
        if vma.flags.contains(VmaFlags::LOCKED) { self.locked_virtual_bytes.fetch_sub(n, Ordering::AcqRel); }
    }
    pub(super) fn replace_locked_range(&self, old: u64, new: u64) {
        if old == new { return; }
        if new > old { self.locked_virtual_bytes.fetch_add(new - old, Ordering::AcqRel); }
        else { self.locked_virtual_bytes.fetch_sub(old - new, Ordering::AcqRel); }
        self.mlock_transitions.fetch_add(1, Ordering::AcqRel);
    }
    pub(super) fn fault(&self) { self.faults.fetch_add(1, Ordering::AcqRel); }
    fn page_table_frame_allocated(&self) { self.page_table_frames.fetch_add(1, Ordering::AcqRel); }
    fn page_table_frame_released(&self) { self.page_table_frames.fetch_sub(1, Ordering::AcqRel); }
    pub(super) fn install_pte(&self, vma: &Vma) {
        if let Some(c) = self.counter(Self::pte_kind(vma)) { c.fetch_add(1, Ordering::AcqRel); }
    }
    pub(super) fn remove_pte(&self, vma: &Vma) {
        if let Some(c) = self.counter(Self::pte_kind(vma)) { c.fetch_sub(1, Ordering::AcqRel); }
    }
    pub(super) fn install_swap_pte(&self) { self.swap_pte_mappings.fetch_add(1, Ordering::AcqRel); }
    pub(super) fn remove_swap_pte(&self) { self.swap_pte_mappings.fetch_sub(1, Ordering::AcqRel); }
    fn pte_kind(vma: &Vma) -> PteKind {
        match vma.backing {
            VmaBacking::Anonymous => PteKind::Anon,
            VmaBacking::File { .. } | VmaBacking::KernelBytes { .. } => PteKind::File,
            VmaBacking::KernelFrame { .. } => PteKind::Kernel,
            VmaBacking::PhysRange { .. } => PteKind::Device,
            VmaBacking::Special => PteKind::None,
        }
    }
    fn counter(&self, k: PteKind) -> Option<&AtomicU64> {
        Some(match k {
            PteKind::Anon => &self.anon_pte_mappings, PteKind::File => &self.file_pte_mappings,
            PteKind::Kernel => &self.kernel_pte_mappings, PteKind::Device => &self.device_pte_mappings,
            PteKind::None => return None,
        })
    }
}

// PMM owns the frames, while an address space owns the per-mm view.  This
// directory is routing only: it contains no counts and no duplicate lifetime
// state.  Its pointers are registered after `AddressSpace` construction and
// removed only after Drop has completed the PMM page-table teardown.
static PAGE_TABLE_OWNERS: Spinlock<BTreeMap<u64, usize>, KMalloc> =
    Spinlock::new(BTreeMap::new());

pub(super) fn register_page_table_owner(root_pa: u64, accounting: *const VmAccounting) {
    if root_pa == 0 { return; }
    PAGE_TABLE_OWNERS.lock().insert(root_pa, accounting as usize);
}

pub(super) fn unregister_page_table_owner(root_pa: u64) {
    if root_pa != 0 { PAGE_TABLE_OWNERS.lock().remove(&root_pa); }
}

/// PMM calls this only after it has made the PageMeta `PAGETABLE` transition.
/// # C: O(log mm count)
pub fn page_table_frame_allocated(root_pa: u64) {
    let ptr = PAGE_TABLE_OWNERS.lock().get(&root_pa).copied();
    if let Some(ptr) = ptr {
        // SAFETY: registration stores the address of an AddressSpace-owned
        // VmAccounting; Drop unregisters only after page-table teardown, so
        // a PMM lifecycle callback cannot observe a dangling pointer.
        unsafe { (&*(ptr as *const VmAccounting)).page_table_frame_allocated(); }
    }
}

/// PMM calls this immediately before returning a typed page-table frame to
/// the buddy. # C: O(log mm count)
pub fn page_table_frame_released(root_pa: u64) {
    let ptr = PAGE_TABLE_OWNERS.lock().get(&root_pa).copied();
    if let Some(ptr) = ptr {
        // SAFETY: same lifetime proof as `page_table_frame_allocated`.
        unsafe { (&*(ptr as *const VmAccounting)).page_table_frame_released(); }
    }
}

/// PMM calls this for each swap leaf consumed while tearing down an mm whose
/// VMA tree no longer exists.  The accounting owner remains registered until
/// its teardown callback returns. # C: O(log mm count)
pub fn swap_pte_teardown(root_pa: u64) {
    let ptr = PAGE_TABLE_OWNERS.lock().get(&root_pa).copied();
    if let Some(ptr) = ptr {
        // SAFETY: same registered-through-teardown lifetime as the page-table callbacks.
        unsafe { (&*(ptr as *const VmAccounting)).remove_swap_pte(); }
    }
}

/// Aggregate every live address-space accounting owner while the owner
/// directory pins their lifetime.  The directory is routing-only: this folds
/// the per-mm canonical counters and creates no global counter that could
/// diverge from VMM transitions. # C: O(live address spaces); # Lk: TaskList
pub fn global_accounting_snapshot() -> VmAccountingSnapshot {
    let owners = PAGE_TABLE_OWNERS.lock();
    let mut out = VmAccountingSnapshot::default();
    for ptr in owners.values().copied() {
        // SAFETY: PAGE_TABLE_OWNERS retains this pointer under its lock until
        // AddressSpace::Drop unregisters only after teardown; holding the
        // directory lock prevents removal while this observation dereferences it.
        let next = unsafe { (&*(ptr as *const VmAccounting)).snapshot() };
        out.committed_virtual_bytes = out.committed_virtual_bytes.saturating_add(next.committed_virtual_bytes);
        out.locked_virtual_bytes = out.locked_virtual_bytes.saturating_add(next.locked_virtual_bytes);
        out.anon_pte_mappings = out.anon_pte_mappings.saturating_add(next.anon_pte_mappings);
        out.file_pte_mappings = out.file_pte_mappings.saturating_add(next.file_pte_mappings);
        out.swap_pte_mappings = out.swap_pte_mappings.saturating_add(next.swap_pte_mappings);
        out.kernel_pte_mappings = out.kernel_pte_mappings.saturating_add(next.kernel_pte_mappings);
        out.device_pte_mappings = out.device_pte_mappings.saturating_add(next.device_pte_mappings);
        out.root_page_table_frames = out.root_page_table_frames.saturating_add(next.root_page_table_frames);
        out.page_table_frames = out.page_table_frames.saturating_add(next.page_table_frames);
        out.faults = out.faults.saturating_add(next.faults);
        out.mlock_transitions = out.mlock_transitions.saturating_add(next.mlock_transitions);
    }
    out
}
