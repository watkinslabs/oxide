// Persistent x86 hibernation payload and pre-terminal admission.

/// Architecture-header format consumed by the cold-boot restore kernel.
pub const ARCH_HEADER_VERSION: u64 = 1;
pub const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
/// The generic owner has a pre-quiesce planner and this HAL has a complete
/// allocation-free terminal continuation; runtime validation remains the
/// final admission boundary for each particular image and machine.
pub const RESTORE_PATH_COMPLETE: bool = true;

/// Whether this CPU can expose the complete hibernation machine adapter.
/// x86 has no additional runtime exclusion beyond per-image admission.
/// # C: O(1)
pub const fn restore_path_available() -> bool { RESTORE_PATH_COMPLETE }

pub type HibernationCpuState = crate::suspend::SavedCpuState;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchHeader {
    pub version:          u64,
    pub continuation_va:  u64,
    pub cpu_state_va:     u64,
    pub restore_entry_va: u64,
    pub restore_entry_pa: u64,
    /// Physical image page-table root; PCID bits are never persisted here.
    pub image_cr3_pa:     u64,
    pub xsave_xcr0:       u64,
    pub cpu_signature:    u64,
    pub paging_levels:    u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CurrentHeader {
    pub restore_entry_va: u64,
    pub restore_entry_pa: u64,
    pub xsave_xcr0: u64,
    pub cpu_signature: u64,
    pub paging_levels: u64,
}

impl ArchHeader {
    /// Fixed-width representation embedded by the generic image header. # C: O(1)
    pub const fn words(self) -> [u64; 9] {
        [self.version, self.continuation_va, self.cpu_state_va,
         self.restore_entry_va, self.restore_entry_pa, self.image_cr3_pa,
         self.xsave_xcr0, self.cpu_signature, self.paging_levels]
    }

    /// Reconstruct the architecture payload from its fixed-width words. # C: O(1)
    pub const fn from_words(w: [u64; 9]) -> Self {
        Self { version: w[0], continuation_va: w[1], cpu_state_va: w[2],
               restore_entry_va: w[3], restore_entry_pa: w[4], image_cr3_pa: w[5],
               xsave_xcr0: w[6], cpu_signature: w[7], paging_levels: w[8] }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Collision { pub source_pa: u64, pub destination_pa: u64 }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PhysRange { pub start: u64, pub end: u64 }

impl PhysRange {
    /// Whether one complete page lies inside this interval. # C: O(1)
    pub const fn contains_page(self, pa: u64) -> bool {
        pa >= self.start && match pa.checked_add(PAGE_BYTES) {
            Some(end) => end <= self.end,
            None => false,
        }
    }

    pub(crate) const fn valid(self) -> bool {
        self.start < self.end && self.start % PAGE_BYTES == 0 && self.end % PAGE_BYTES == 0
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextMapping { pub va: u64, pub pa: u64 }

/// Safe-page chain consumed directly by the relocated terminal loop.
///
/// `next_pa` is physical, zero terminates the chain, and unused entries are
/// zero. A whole node occupies one page so generic power can exclude every
/// node with the same PFN ownership mechanism as the image destinations.
pub const COLLISIONS_PER_PAGE: usize = (PAGE_BYTES as usize - 16) / core::mem::size_of::<Collision>();

#[repr(C, align(4096))]
#[derive(Copy, Clone)]
pub struct CollisionPage {
    pub next_pa: u64,
    pub count:   u64,
    pub entries: [Collision; COLLISIONS_PER_PAGE],
}

const _: () = assert!(core::mem::size_of::<CollisionPage>() == PAGE_BYTES as usize);

/// Values read into registers before the temporary CR3 becomes active.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalControl {
    pub collision_head_pa: u64,
    pub hhdm_offset:       u64,
    pub image_cr3_pa:      u64,
    pub restore_entry_va:  u64,
    pub continuation_va:   u64,
    pub cpu_state_va:      u64,
}

pub struct RestorePlan<'a> {
    pub collisions: &'a [Collision],
    pub temporary_cr3_pa: u64,
    pub trampoline_pa: u64,
    pub stack_pa: u64,
    pub direct_map: PhysRange,
    pub restored_text: TextMapping,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PlanError { Header, Alignment, Range, ControlCollision, Duplicate, Unmapped, TooMany }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RestoreStep {
    InstallTemporaryCr3,
    FlushGlobalTlb,
    EnterSafeCode,
    CopyCollisions,
    EnterRestoredText,
    InstallImageCr3,
    FlushImageTlb,
    RestoreProcessorState,
    EnterContinuation,
}

pub const RESTORE_ORDER: [RestoreStep; 9] = [
    RestoreStep::InstallTemporaryCr3, RestoreStep::FlushGlobalTlb,
    RestoreStep::EnterSafeCode, RestoreStep::CopyCollisions,
    RestoreStep::EnterRestoredText, RestoreStep::InstallImageCr3,
    RestoreStep::FlushImageTlb, RestoreStep::RestoreProcessorState,
    RestoreStep::EnterContinuation,
];

/// Page-alignment predicate shared by terminal planners. # C: O(1)
pub(crate) fn aligned_page(pa: u64) -> bool { pa != 0 && pa % PAGE_BYTES == 0 }
/// Data-page alignment permits physical frame zero; only owner pointers use zero as a sentinel. # C: O(1)
fn aligned_data_page(pa: u64) -> bool { pa % PAGE_BYTES == 0 }
/// Containing base-page address. # C: O(1)
pub(crate) fn page_base(addr: u64) -> u64 { addr & !(PAGE_BYTES - 1) }

/// Validate the persistent x86 payload before any destination is modified. # C: O(1)
pub fn validate_header(h: &ArchHeader) -> Result<(), PlanError> {
    if h.version != ARCH_HEADER_VERSION || h.continuation_va == 0 || h.cpu_state_va == 0
        || h.restore_entry_va == 0 || h.cpu_signature == 0
    { return Err(PlanError::Header); }
    if h.restore_entry_pa == 0 || !aligned_page(h.image_cr3_pa) {
        return Err(PlanError::Alignment);
    }
    if h.paging_levels != 4 && h.paging_levels != 5 { return Err(PlanError::Header); }
    Ok(())
}

/// Match persistent CPU and restore-entry state before destination ownership.
/// # C: O(1)
pub fn validate_current_header(h: &ArchHeader, current: CurrentHeader) -> Result<(), PlanError> {
    validate_header(h)?;
    if h.restore_entry_va != current.restore_entry_va
        || h.restore_entry_pa != current.restore_entry_pa
        || h.xsave_xcr0 != current.xsave_xcr0
        || h.cpu_signature != current.cpu_signature
        || h.paging_levels != current.paging_levels
    { return Err(PlanError::Header); }
    Ok(())
}

/// Check temporary-map coverage and safe-page exclusion before terminal entry.
/// # C: O(number of collision pages)
pub fn validate_restore_plan(h: &ArchHeader, p: &RestorePlan<'_>) -> Result<(), PlanError> {
    validate_header(h)?;
    if !p.direct_map.valid() { return Err(PlanError::Range); }
    let controls = [p.temporary_cr3_pa, p.trampoline_pa, p.stack_pa];
    if controls.iter().any(|pa| !aligned_page(*pa)) { return Err(PlanError::Alignment); }
    if controls[0] == controls[1] || controls[0] == controls[2] || controls[1] == controls[2] {
        return Err(PlanError::ControlCollision);
    }
    if p.restored_text.va != page_base(h.restore_entry_va)
        || p.restored_text.pa != page_base(h.restore_entry_pa)
    { return Err(PlanError::Unmapped); }
    for pa in controls {
        if !p.direct_map.contains_page(pa) { return Err(PlanError::Unmapped); }
    }
    for c in p.collisions {
        if !aligned_data_page(c.source_pa) || !aligned_data_page(c.destination_pa)
            || c.source_pa == c.destination_pa {
            return Err(PlanError::Alignment);
        }
        if controls.contains(&c.destination_pa) { return Err(PlanError::ControlCollision); }
        if !p.direct_map.contains_page(c.source_pa) || !p.direct_map.contains_page(c.destination_pa) {
            return Err(PlanError::Unmapped);
        }
    }
    Ok(())
}

/// Build terminal register inputs from an admitted header and safe chain. # C: O(1)
pub fn terminal_control(h: &ArchHeader, collision_head_pa: u64, hhdm_offset: u64)
    -> Result<TerminalControl, PlanError>
{
    validate_header(h)?;
    if collision_head_pa != 0 && !aligned_page(collision_head_pa) { return Err(PlanError::Alignment); }
    if hhdm_offset == 0 || hhdm_offset % PAGE_BYTES != 0 { return Err(PlanError::Alignment); }
    Ok(TerminalControl { collision_head_pa, hhdm_offset, image_cr3_pa: h.image_cr3_pa,
        restore_entry_va: h.restore_entry_va, continuation_va: h.continuation_va,
        cpu_state_va: h.cpu_state_va })
}

/// Validate the physical collision chain and every page that keeps it alive.
///
/// `safe_pages` contains every staging source plus the trampoline, control,
/// collision-node and temporary-table PFNs. Requiring nodes and sources to
/// occur in that set proves copy-order independence and bounds a malicious
/// cycle without allocation.
///
/// # SAFETY: `hhdm_offset + safe_pages[i]` maps a readable full page owned by
/// the caller for the duration of this walk; no concurrent writer mutates it.
/// # C: O(safe pages² + collision pages * safe pages)
pub unsafe fn validate_collision_chain(
    head_pa: u64, hhdm_offset: u64, direct: PhysRange, safe_pages: &[u64],
) -> Result<usize, PlanError> {
    if !direct.valid() || hhdm_offset == 0 || hhdm_offset % PAGE_BYTES != 0 {
        return Err(PlanError::Range);
    }
    for (i, pa) in safe_pages.iter().enumerate() {
        if !aligned_page(*pa) || !direct.contains_page(*pa) { return Err(PlanError::Unmapped); }
        if safe_pages[i + 1..].contains(pa) { return Err(PlanError::ControlCollision); }
    }
    if head_pa == 0 { return Ok(0); }
    let mut pa = head_pa;
    let mut nodes = 0usize;
    let mut collisions = 0usize;
    while pa != 0 {
        if nodes >= safe_pages.len() || !safe_pages.contains(&pa) { return Err(PlanError::ControlCollision); }
        // SAFETY: fn contract maps this safe-list page and pins it read-only for the walk.
        let node = unsafe { &*((hhdm_offset.wrapping_add(pa)) as *const CollisionPage) };
        if node.count as usize > COLLISIONS_PER_PAGE { return Err(PlanError::TooMany); }
        for c in &node.entries[..node.count as usize] {
            if !aligned_data_page(c.source_pa) || !aligned_data_page(c.destination_pa)
                || c.source_pa == c.destination_pa
            { return Err(PlanError::Alignment); }
            if !safe_pages.contains(&c.source_pa) { return Err(PlanError::ControlCollision); }
            if safe_pages.contains(&c.destination_pa) { return Err(PlanError::ControlCollision); }
            if !direct.contains_page(c.source_pa) || !direct.contains_page(c.destination_pa) {
                return Err(PlanError::Unmapped);
            }
        }
        collisions = collisions.checked_add(node.count as usize).ok_or(PlanError::TooMany)?;
        if node.next_pa != 0 && !aligned_page(node.next_pa) { return Err(PlanError::Alignment); }
        pa = node.next_pa;
        nodes += 1;
    }

    // Header input is persistent and therefore untrusted. A repeated source
    // or destination makes copy results order-dependent even when every page
    // is mapped and safe, so prove the one-to-one relation before entry.
    let mut outer_pa = head_pa;
    for _ in 0..nodes {
        // SAFETY: first pass proved every node belongs to the pinned safe set.
        let outer = unsafe { &*((hhdm_offset.wrapping_add(outer_pa)) as *const CollisionPage) };
        for c in &outer.entries[..outer.count as usize] {
            let mut source_hits = 0usize;
            let mut destination_hits = 0usize;
            let mut inner_pa = head_pa;
            for _ in 0..nodes {
                // SAFETY: same first-pass proof; bounded by the admitted node count.
                let inner = unsafe { &*((hhdm_offset.wrapping_add(inner_pa)) as *const CollisionPage) };
                for other in &inner.entries[..inner.count as usize] {
                    source_hits += usize::from(other.source_pa == c.source_pa);
                    destination_hits += usize::from(other.destination_pa == c.destination_pa);
                }
                inner_pa = inner.next_pa;
            }
            if source_hits != 1 || destination_hits != 1 { return Err(PlanError::Duplicate); }
        }
        outer_pa = outer.next_pa;
    }
    Ok(collisions)
}
