// Persistent aarch64 hibernation payload and terminal restore admission.

pub const ARCH_HEADER_VERSION: u64 = 1;
pub const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
/// The generic owner has a pre-quiesce planner and this HAL has a complete
/// allocation-free terminal continuation; runtime validation remains the
/// final admission boundary for each particular image and machine.
pub const RESTORE_PATH_COMPLETE: bool = true;
pub const EXCEPTION_LEVEL_1: u64 = 1;
pub const EXCEPTION_LEVEL_2: u64 = 2;

/// Pure availability decision used by runtime probing and hosted RED controls.
/// This implementation owns no persistent MTE tag stream. # C: O(1)
pub const fn restore_path_available_for(mte_supported: bool) -> bool {
    RESTORE_PATH_COMPLETE && !mte_supported
}

/// Existing processor-state owner used by PSCI sleep and hibernation.
pub type HibernationCpuState = crate::cpu_suspend_ctx::SuspendCtx;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchHeader {
    pub version:          u64,
    pub continuation_va:  u64,
    pub context_pa:       u64,
    pub image_ttbr1_pa:   u64,
    pub kernel_load_pa:   u64,
    pub boot_mpidr:       u64,
    pub exception_level:  u64,
    pub mte_tag_pages:    u64,
    pub cpu_signature:    u64,
    pub mair_el1:         u64,
    pub tcr_el1:          u64,
    pub sctlr_el1:        u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CurrentHeader {
    pub continuation_va: u64,
    pub boot_mpidr: u64,
    pub exception_level: u64,
    pub cpu_signature: u64,
    pub mair_el1: u64,
    pub tcr_el1: u64,
    pub sctlr_el1: u64,
    /// This implementation has no persistent allocation-tag stream. Until
    /// one exists, an MTE-capable restore CPU is refused rather than assuming
    /// that the image contains no tagged pages.
    pub mte_supported: bool,
}

impl ArchHeader {
    /// Fixed-width representation embedded by the generic image header. # C: O(1)
    pub const fn words(self) -> [u64; 12] {
        [self.version, self.continuation_va, self.context_pa, self.image_ttbr1_pa,
         self.kernel_load_pa, self.boot_mpidr, self.exception_level,
         self.mte_tag_pages, self.cpu_signature, self.mair_el1, self.tcr_el1,
         self.sctlr_el1]
    }

    /// Reconstruct the architecture payload from its fixed-width words. # C: O(1)
    pub const fn from_words(w: [u64; 12]) -> Self {
        Self { version: w[0], continuation_va: w[1], context_pa: w[2],
               image_ttbr1_pa: w[3], kernel_load_pa: w[4], boot_mpidr: w[5],
               exception_level: w[6], mte_tag_pages: w[7], cpu_signature: w[8],
               mair_el1: w[9], tcr_el1: w[10], sctlr_el1: w[11] }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Collision { pub source_pa: u64, pub destination_pa: u64 }

pub const COLLISIONS_PER_PAGE: usize = (PAGE_BYTES as usize - 16)
    / core::mem::size_of::<Collision>();

#[repr(C, align(4096))]
#[derive(Copy, Clone)]
pub struct CollisionPage {
    pub next_pa: u64,
    pub count: u64,
    pub entries: [Collision; COLLISIONS_PER_PAGE],
}

const _: () = assert!(core::mem::size_of::<CollisionPage>() == PAGE_BYTES as usize);

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

    const fn valid(self) -> bool {
        self.start < self.end && self.start.is_multiple_of(PAGE_BYTES)
            && self.end.is_multiple_of(PAGE_BYTES)
    }
}

/// Temporary TTBR1 linear-map window (`va = pa + va_offset`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinearMap { pub physical: PhysRange, pub va_offset: u64 }

/// Fully allocated operands for the terminal aarch64 restore.
pub struct RestorePlan<'a> {
    pub safe_pages: &'a [u64],
    pub temporary_ttbr0_pa: u64,
    pub temporary_ttbr1_pa: u64,
    pub trampoline_pa: u64,
    pub arguments_pa: u64,
    pub collision_head_pa: u64,
    pub zero_page_pa: u64,
    pub identity_map: PhysRange,
    pub linear_map: LinearMap,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    Header, Alignment, Range, ControlCollision, Unmapped, MteUnsupported,
    DuplicateDestination, Capacity, CurrentCpu, Continuation,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RestoreStep {
    InstallSafeTtbr0,
    BreakBeforeMakeTemporaryTtbr1,
    EnterSafeCode,
    CopyCollisions,
    CleanDestinationsToPou,
    BreakBeforeMakeImageTtbr1,
    InvalidateTlb,
    InvalidateInstructionCache,
    RestoreProcessorState,
    EnterContinuation,
}

pub const RESTORE_ORDER: [RestoreStep; 10] = [
    RestoreStep::InstallSafeTtbr0, RestoreStep::BreakBeforeMakeTemporaryTtbr1,
    RestoreStep::EnterSafeCode, RestoreStep::CopyCollisions,
    RestoreStep::CleanDestinationsToPou, RestoreStep::BreakBeforeMakeImageTtbr1,
    RestoreStep::InvalidateTlb, RestoreStep::InvalidateInstructionCache,
    RestoreStep::RestoreProcessorState, RestoreStep::EnterContinuation,
];

fn aligned_page(pa: u64) -> bool { pa != 0 && pa.is_multiple_of(PAGE_BYTES) }
fn aligned_data_page(pa: u64) -> bool { pa.is_multiple_of(PAGE_BYTES) }

/// Validate the persistent aarch64 payload before destination modification.
/// # C: O(1)
pub fn validate_header(h: &ArchHeader) -> Result<(), PlanError> {
    if h.version != ARCH_HEADER_VERSION || h.continuation_va == 0 || h.cpu_signature == 0 {
        return Err(PlanError::Header);
    }
    if !aligned_page(h.context_pa) || !aligned_page(h.image_ttbr1_pa) || !aligned_page(h.kernel_load_pa) {
        return Err(PlanError::Alignment);
    }
    if h.exception_level != EXCEPTION_LEVEL_1 { return Err(PlanError::Header); }
    if h.mte_tag_pages != 0 { return Err(PlanError::MteUnsupported); }
    Ok(())
}

/// Match persistent boot-CPU and architectural state before destination ownership.
/// # C: O(1)
pub fn validate_current_header(h: &ArchHeader, current: CurrentHeader) -> Result<(), PlanError> {
    validate_header(h)?;
    if current.mte_supported { return Err(PlanError::MteUnsupported); }
    if h.continuation_va != current.continuation_va
        || h.boot_mpidr & crate::MPIDR_HWID_MASK != current.boot_mpidr & crate::MPIDR_HWID_MASK
        || h.exception_level != current.exception_level
        || h.cpu_signature != current.cpu_signature
        || h.mair_el1 != current.mair_el1
        || h.tcr_el1 != current.tcr_el1
        || h.sctlr_el1 != current.sctlr_el1
    { return Err(PlanError::CurrentCpu); }
    Ok(())
}

fn safe_contains(p: &RestorePlan<'_>, pa: u64) -> bool { p.safe_pages.contains(&pa) }

/// Check map coverage and safe-control exclusion before terminal entry.
/// # C: O(number of collision and safe pages squared)
pub fn validate_restore_plan(h: &ArchHeader, p: &RestorePlan<'_>) -> Result<(), PlanError> {
    validate_header(h)?;
    if !p.identity_map.valid() || !p.linear_map.physical.valid() { return Err(PlanError::Range); }
    let controls = [p.temporary_ttbr0_pa, p.temporary_ttbr1_pa, p.trampoline_pa,
                    p.arguments_pa, p.zero_page_pa];
    if controls.iter().any(|pa| !aligned_page(*pa)) {
        return Err(PlanError::Alignment);
    }
    for i in 0..p.safe_pages.len() {
        let pa = p.safe_pages[i];
        if !aligned_page(pa) || !p.linear_map.physical.contains_page(pa) { return Err(PlanError::Unmapped); }
        if p.safe_pages[i + 1..].contains(&pa) { return Err(PlanError::ControlCollision); }
    }
    if controls.iter().any(|pa| !safe_contains(p, *pa)) { return Err(PlanError::Unmapped); }
    if p.collision_head_pa != 0
        && (!aligned_page(p.collision_head_pa) || !safe_contains(p, p.collision_head_pa)) {
        return Err(PlanError::Unmapped);
    }
    if !p.identity_map.contains_page(p.trampoline_pa) || !p.identity_map.contains_page(h.context_pa) {
        return Err(PlanError::Unmapped);
    }
    for pa in [p.trampoline_pa, p.arguments_pa, h.context_pa] {
        if pa.checked_add(p.linear_map.va_offset).and_then(|va| va.checked_add(PAGE_BYTES)).is_none() {
            return Err(PlanError::Range);
        }
    }
    Ok(())
}

/// Validate the pinned physical collision chain without allocating metadata.
///
/// # Safety
/// `linear_offset + safe_pages[i]` maps a readable page exclusively retained
/// by the caller; the chain is immutable for this complete walk.
/// # C: O(collision pages * safe pages + collisions²)
pub unsafe fn validate_collision_chain(p: &RestorePlan<'_>) -> Result<usize, PlanError> {
    if p.collision_head_pa == 0 { return Ok(0); }
    let mut pa = p.collision_head_pa;
    let mut nodes = 0usize;
    let mut collisions = 0usize;
    while pa != 0 {
        if nodes >= p.safe_pages.len() || !safe_contains(p, pa) { return Err(PlanError::ControlCollision); }
        let va = pa.checked_add(p.linear_map.va_offset).ok_or(PlanError::Range)?;
        // SAFETY: fn contract maps and pins every safe chain page.
        let page = unsafe { &*(va as *const CollisionPage) };
        if page.count as usize > COLLISIONS_PER_PAGE { return Err(PlanError::Capacity); }
        for collision in &page.entries[..page.count as usize] {
            if !aligned_data_page(collision.source_pa) || !aligned_data_page(collision.destination_pa)
                || collision.source_pa == collision.destination_pa { return Err(PlanError::Alignment); }
            if !safe_contains(p, collision.source_pa) || safe_contains(p, collision.destination_pa) {
                return Err(PlanError::ControlCollision);
            }
            if !p.linear_map.physical.contains_page(collision.source_pa)
                || !p.linear_map.physical.contains_page(collision.destination_pa) {
                return Err(PlanError::Unmapped);
            }
        }
        collisions = collisions.checked_add(page.count as usize).ok_or(PlanError::Capacity)?;
        if page.next_pa != 0 && !aligned_page(page.next_pa) { return Err(PlanError::Alignment); }
        pa = page.next_pa;
        nodes += 1;
    }
    let mut outer_pa = p.collision_head_pa;
    for _ in 0..nodes {
        // SAFETY: first pass proved this node belongs to the pinned safe set.
        let outer = unsafe { &*((outer_pa + p.linear_map.va_offset) as *const CollisionPage) };
        for collision in &outer.entries[..outer.count as usize] {
            let mut sources = 0usize;
            let mut destinations = 0usize;
            let mut inner_pa = p.collision_head_pa;
            for _ in 0..nodes {
                // SAFETY: first pass bounded and admitted every chain node.
                let inner = unsafe { &*((inner_pa + p.linear_map.va_offset) as *const CollisionPage) };
                for other in &inner.entries[..inner.count as usize] {
                    sources += usize::from(other.source_pa == collision.source_pa);
                    destinations += usize::from(other.destination_pa == collision.destination_pa);
                }
                inner_pa = inner.next_pa;
            }
            if sources != 1 || destinations != 1 { return Err(PlanError::DuplicateDestination); }
        }
        outer_pa = outer.next_pa;
    }
    Ok(collisions)
}
