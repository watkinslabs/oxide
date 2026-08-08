//! `oom_score_adj` ABI, the PMM memory observer, and the badness function.

use core::sync::atomic::Ordering;

use crate::{Task, TaskState};

/// Linux `OOM_SCORE_ADJ_MIN`, `OOM_SCORE_ADJ_MAX`, and score divisor.
pub const OOM_SCORE_ADJ_MIN: i32 = -1000;
pub const OOM_SCORE_ADJ_MAX: i32 = 1000;
const OOM_SCORE_ADJ_SCALE: i64 = 1000;
/// PID of the globally protected init task.
pub(super) const INITIAL_PID: u32 = 1;
/// Linux smaps-style fixed-point PSS precision (`PSS_SHIFT = 12`).
pub const PSS_UNITS_PER_PAGE: u64 = 1 << 12;

/// Concrete mm facts supplied by PMM.  Resident pages are PSS fixed-point
/// units derived from the canonical frame mapcount; swap entries remain
/// mappings until swap exposes its own canonical mapcount.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OomMemory {
    pub proportional_resident_units: u64,
    pub proportional_swap_units: u64,
    pub page_table_pages: u64,
}

pub type OomMemoryObserver = fn(&vmm::AddressSpace) -> Option<OomMemory>;

static MANAGED_PAGES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MEMORY_OBSERVER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Install the PMM-derived count of managed physical pages.  OOM score
/// adjustment is undefined without this Linux `totalpages` equivalent, so no
/// fallback estimate is used.
pub fn install_managed_pages(managed_pages: u64) {
    MANAGED_PAGES.store(managed_pages, Ordering::Release);
}

/// Install the sole observer that may translate an mm into proportional
/// resident usage. PMM owns physical mapcounts, preventing VMM accounting
/// counters from becoming a competing truth source.
pub fn install_memory_observer(observer: OomMemoryObserver) {
    MEMORY_OBSERVER.store(observer as usize as u64, Ordering::Release);
}

pub(super) fn managed_pages() -> u64 { MANAGED_PAGES.load(Ordering::Acquire) }

pub(super) fn memory_observer() -> Option<OomMemoryObserver> {
    let raw = MEMORY_OBSERVER.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: only `install_memory_observer` stores this atomic, from a
    // same-process function pointer with the exact declared signature.
    Some(unsafe { core::mem::transmute::<usize, OomMemoryObserver>(raw as usize) })
}

impl Task {
    /// Set the Linux OOM score adjustment. Values outside the kernel ABI
    /// range are rejected rather than clamped into a different policy.
    pub fn set_oom_score_adj(&self, adjustment: i32) -> bool {
        if !(OOM_SCORE_ADJ_MIN..=OOM_SCORE_ADJ_MAX).contains(&adjustment) { return false; }
        self.oom_score_adj.store(adjustment, Ordering::Release);
        true
    }

    /// Read this task's Linux OOM score adjustment. # C: O(1)
    pub fn oom_score_adj(&self) -> i32 { self.oom_score_adj.load(Ordering::Acquire) }

    /// Still on the process list as far as selection is concerned: a task that
    /// has become a zombie or been reaped has already released its mm, so the
    /// reference's iteration never reaches it. # C: O(1)
    pub(super) fn oom_alive(&self) -> bool {
        self.state() != TaskState::Zombie && !self.reaped.load(Ordering::Acquire)
    }

    /// Marked by an earlier out-of-memory event and not yet gone. # C: O(1)
    pub(super) fn oom_marked(&self) -> bool { self.oom_victim.load(Ordering::Acquire) }

    pub(super) fn oom_eligible(&self) -> bool { self.oom_alive() && !self.oom_marked() }

    pub(super) fn try_claim_oom_victim(&self) -> bool {
        self.oom_eligible()
            && self.oom_victim.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Never a candidate at any scope: the protected init task and kernel
    /// threads, which own no user memory to reclaim. # C: O(1)
    pub(super) fn oom_unkillable(&self) -> bool {
        self.kernel_thread.load(Ordering::Acquire) || self.visible_pid() == INITIAL_PID
    }
}

/// The reference's badness score in PSS fixed-point units: proportional
/// resident set plus swap plus page tables, biased by `oom_score_adj` scaled
/// against total managed memory.
pub(super) fn badness(memory: OomMemory, adjustment: i32, managed_pages: u64) -> i128 {
    let resident = i128::from(memory.proportional_resident_units);
    let swap = i128::from(memory.proportional_swap_units);
    let page_tables = i128::from(memory.page_table_pages) * i128::from(PSS_UNITS_PER_PAGE);
    let adjustment = i128::from(adjustment) * i128::from(managed_pages)
        * i128::from(PSS_UNITS_PER_PAGE) / i128::from(OOM_SCORE_ADJ_SCALE);
    resident.saturating_add(swap).saturating_add(page_tables).saturating_add(adjustment)
}

/// Linux `/proc/<pid>/oom_score` normalized to the documented 0..=1000
/// scale. It is derived from the same PMM observer used for selection.
pub fn task_score(task: &Task) -> Option<u64> {
    let managed_pages = managed_pages();
    let observer = memory_observer()?;
    if managed_pages == 0 { return None; }
    let mm = task.clone_mm_for_oom()?;
    let score = badness(observer(&mm)?, task.oom_score_adj(), managed_pages).max(0);
    let total = i128::from(managed_pages) * i128::from(PSS_UNITS_PER_PAGE);
    Some((score.saturating_mul(i128::from(OOM_SCORE_ADJ_SCALE)) / total) as u64)
}
