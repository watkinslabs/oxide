//! Memcg OOM victim selection and fatal signal delivery.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{signum::Signum, Task, TaskState};

/// Linux `OOM_SCORE_ADJ_MIN`, `OOM_SCORE_ADJ_MAX`, and score divisor.
pub const OOM_SCORE_ADJ_MIN: i32 = -1000;
pub const OOM_SCORE_ADJ_MAX: i32 = 1000;
const OOM_SCORE_ADJ_SCALE: i64 = 1000;
/// PID of the globally protected init task.
const INITIAL_PID: u32 = 1;
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

static MANAGED_PAGES: AtomicU64 = AtomicU64::new(0);
static MEMORY_OBSERVER: AtomicU64 = AtomicU64::new(0);

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

fn memory_observer() -> Option<OomMemoryObserver> {
    let raw = MEMORY_OBSERVER.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: only `install_memory_observer` stores this atomic, from a
    // same-process function pointer with the exact declared signature.
    Some(unsafe { core::mem::transmute::<usize, OomMemoryObserver>(raw as usize) })
}

fn lookup(pid: u64) -> Option<Arc<Task>> {
    let namespace = namespace_identity::initial(namespace_identity::NamespaceKind::Pid);
    crate::registry::lookup_in_namespace(&namespace, pid as u32)
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

    fn oom_eligible(&self) -> bool {
        self.state() != TaskState::Zombie
            && !self.reaped.load(Ordering::Acquire)
            && !self.oom_victim.load(Ordering::Acquire)
    }

    fn try_claim_oom_victim(&self) -> bool {
        self.oom_eligible()
            && self.oom_victim.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }
}

fn eligible_leader(task: &Task) -> bool {
    task.tid == task.tgid.load(Ordering::Acquire)
        && task.oom_eligible()
        && task.oom_score_adj() != OOM_SCORE_ADJ_MIN
}

fn eligible_group_member(task: &Task) -> bool {
    task.oom_eligible()
        && task.oom_score_adj() != OOM_SCORE_ADJ_MIN
        && task.visible_pid() != INITIAL_PID
}

fn post_kill(task: &Arc<Task>) -> bool {
    if !task.try_claim_oom_victim() { return false; }
    task.sigpending.fetch_or(Signum::Sigkill.bit(), Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    crate::live::signal_wake_up(task);
    true
}

fn badness(memory: OomMemory, adjustment: i32, managed_pages: u64) -> i128 {
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
    let managed_pages = MANAGED_PAGES.load(Ordering::Acquire);
    let observer = memory_observer()?;
    if managed_pages == 0 { return None; }
    let mm = task.clone_mm_for_oom()?;
    let score = badness(observer(&mm)?, task.oom_score_adj(), managed_pages).max(0);
    let total = i128::from(managed_pages) * i128::from(PSS_UNITS_PER_PAGE);
    Some((score.saturating_mul(i128::from(OOM_SCORE_ADJ_SCALE)) / total) as u64)
}

/// Select the largest concrete-memory consumer in `cgid` and post the
/// canonical fatal signal.  A `memory.oom.group` cgroup instead kills every
/// live member.  The selector pins each candidate mm before reading its VMM
/// badness snapshot; it never substitutes pid order, runtime, or virtual
/// size for actual resident/swap consumption. # C: O(members)
pub fn kill_memcg(cgid: u64) -> bool {
    let managed_pages = MANAGED_PAGES.load(Ordering::Acquire);
    let Some(observer) = memory_observer() else { return false; };
    if managed_pages == 0 { return false; }
    let members = cgroup::subtree_pids(cgid);
    cgroup::record_memory_event(cgid, cgroup::MemoryEvent::Oom);
    if cgroup::memory_oom_group(cgid) {
        let mut killed = false;
        for pid in members {
            let Some(task) = lookup(pid) else { continue; };
            if !eligible_group_member(&task) || task.clone_mm_for_oom().is_none() { continue; }
            killed |= post_kill(&task);
        }
        if killed { cgroup::record_memory_event(cgid, cgroup::MemoryEvent::OomKill); }
        return killed;
    }
    let mut victim: Option<(i128, Arc<Task>)> = None;
    for pid in members {
        let Some(task) = lookup(pid) else { continue; };
        if !eligible_leader(&task) { continue; }
        let Some(mm) = task.clone_mm_for_oom() else { continue; };
        let Some(memory) = observer(&mm) else { continue; };
        let badness = badness(memory, task.oom_score_adj(), managed_pages);
        if victim.as_ref().map(|(score, _)| badness > *score).unwrap_or(true) {
            victim = Some((badness, task));
        }
    }
    let Some((_badness, task)) = victim else { return false; };
    if !post_kill(&task) { return false; }
    cgroup::record_memory_event(cgid, cgroup::MemoryEvent::OomKill);
    true
}
