//! The out-of-memory reaper's decisions, as pure data, plus its work queue.
//
// The reference answers "what if the victim never dies?" with a kthread: two
// seconds after the kill it drains the victim's own private memory on the
// victim's behalf, and — whether that succeeded or not — marks the mm
// skippable so the selector stops waiting on a process that is never going to
// release anything. Both halves matter. Without the reap, a victim wedged in
// an uninterruptible sleep holds every page it owns; without the skip, every
// later scan reports a kill still in progress and the fault leg re-takes the
// same instruction forever.
//
// WHAT MAY BE REAPED. Private mappings only. A shared mapping is somebody
// else's memory as much as the victim's, so tearing its leaves down would
// take pages out from under a live process; a device range owns no reclaimable
// frames at all; a huge mapping's leaves are block leaves whose home is the
// huge-page pool, not the page allocator. `reapable` is the whole rule and it
// is the ONLY copy — `process_mrelease` reaps through it too, because the
// reference reaches the same function from both entries.
//
// GIVE-UP. Ten attempts, a tenth of a second apart, then the mm is marked
// skippable regardless of whether anything was released. The mark is not a
// reward for success; it is the statement that this mm will not be waited on
// again.
//
// Ungated on purpose: the mapping rule, the give-up ladder and the queue are
// all `cargo test -p sched` provable. `reaper.rs` is the kthread that consumes
// this and carries no policy of its own.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Reclaim, Spinlock};
use vmm::{AddressSpace, Vma, VmaBacking, VmaFlags};

use crate::Task;

/// Attempts before the mm is written off. Linux `MAX_OOM_REAP_RETRIES`.
pub const MAX_REAP_ATTEMPTS: u32 = 10;
/// Grace given to the victim's own exit path before the reaper touches its
/// memory. Reaping sooner races the exit: a robust-futex list living in
/// anonymous memory has to survive long enough for the exit to wake its
/// waiters. Linux `OOM_REAPER_DELAY` (2 s).
pub const REAP_DELAY_NS: u64 = 2_000_000_000;
/// Pause between attempts. Linux `schedule_timeout_idle(HZ/10)`.
pub const REAP_RETRY_NS: u64 = 100_000_000;

/// Whether the reaper may tear down this mapping's leaves.
///
/// Private and not device-backed and not huge — that is the whole rule. A
/// `SHARED` mapping belongs to more than the dying process. `PhysRange` is a
/// device range with no reclaimable frame behind it. `KernelFrame` and
/// `Special` name kernel-owned pages (the vDSO/vvar window) that the victim
/// merely sees. A hugetlbfs mapping installs block leaves whose frames belong
/// to the huge-page pool, and the reaper has no business shrinking a pool an
/// operator sized.
/// # C: O(1)
pub fn reapable(flags: VmaFlags, backing: &VmaBacking) -> bool {
    if flags.contains(VmaFlags::SHARED) { return false; }
    match backing {
        VmaBacking::PhysRange { .. } | VmaBacking::KernelFrame { .. }
            | VmaBacking::KernelPages { .. } | VmaBacking::Special => false,
        VmaBacking::File { backing, .. } => backing.huge_page_size() == 0,
        VmaBacking::Anonymous | VmaBacking::KernelBytes { .. } => true,
    }
}

/// [`reapable`] for a whole descriptor. # C: O(1)
pub fn reapable_vma(vma: &Vma) -> bool { reapable(vma.flags, &vma.backing) }

/// What the reaper does after one pass over a victim's mm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReapStep {
    /// Nothing was released and attempts remain: sleep and walk it again.
    Retry,
    /// The mm was drained. Mark it skippable and stop.
    Drained,
    /// The attempts are spent. Mark it skippable anyway and stop — an mm that
    /// resisted ten passes will not release memory for an eleventh, and the
    /// selector must not keep waiting on it.
    GaveUp,
}

impl ReapStep {
    /// Both terminal steps mark the mm skippable; only the reason differs.
    /// # C: O(1)
    pub fn marks_skippable(self) -> bool { !matches!(self, ReapStep::Retry) }
}

/// The give-up ladder. `attempts` counts passes ALREADY made, so the first
/// call after one failed pass sees 1.
/// # C: O(1)
pub fn after_attempt(attempts: u32, reaped: bool) -> ReapStep {
    if reaped { return ReapStep::Drained; }
    if attempts >= MAX_REAP_ATTEMPTS { return ReapStep::GaveUp; }
    ReapStep::Retry
}

/// The sole owner of leaf teardown over a foreign address space. PMM installs
/// it; the reaper never walks page tables itself, exactly as the badness
/// observer keeps physical accounting on PMM's side of the boundary.
/// Returns 0 on success, a negative errno otherwise.
pub type OomZapper = fn(&AddressSpace, u64, u64) -> i64;

static ZAPPER: AtomicU64 = AtomicU64::new(0);

/// Install the foreign-range evictor the reaper releases memory through.
/// # C: O(1)
pub fn install_oom_zapper(zapper: OomZapper) { ZAPPER.store(zapper as usize as u64, Ordering::Release); }

/// # C: O(1)
pub fn oom_zapper() -> Option<OomZapper> {
    let raw = ZAPPER.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: only `install_oom_zapper` stores this atomic, from a same-process
    // function pointer with the exact declared `OomZapper` signature.
    Some(unsafe { core::mem::transmute::<usize, OomZapper>(raw as usize) })
}

/// One victim awaiting the reaper, with the moment it becomes due.
pub struct Queued {
    pub task: Arc<Task>,
    pub mm: Arc<AddressSpace>,
    pub due_ns: u64,
}

static QUEUE: Spinlock<Vec<Queued>, Reclaim> = Spinlock::new(Vec::new());

/// Queue a victim's mm for reaping `REAP_DELAY_NS` from `now_ns`.
///
/// An mm already queued is not queued twice (Linux `MMF_OOM_REAP_QUEUED`), and
/// one already marked skippable is not queued at all — the victim got there on
/// its own. The queue itself is what "already queued" means; no flag mirrors it.
/// # C: O(N_queued); # Lk: Reclaim
pub fn queue_oom_reaper(task: &Arc<Task>, mm: &Arc<AddressSpace>, now_ns: u64) -> bool {
    if mm.oom_skip() { return false; }
    let mut queue = QUEUE.lock();
    if queue.iter().any(|entry| Arc::ptr_eq(&entry.mm, mm)) { return false; }
    queue.push(Queued { task: Arc::clone(task), mm: Arc::clone(mm), due_ns: now_ns.saturating_add(REAP_DELAY_NS) });
    drop(queue);
    #[cfg(target_os = "oxide-kernel")]
    super::reaper::wake_oom_reaper();
    true
}

/// Take the first victim whose grace period has elapsed.
/// # C: O(N_queued); # Lk: Reclaim
pub fn take_due(now_ns: u64) -> Option<Queued> {
    let mut queue = QUEUE.lock();
    let index = queue.iter().position(|entry| entry.due_ns <= now_ns)?;
    Some(queue.remove(index))
}

/// When the earliest queued victim becomes due, or `None` when nothing is
/// waiting. The kthread parks until this moment rather than polling.
/// # C: O(N_queued); # Lk: Reclaim
pub fn next_due_ns() -> Option<u64> { QUEUE.lock().iter().map(|entry| entry.due_ns).min() }

/// Queue depth. # C: O(1); # Lk: Reclaim
pub fn queued_len() -> usize { QUEUE.lock().len() }

/// Drop every queued victim. Test fixture only — a live queue is drained by
/// the kthread. # C: O(N_queued); # Lk: Reclaim
#[cfg(any(test, feature = "hosted"))]
pub fn clear_queue_for_tests() { QUEUE.lock().clear(); }

#[cfg(test)]
mod tests;
