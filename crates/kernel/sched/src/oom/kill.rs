//! The out-of-memory entries: candidate construction, kill, accounting.
//
// Two entries, ONE selector (`super::select`). The global entry walks the
// whole process list; the control-group entry walks one subtree. Neither
// carries selection rules of its own.
//
// Ungated: nothing here needs a live CPU. Without a runqueue there is no
// current task and without an installed observer nothing scores, which is
// exactly what the hosted tests drive.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use cgroup::MemoryEvent;

use super::score::{badness, managed_pages, memory_observer};
use super::select::{select_victim, Candidate, Selection};
use crate::{signum::Signum, Task};

/// Which memory the caller ran out of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// System-wide exhaustion: every process is a candidate.
    Global,
    /// One control group hit its limit: only its subtree is a candidate.
    Memcg(u64),
}

/// What one out-of-memory event did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A victim was chosen and its whole thread group was sent SIGKILL.
    Killed,
    /// The caller is itself dying and will release its memory; it was marked
    /// so nobody else is killed on its behalf.
    SelfWillFree,
    /// An earlier victim has not finished exiting. Nothing new was killed.
    InProgress,
    /// Nothing in this scope may be killed.
    NoKillable,
}

/// What a fault that could not obtain memory must do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultOutcome {
    /// Resume userspace and re-take the faulting instruction. Memory is either
    /// on its way back from a victim that is exiting, or this task is the one
    /// exiting and will not complete the retry.
    Retake,
    /// Out of memory with no process left that may be killed. Retrying would
    /// spin the faulting instruction forever with nothing able to change the
    /// answer.
    Deadlocked,
}

/// Processes killed by the out-of-memory selector since boot (`/proc/vmstat`
/// `oom_kill`). # C: O(1)
pub fn kill_count() -> u64 { OOM_KILLS.load(Ordering::Relaxed) }

static OOM_KILLS: AtomicU64 = AtomicU64::new(0);

/// The out-of-memory entry for a user fault whose fill could not obtain a
/// page.
///
/// A task that is already dying is left alone — it is about to release
/// everything it holds, and the fault it cannot complete will never resume
/// past the pending fatal signal. Otherwise a victim is selected, and the
/// faulting instruction is re-taken so it can use the memory the victim
/// releases.
///
/// TERMINATION. The retry is bounded because every path out of here changes
/// the state the next pass reads: the faulting task is marked and dies on its
/// way back to userspace; or a victim is marked and its exit frees memory; or
/// the scan reports a victim still exiting, which cannot outlive that task;
/// or there is nobody left to kill, and this answers `Deadlocked` rather than
/// asking the caller to try the same thing again.
/// # C: O(N_tasks)
pub fn pagefault_out_of_memory() -> FaultOutcome {
    if current_task().is_some_and(|task| fatal_signal_pending(&task)) { return FaultOutcome::Retake; }
    match out_of_memory(Scope::Global) {
        Outcome::NoKillable => FaultOutcome::Deadlocked,
        _ => FaultOutcome::Retake,
    }
}

/// Choose and kill one process in `scope`.
///
/// A caller that is itself exiting or carrying a fatal signal is selected
/// first: it will release its memory sooner than anything this could kill, and
/// killing a second process on its behalf only widens the damage.
/// # C: O(N_tasks_in_scope)
pub fn out_of_memory(scope: Scope) -> Outcome {
    // The control group observed the failure whatever is decided about it
    // below, so the event is recorded before any path can return.
    if let Scope::Memcg(cgid) = scope { cgroup::record_memory_event(cgid, MemoryEvent::Oom); }
    if let Some(task) = current_task() {
        if will_free_mem(&task) { let _ = task.try_claim_oom_victim(); return Outcome::SelfWillFree; }
    }
    if let Scope::Memcg(cgid) = scope {
        if cgroup::memory_oom_group(cgid) { return kill_whole_cgroup(cgid); }
    }
    let scanned = scan(scope);
    match select_victim(scanned.iter().map(|(candidate, _)| *candidate)) {
        Selection::None => Outcome::NoKillable,
        Selection::InProgress => Outcome::InProgress,
        // Losing the claim race means another CPU marked this same process
        // between the scan and the kill, which is the in-progress answer.
        Selection::Victim(index) => match kill_process(&scanned[index].1) {
            true => Outcome::Killed,
            false => Outcome::InProgress,
        },
    }
}

/// Select the largest concrete-memory consumer in `cgid` and post the
/// canonical fatal signal.  A `memory.oom.group` cgroup instead kills every
/// live member.  Selection reads the same badness snapshot the global scope
/// uses; it never substitutes pid order, runtime, or virtual size for actual
/// resident/swap consumption. # C: O(members)
pub fn kill_memcg(cgid: u64) -> bool {
    matches!(out_of_memory(Scope::Memcg(cgid)), Outcome::Killed)
}

/// `memory.oom.group`: the cgroup is the failure unit, so every member dies
/// rather than one selected process. The protections that survive are the ones
/// that survive everywhere — the init task, kernel threads, and a process
/// pinned at the minimum score adjustment.
/// # C: O(members)
fn kill_whole_cgroup(cgid: u64) -> Outcome {
    let mut killed = false;
    for task in subtree_tasks(cgid) {
        if task.oom_unkillable() || task.oom_score_adj() == super::OOM_SCORE_ADJ_MIN { continue; }
        if !task.oom_alive() || task.clone_mm_for_oom().is_none() { continue; }
        killed |= kill_process(&task);
    }
    match killed { true => Outcome::Killed, false => Outcome::NoKillable }
}

/// Mark one process a victim and send its whole thread group SIGKILL, plus
/// every other thread group sharing its address space — a survivor pinning the
/// mm would keep exactly the memory this event needs back.
///
/// Returns false when the process was already marked, which is what makes a
/// concurrent second event a no-op rather than a second kill.
/// # C: O(N_sharers)
fn kill_process(task: &Arc<Task>) -> bool {
    if !task.try_claim_oom_victim() { return false; }
    OOM_KILLS.fetch_add(1, Ordering::Relaxed);
    cgroup::record_memory_event(cgroup::cgroup_of(u64::from(task.tgid.load(Ordering::Acquire))),
                                MemoryEvent::OomKill);
    report(task);
    sigkill_group(task);
    if let Some(mm) = task.clone_mm_for_oom() {
        for sharer in crate::registry::mm_sharers(&mm) {
            if sharer.tgid.load(Ordering::Acquire) == task.tgid.load(Ordering::Acquire) { continue; }
            // A sharer that may not be killed pins the mm; the kill still
            // stands, the memory just comes back later.
            if sharer.oom_unkillable() || !sharer.oom_alive() { continue; }
            sigkill_group(&sharer);
        }
    }
    true
}

/// The whole process dies, not the one thread the scan happened to name.
fn sigkill_group(task: &Arc<Task>) {
    #[cfg(target_os = "oxide-kernel")]
    crate::live::send_sig_priv_group(task, Signum::Sigkill.as_u8() as u32);
    #[cfg(not(target_os = "oxide-kernel"))]
    task.sigpending.fetch_or(Signum::Sigkill.bit(), Ordering::Release);
}

/// Name the victim on the console.
///
/// The reference reports every kill unconditionally. Here the call site is
/// feature-gated, because `04§4.0` is frozen on every `klog` call being
/// `cfg`-elidable and a default build emitting zero log bytes. A production
/// kill is still counted — `/proc/vmstat` `oom_kill` and the victim cgroup's
/// `memory.events` `oom_kill` — so it is observable, just not on the console.
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
fn report(task: &Arc<Task>) {
    klog::write_raw(b"[OOM] killed process pid=");
    klog::write_dec_u64(u64::from(task.visible_pid()));
    klog::write_raw(b" oom_score_adj=");
    klog::write_dec_u64(i64::from(task.oom_score_adj()) as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(all(target_os = "oxide-kernel", feature = "debug-sched")))]
fn report(_task: &Arc<Task>) {}

/// Linux `task_will_free_mem`: this task is already on its way out and its
/// address space is about to be released, so it needs no help from the
/// selector. Requires an mm — a task that has already dropped one has nothing
/// left to give back.
/// # C: O(1)
fn will_free_mem(task: &Arc<Task>) -> bool {
    task.clone_mm_for_oom().is_some()
        && (task.thread_group.group_exit_status().is_some() || fatal_signal_pending(task))
}

/// A pending SIGKILL, whether posted at the thread or at the process.
/// # C: O(1)
fn fatal_signal_pending(task: &Arc<Task>) -> bool {
    let kill = Signum::Sigkill.bit();
    task.sigpending.load(Ordering::Acquire) & kill != 0
        || task.thread_group.shared_pending() & kill != 0
}

/// The running task as an owned handle, or `None` before a runqueue exists.
/// # C: O(log N)
fn current_task() -> Option<Arc<Task>> {
    crate::live::current().and_then(|task| crate::registry::lookup(task.tid))
}

/// Every live task in `cgid`'s subtree.
/// # C: O(subtree)
fn subtree_tasks(cgid: u64) -> Vec<Arc<Task>> {
    let namespace = namespace_identity::initial(namespace_identity::NamespaceKind::Pid);
    cgroup::subtree_pids(cgid).into_iter()
        .filter_map(|pid| crate::registry::lookup_in_namespace(&namespace, pid as u32))
        .collect()
}

/// Fold the tasks in `scope` into one candidate per process, in the order the
/// scan sees them.
///
/// A process is scored through the first of its threads that still holds an
/// mm, because the thread the scan happened to name may have dropped its own
/// on the way out while the process still owns memory. That thread is also the
/// one the kill names; the signal goes to the whole group either way.
/// # C: O(N_tasks_in_scope · log N_processes)
fn scan(scope: Scope) -> Vec<(Candidate, Arc<Task>)> {
    let tasks = match scope {
        Scope::Global => crate::registry::snapshot(),
        Scope::Memcg(cgid) => subtree_tasks(cgid),
    };
    let mut processes: BTreeMap<u32, Vec<Arc<Task>>> = BTreeMap::new();
    for task in tasks {
        if !task.oom_alive() { continue; }
        processes.entry(task.tgid.load(Ordering::Acquire)).or_default().push(task);
    }
    processes.into_values().map(|threads| candidate(threads)).collect()
}

/// One process as the selector sees it, plus the thread the kill names.
fn candidate(threads: Vec<Arc<Task>>) -> (Candidate, Arc<Task>) {
    let unkillable = threads.iter().any(|task| task.oom_unkillable());
    let already_victim = threads.iter().any(|task| task.oom_marked());
    let holder = threads.iter().find(|task| task.clone_mm_for_oom().is_some());
    let named = holder.unwrap_or(&threads[0]).clone();
    let candidate = Candidate { unkillable, already_victim, badness: holder.and_then(|task| score(task)) };
    (candidate, named)
}

/// This process's badness, or `None` when it cannot be scored: no observer or
/// no total to normalise against, no mm, or a pin at the minimum adjustment.
/// # C: O(1)
fn score(task: &Arc<Task>) -> Option<i128> {
    let adjustment = task.oom_score_adj();
    if adjustment == super::OOM_SCORE_ADJ_MIN { return None; }
    let total = managed_pages();
    if total == 0 { return None; }
    let observer = memory_observer()?;
    let mm = task.clone_mm_for_oom()?;
    Some(badness(observer(&mm)?, adjustment, total))
}
