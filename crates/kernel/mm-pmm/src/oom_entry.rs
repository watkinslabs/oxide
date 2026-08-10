//! Allocation-context out-of-memory entry — the allocator slowpath.
//
// Module manifest:
//   this file        — the ungated slowpath decision machine + the gated glue
//                      that runs reclaim and invokes the selector.
//   `oom_entry/tests.rs` — hosted tests for the decision machine.
//
// Shape mirrors the reference page allocator: the fast path takes the buddy
// lock once and, on exhaustion, hands off to a retry loop that reclaims,
// re-tries, and only after reclaim has stopped making progress selects a
// victim.  Selection itself lives in `sched::oom` and is not duplicated here;
// this module is entry wiring only.
//
// Deliberate simplifications against the reference, each with its reason:
//   * No GFP flags exist in this allocator, so the context gate is derived
//     from what the running context can actually do: an atomic context cannot
//     sleep, therefore it cannot reclaim, therefore the reference's
//     `!can_direct_reclaim -> nopage` edge is the whole gate.
//   * The retry viability test is the loop counter only.  The reference also
//     asks whether reclaiming every reclaimable page could meet the watermark
//     and short-circuits to the killer when it could not; that is an
//     optimisation of when the killer runs, not of whether it runs.
//   * The number of killer invocations per allocation is bounded.  The
//     reference loops until the allocation succeeds or nothing is killable,
//     which is safe there because a reaper frees a victim's memory
//     asynchronously.  Recorded in `scratch/known_issues.md`.

#[cfg(test)]
mod tests;

/// Orders above this are not worth killing for: the reference declines the
/// killer for them because a kill frees pages, not contiguity.
pub const PAGE_ALLOC_COSTLY_ORDER: u8 = 3;

/// Reclaim passes without progress after which the allocation stops retrying
/// and asks for a victim.
pub const MAX_RECLAIM_RETRIES: u32 = 16;

/// Killer invocations one allocation may make before it gives up and reports
/// failure to its caller.
pub const MAX_OOM_ATTEMPTS: u32 = 16;

/// What the slowpath does next after one pass.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Re-attempt the allocation; the state that governs it has changed.
    Retry,
    /// Reclaim is exhausted — select and kill a victim, then re-attempt.
    InvokeOom,
    /// Nothing further can change the answer; report allocation failure.
    Fail,
}

/// What one killer invocation achieved.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OomOutcome {
    /// A victim was selected, or one is already on its way out; memory is
    /// expected to come back.
    Progress,
    /// Another CPU holds the selector; it is making progress on our behalf.
    Contended,
    /// Every remaining process is protected. Killing cannot happen here.
    NoKillable,
}

/// Per-allocation slowpath progress.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RetryState {
    /// Consecutive reclaim passes that freed nothing usable.
    pub no_progress_loops: u32,
    /// Killer invocations made for this allocation.
    pub oom_attempts: u32,
}

impl RetryState {
    /// Account one reclaim pass.  A costly-order request always advances the
    /// counter even when reclaim freed pages, because freeing pages does not
    /// produce the contiguity it needs. # C: O(1)
    pub fn note_reclaim(&mut self, did_some_progress: bool, order: u8) {
        if did_some_progress && order <= PAGE_ALLOC_COSTLY_ORDER { self.no_progress_loops = 0; }
        else { self.no_progress_loops = self.no_progress_loops.saturating_add(1); }
    }

    /// Is another reclaim pass still worth taking? # C: O(1)
    pub const fn should_reclaim_retry(&self) -> bool { self.no_progress_loops <= MAX_RECLAIM_RETRIES }
}

/// May this context enter the reclaim/kill slowpath at all?  An atomic caller
/// cannot sleep, so it can neither reclaim nor wait for a victim to exit; its
/// allocation fails immediately, exactly as an allocation without direct
/// reclaim does in the reference. # C: O(1)
pub const fn slowpath_allowed(in_atomic: bool) -> bool { !in_atomic }

/// May an allocation of `order` ask for a victim? # C: O(1)
pub const fn may_invoke_oom(order: u8) -> bool { order <= PAGE_ALLOC_COSTLY_ORDER }

/// Decide what follows one failed allocation plus one reclaim pass.
/// # C: O(1)
pub fn next_step(state: &mut RetryState, order: u8, did_some_progress: bool) -> Step {
    state.note_reclaim(did_some_progress, order);
    if state.should_reclaim_retry() { return Step::Retry; }
    if !may_invoke_oom(order) { return Step::Fail; }
    Step::InvokeOom
}

/// Decide what follows one killer invocation.  A kill is progress, so the
/// reclaim counter restarts and the allocation is re-attempted rather than
/// failed — the memory the victim releases is the point of having killed it.
/// # C: O(1)
pub fn after_oom(state: &mut RetryState, outcome: OomOutcome) -> Step {
    if outcome == OomOutcome::NoKillable { return Step::Fail; }
    state.oom_attempts = state.oom_attempts.saturating_add(1);
    state.no_progress_loops = 0;
    if state.oom_attempts > MAX_OOM_ATTEMPTS { return Step::Fail; }
    Step::Retry
}

/// The slowpath loop: reclaim, re-attempt, and once reclaim stops helping,
/// select a victim and re-attempt again.  `alloc` answers `Some` the moment
/// the allocation succeeds; `None` here is the allocation's final failure.
///
/// TERMINATION. Every pass either advances `no_progress_loops` or consumes one
/// of the bounded killer invocations, and both bounds answer `Fail`.
/// # C: O(MAX_RECLAIM_RETRIES * MAX_OOM_ATTEMPTS) passes
pub fn run_slowpath<T, A, R, O>(order: u8, allowed: bool, mut alloc: A, mut reclaim: R, mut oom: O) -> Option<T>
where A: FnMut() -> Option<T>, R: FnMut() -> bool, O: FnMut() -> OomOutcome {
    if !allowed { return None; }
    let mut state = RetryState::default();
    loop {
        let did_some_progress = reclaim();
        let step = match next_step(&mut state, order, did_some_progress) {
            Step::Fail => return None,
            Step::Retry => Step::Retry,
            Step::InvokeOom => after_oom(&mut state, oom()),
        };
        if step == Step::Fail { return None; }
        if let Some(value) = alloc() { return Some(value); }
    }
}

/// Serializes victim selection across CPUs and against re-entry from the
/// signal/exit work a kill performs, which allocates.
#[cfg(target_os = "oxide-kernel")]
static OOM_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Run the selector under the single-holder guard.  A caller that cannot take
/// the guard does not queue behind it: somebody else is already freeing
/// memory, so it retries instead. # C: O(N_tasks)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn invoke_oom() -> OomOutcome {
    use core::sync::atomic::Ordering;
    if OOM_LOCK.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return OomOutcome::Contended;
    }
    let outcome = sched::oom::out_of_memory(sched::oom::Scope::Global);
    OOM_LOCK.store(false, Ordering::Release);
    match outcome { sched::oom::Outcome::NoKillable => OomOutcome::NoKillable, _ => OomOutcome::Progress }
}

/// Hosted fixtures have no process list, so exhaustion is terminal and the
/// allocator keeps its present behaviour. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn invoke_oom() -> OomOutcome { OomOutcome::NoKillable }

/// One direct reclaim transaction; `true` when it freed something.
/// # C: O(one LRU transaction); # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn reclaim_once() -> bool { crate::kswapd::direct_reclaim_once() }

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn reclaim_once() -> bool { false }

/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn context_allows_slowpath() -> bool { slowpath_allowed(sched::preempt::in_atomic()) }

/// Hosted PMM fixtures run outside any task context and own no reclaimable
/// memory, so the slowpath has nothing to do there. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn context_allows_slowpath() -> bool { false }
