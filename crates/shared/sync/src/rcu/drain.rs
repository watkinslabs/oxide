use super::*;

/// Advance the grace-period state machine one step (caller holds STATE).
/// Completes an in-flight period only after every online CPU quiesces, then
/// opens another when callbacks or a synchronous waiter require one.
fn advance_locked(st: &mut DrainState) -> bool {
    let mask = online();
    let mut advanced = false;
    if st.active {
        if all_quiesced(&st.snap, mask) {
            GP_SEQ.fetch_add(1, Ordering::AcqRel);
            st.active = false;
            advanced = true;
        }
    }
    if !st.active && (!st.waiting.is_empty()
        || GP_SEQ.load(Ordering::Acquire) < GP_REQUESTED.load(Ordering::Acquire)) {
        for c in 0..MAX_CPUS {
            st.snap[c] = CPU_QS[c].0.load(Ordering::Acquire);
        }
        st.active = true;
    }
    advanced
}

/// Drain ready callbacks: pull the incoming ring, advance the grace
/// machine, run callbacks whose target generation has elapsed. Runs
/// callbacks OUTSIDE the lock (they may take other locks / iput). Uses
/// `try_lock` — concurrent drainers cause an early return, never a
/// deadlock against a lock-free `call_rcu`.
/// # C: O(queued)
/// # Ctx: process / softirq
pub(super) fn drain_callbacks() {
    let _ = drain_once();
}

pub(super) fn drain_once() -> usize {
    if DRAIN_ACTIVE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return 0;
    }
    let _run = DrainRun;
    let mut ready: Vec<RcuCallback> = Vec::new();
    let advanced = {
        let mut st = match STATE.try_lock() {
            Some(g) => g,
            None => return 0,
        };
        // 1. Pull sealed work before current-generation work. A barrier
        // marker is therefore behind every callback it sealed, while later
        // callbacks may keep arriving on the current generation.
        let install = BARRIER_INSTALL.load(Ordering::Acquire);
        if install & 1 != 0 { return 0; }
        let generation = INCOMING_GENERATION.load(Ordering::Acquire);
        if BARRIER_INSTALL.load(Ordering::Acquire) != install { return 0; }
        drain_incoming(&INCOMING[(generation ^ 1) & 1], &mut st.waiting);
        drain_incoming(&INCOMING[generation & 1], &mut st.waiting);
        // 2. advance the grace machine.
        let advanced = advance_locked(&mut st);
        // 3. collect callbacks whose grace period has elapsed.
        let seq = GP_SEQ.load(Ordering::Acquire);
        let mut waiting = core::mem::take(&mut st.waiting);
        for (target, f) in waiting.drain(..) {
            if target <= seq {
                ready.push(f);
            } else {
                st.waiting.push((target, f));
            }
        }
        advanced
    };
    let n = ready.len();
    for f in ready {
        f();
        PENDING.fetch_sub(1, Ordering::AcqRel);
    }
    if advanced || n != 0 { notify_waiters(); }
    n
}

