// Fork/exit propagation of `attr.inherit` events: the creation side at fork,
// and the fold-back plus `attr.inherit_stat` publication at exit. Pure over the
// registry + `PerfEvent` API, no target gate, so the propagation and fold-back
// algebra are hosted-testable (`docs/53` — decision logic never lives in a
// gated shim).
//
// Only TASK-scoped events (`tid` came back `Some` from admission) are ever
// inheritable. A CPU-wide event (opened with `pid == -1`) has no task to follow
// and is invisible to a fork. Both kinds live in `registry`, which is the
// single table the sample path walks too.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::counter::{format_group, format_one, MemberRead};
use super::event::{now_ns, PerfEvent};
use super::registry::{live_task_events, retire_task, with_context};
use super::sample::SampleValues;
use super::sideband::record::{read_record, SIDEBAND_MAX};
use super::uapi::{attr_bit, fmt};

/// Clone the forking task's inheritable events onto its new child: every event
/// open against the parent with `attr.inherit` set gets a clone that targets
/// the child and starts counting from the fork instant. Without it a child born
/// after an inheriting event was opened gets no event at all, and a read of the
/// parent at `waitpid` time silently undercounts.
///
/// GROUPS are cloned as groups, leader first, so a grouped read on the child's
/// tree returns the same member list the parent's does.
///
/// `clone_thread` is `flags & CLONE_THREAD`: by default an event follows a
/// `fork()`-born PROCESS child but not a `pthread_create()`-born thread, unless
/// it set `attr.inherit_thread`.
///
/// Returns the number of events inherited, for callers/tests that want to
/// confirm propagation happened.
/// # C: O(N_parent_task_events)
pub fn on_fork(parent_tid: u32, child_tid: u32, clone_thread: bool) -> usize {
    let mut n = 0;
    // Every event of the parent's has to make it across for the child's
    // context to be a CLONE of the parent's: the two lists pair positionally
    // during the mid-life synchronisation, and one skipped event puts every
    // later pair against the wrong partner. A partial inherit still inherits —
    // it just leaves the child's context unstamped, so no pairing is claimed.
    let mut all = true;
    for ev in live_task_events(parent_tid) {
        // Groups are inherited leader-first and as a WHOLE: the leader's `attr`
        // decides for every member, and a sibling reached here on its own is
        // skipped so it is not cloned twice.
        if ev.leader.is_some() { continue; }
        if !ev.attr.bit(attr_bit::INHERIT) { all = false; continue; }
        // By default an event follows a `fork()`-born process child but not a
        // thread of the same process; an event that asked to follow threads
        // does both.
        if clone_thread && !ev.attr.bit(attr_bit::INHERIT_THREAD) { all = false; continue; }
        // `PerfEvent::new_inherited` registers the child itself (every
        // task-scoped event self-registers on construction, which is also
        // where the registry takes its owning keep-alive since an inherited
        // child has no fd of its own), so this loop only decides WHICH
        // parent events qualify and how the child-side group is shaped.
        let leader = PerfEvent::new_inherited(&ev, child_tid, None);
        n += 1;
        for sib in ev.siblings() {
            PerfEvent::new_inherited(&sib, child_tid, Some(&leader));
            n += 1;
        }
    }
    if n > 0 && all { stamp_clone(parent_tid, child_tid); }
    n
}

/// Record the child's context as a clone of the parent's, at the parent's
/// current version. Taken after the walk, so the version recorded is the one
/// the child's list actually matches. # C: O(1)
fn stamp_clone(parent_tid: u32, child_tid: u32) {
    let Some(s) = with_context(parent_tid, |c| c.clone_stamp()) else { return };
    with_context(child_tid, |c| c.stamp_clone(s));
}

/// Exit side: publish each `attr.inherit_stat` child's final values as a
/// record, fold every inherited event this exiting task held back into its
/// parent's child totals, then retire the task's registry entry outright —
/// taking back the registry's own keep-alive on each inherited child so it is
/// actually freed here, not merely orphaned. A non-inherited event (this task's
/// own, never anyone's child) folds into nothing and is simply dropped.
/// # C: O(N_tid_events)
pub fn on_task_exit(tid: u32) {
    for ev in retire_task(tid) {
        sync_stat(&ev, tid);
        ev.fold_into_parent();
    }
}

/// `attr.inherit_stat`'s exit half: publish the dying child's own final
/// counter values as a record, so a consumer can attribute them to the CHILD.
/// Without it the counts are only ever visible folded into the parent's total,
/// which is precisely the per-child breakdown the flag asks for.
///
/// Silent for an event that did not ask for it, that was never inherited, or
/// whose tree has no ring mapped. # C: O(group)
fn sync_stat(ev: &Arc<PerfEvent>, tid: u32) {
    if !ev.attr.bit(attr_bit::INHERIT_STAT) { return; }
    if ev.parent.is_none() { return; }
    let Some(out) = ev.output_target() else { return };
    let Some(rb) = out.buffer() else { return };
    let payload = read_payload(ev);
    let v = SampleValues {
        id: out.id, stream_id: ev.id, ip: 0, addr: 0, period: 0,
        pid: pid_of(tid), tid, time: now_ns(), cpu: ev.cpu.max(0) as u32,
    };
    let st = out.attr.sample_type;
    let all = out.attr.bit(attr_bit::SAMPLE_ID_ALL);
    let Some(r) = read_record::<SIDEBAND_MAX>(st, all, v.pid, tid, &payload, &v) else { return };
    match rb.output(r.as_slice(),
                    |lost| super::sample::lost_record::<SIDEBAND_MAX>(st, all, lost, &v)) {
        Some(w) => if w.wakeup { out.wakeup(); },
        None    => { rb.note_lost(); }
    }
}

fn pid_of(tid: u32) -> u32 {
    sched::registry::lookup(tid)
        .map(|t| t.tgid.load(core::sync::atomic::Ordering::Relaxed))
        .unwrap_or(tid)
}

/// The event's counter values framed by its own `read_format` — the same bytes
/// a `read(2)` on it would return.
fn read_payload(ev: &Arc<PerfEvent>) -> Vec<u8> {
    let rf = ev.attr.read_format;
    if rf & fmt::GROUP != 0 {
        let members = ev.group_members();
        if members.is_empty() { return Vec::new(); }
        let (_, enabled, running) = members[0].read_value();
        let vals: Vec<MemberRead> = members.iter()
            .map(|m| MemberRead { count: m.read_value().0, id: m.id,
                                  lost: m.state.lock().lost_samples })
            .collect();
        format_group(rf, &vals, enabled, running)
    } else {
        let (count, enabled, running) = ev.read_value();
        let lost = ev.state.lock().lost_samples;
        format_one(rf, MemberRead { count, id: ev.id, lost }, enabled, running)
    }
}

#[cfg(test)]
mod tests;
