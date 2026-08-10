// Side-band record emission — `perf_event_mmap`, `perf_event_comm`,
// `perf_event_fork`, `perf_event_exit` and `perf_event_switch`.
//
// A sample carries an instruction pointer; only these records say what that
// pointer POINTS AT. Without them `perf report` has an address and no way to
// name the object it fell in, which is why the reference emits them from the
// sites that already know — the mapping call, the exec, the fork, the exit and
// the context switch.
//
// Module manifest:
//   record  the `PERF_RECORD_*` byte layouts (pure)
//
// Routing mirrors `perf_iterate_sb`: a record reaches the CPU-wide events on
// this CPU and the task-scoped events of the task the record is ABOUT. There
// is no separate side-band registry — `registry` is the one table.

pub mod record;

use alloc::sync::Arc;

use super::event::{now_ns, PerfEvent};
use super::registry;
use super::sample::SampleValues;
use super::uapi::{attr_bit, record as rec, sample as samp};

pub use record::MmapInfo;

/// Deliver one already-built record to every event `want` accepts, on the
/// contexts a side-band record reaches. The builder runs once per event because
/// the trailer's contents depend on that event's `sample_type` and ids.
fn iterate_sb<W, B>(tid: u32, cpu: i32, want: W, build: B)
where W: Fn(&Arc<PerfEvent>) -> bool,
      B: Fn(&Arc<PerfEvent>, &SampleValues) -> Option<record::SbBuf>
{
    if !registry::any_registered() { return; }
    for ev in registry::live_task_events(tid) { one(&ev, tid, cpu, &want, &build); }
    for ev in registry::live_cpu_events(cpu)  { one(&ev, tid, cpu, &want, &build); }
}

fn one<W, B>(ev: &Arc<PerfEvent>, tid: u32, cpu: i32, want: &W, build: &B)
where W: Fn(&Arc<PerfEvent>) -> bool,
      B: Fn(&Arc<PerfEvent>, &SampleValues) -> Option<record::SbBuf>
{
    if !want(ev) { return; }
    // A side-band record is not a sample: it carries no period budget and is
    // emitted whether or not the event is currently counting. It does need a
    // ring, and an inherited child publishes into its parent's.
    let Some(out) = ev.output_target() else { return };
    let Some(rb) = out.buffer() else { return };
    let v = SampleValues {
        id: out.id, stream_id: ev.id, ip: 0, addr: 0, period: 0,
        pid: pid_of(tid), tid, time: now_ns(), cpu: cpu.max(0) as u32,
    };
    let Some(r) = build(&out, &v) else { return };
    let st = out.attr.sample_type;
    let all = out.attr.bit(attr_bit::SAMPLE_ID_ALL);
    match rb.output(r.as_slice(), |lost| super::sample::lost_record::<{ record::SIDEBAND_MAX }>(st, all, lost, &v)) {
        Some(w) => if w.wakeup { out.wakeup(); },
        None    => { rb.note_lost(); }
    }
}

fn pid_of(tid: u32) -> u32 {
    sched::registry::lookup(tid)
        .map(|t| t.tgid.load(core::sync::atomic::Ordering::Relaxed))
        .unwrap_or(tid)
}

/// `perf_event_mmap` — a new mapping came into existence.
///
/// `perf_event_mmap_match`: a code mapping goes to `attr.mmap`/`attr.mmap2`
/// events, a data mapping ONLY to `attr.mmap_data` ones. An event with
/// `attr.mmap2` gets the augmented record.
/// # C: O(events × name)
pub fn mmap(tid: u32, cpu: i32, m: &MmapInfo) {
    let exec = m.executable;
    iterate_sb(tid, cpu,
        |ev| if exec { ev.attr.bit(attr_bit::MMAP) || ev.attr.bit(attr_bit::MMAP2) }
             else    { ev.attr.bit(attr_bit::MMAP_DATA) },
        |ev, v| record::mmap_record(ev.attr.sample_type,
                                    ev.attr.bit(attr_bit::SAMPLE_ID_ALL),
                                    ev.attr.bit(attr_bit::MMAP2), m, v));
}

/// `perf_event_comm(task, exec)` — the task's name changed. `exec` marks the
/// change as an `execve` rather than a `prctl(PR_SET_NAME)`.
/// # C: O(events × name)
pub fn comm(tid: u32, cpu: i32, name: &[u8], exec: bool) {
    iterate_sb(tid, cpu,
        |ev| ev.attr.bit(attr_bit::COMM),
        |ev, v| record::comm_record(ev.attr.sample_type,
                                    ev.attr.bit(attr_bit::SAMPLE_ID_ALL),
                                    exec && ev.attr.bit(attr_bit::COMM_EXEC),
                                    v.pid, v.tid, name, v));
}

/// `perf_event_fork(child)` — the record is ABOUT the child, so it goes to the
/// child's contexts (which a just-inherited event is already in) and names the
/// parent it came from. # C: O(events)
pub fn fork(child_tid: u32, child_pid: u32, parent_tid: u32, parent_pid: u32, cpu: i32) {
    task(rec::FORK, child_tid, child_pid, parent_tid, parent_pid, cpu);
}

/// `perf_event_exit_event` — `PERF_RECORD_EXIT`, same layout, emitted before
/// the task's events are torn down so the record still has a ring to land in.
/// # C: O(events)
pub fn exit(tid: u32, pid: u32, parent_tid: u32, parent_pid: u32, cpu: i32) {
    task(rec::EXIT, tid, pid, parent_tid, parent_pid, cpu);
}

fn task(ty: u32, tid: u32, pid: u32, ptid: u32, ppid: u32, cpu: i32) {
    let now = now_ns();
    iterate_sb(tid, cpu,
        |ev| ev.attr.bit(attr_bit::TASK),
        |ev, v| record::task_record(ty, ev.attr.sample_type,
                                    ev.attr.bit(attr_bit::SAMPLE_ID_ALL),
                                    pid, ppid, tid, ptid, now, v));
}

/// `perf_event_switch(task, next_prev, sched_in)` — one record per side of a
/// context switch, for `attr.context_switch` events only.
///
/// `preempt` is the reference's `PERF_RECORD_MISC_SWITCH_OUT_PREEMPT`: the
/// outgoing task was still runnable, so it was preempted rather than blocking.
/// # C: O(events)
pub fn switch(tid: u32, cpu: i32, switching_out: bool, preempt: bool,
              other_pid: u32, other_tid: u32)
{
    iterate_sb(tid, cpu,
        |ev| ev.attr.bit(attr_bit::CONTEXT_SWITCH),
        |ev, v| record::switch_record(ev.attr.sample_type,
                                      ev.attr.bit(attr_bit::SAMPLE_ID_ALL),
                                      // Only a CPU-wide event may see the
                                      // other task's identity.
                                      ev.tid.is_none(), switching_out, preempt,
                                      other_pid, other_tid, v));
}

/// `sample_type` bits a side-band record's trailer can carry. Exposed so the
/// tests can build an event whose trailer exercises every field.
pub const TRAILER_BITS: u64 = samp::TID | samp::TIME | samp::ID | samp::STREAM_ID
                            | samp::CPU | samp::IDENTIFIER;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::attr::PerfAttr;
    use super::super::counter::{SwSource, TaskCount};
    use super::super::ring::PerfBuffer;

    /// A task id no other case will use.
    ///
    /// An event registers itself against a task in a process-global list, and
    /// every sideband record for that task fans out to EVERY event watching
    /// it. All the cases here used one hard-coded id, so a record one case
    /// emitted landed in a sibling's ring — measured as `unread()` being
    /// non-zero where a case asserts nothing arrived, and as the first record
    /// in a ring belonging to a different case. Distinct ids make each
    /// registration private, which no lock is needed for.
    fn fresh_tid() -> u32 {
        use core::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(424_200);
        NEXT.fetch_add(2, Ordering::Relaxed)
    }

    fn event(bits: u64, tid: u32) -> Arc<PerfEvent> {
        let attr = PerfAttr { bits, sample_type: TRAILER_BITS, ..PerfAttr::default() };
        let ev = PerfEvent::new(attr, SwSource::TaskCount(TaskCount::PageFaultsMin),
                                Some(tid), -1, None);
        ev.state.lock().buffer = Some(PerfBuffer::hosted(4, 0, false));
        ev
    }

    fn ty_of(rb: &PerfBuffer) -> u32 {
        u32::from_le_bytes(rb.peek_data(0, 4).try_into().unwrap())
    }

    fn info<'a>(name: &'a [u8], exec: bool) -> MmapInfo<'a> {
        MmapInfo { addr: 0x40_0000, len: 0x1000, executable: exec, name,
                   ..MmapInfo::default() }
    }

    /// The whole route: a mapping the task made reaches the task's own
    /// `attr.mmap` event and lands in its ring as a `PERF_RECORD_MMAP`.
    #[test]
    fn a_code_mapping_reaches_an_attr_mmap_event() {
        let tid = fresh_tid();
        let ev = event(1 << attr_bit::MMAP, tid);
        let rb = ev.buffer().unwrap();
        mmap(tid, 0, &info(b"/lib/libc.so", true));
        assert_eq!(ty_of(&rb), rec::MMAP);
        assert!(rb.unread() > 0);
    }

    /// `attr.mmap2` selects the augmented record from the same call.
    #[test]
    fn an_attr_mmap2_event_gets_the_augmented_record() {
        let tid = fresh_tid();
        let ev = event(1 << attr_bit::MMAP2, tid);
        let rb = ev.buffer().unwrap();
        mmap(tid, 0, &info(b"/lib/libc.so", true));
        assert_eq!(ty_of(&rb), rec::MMAP2);
    }

    /// `perf_event_mmap_match`: a data mapping is NOT reported to an
    /// `attr.mmap`-only event, and a code mapping is not reported to an
    /// `attr.mmap_data`-only one.
    #[test]
    fn the_mapping_kind_selects_which_events_are_told() {
        let tid = fresh_tid();
        let code_only = event(1 << attr_bit::MMAP, tid);
        let rb = code_only.buffer().unwrap();
        mmap(tid, 0, &info(b"/tmp/heap", false));
        assert_eq!(rb.unread(), 0, "a data mapping is not an attr.mmap record");

        let data_only = event(1 << attr_bit::MMAP_DATA, tid);
        let rb = data_only.buffer().unwrap();
        mmap(tid, 0, &info(b"/lib/libc.so", true));
        assert_eq!(rb.unread(), 0, "a code mapping is not an attr.mmap_data record");
        mmap(tid, 0, &info(b"/tmp/heap", false));
        assert!(rb.unread() > 0);
    }

    /// An event that asked for none of these gets none of them — the records
    /// are gated on the attr bits, not emitted to every ring.
    #[test]
    fn an_event_that_asked_for_nothing_receives_nothing() {
        let tid = fresh_tid();
        let ev = event(0, tid);
        let rb = ev.buffer().unwrap();
        mmap(tid, 0, &info(b"/lib/libc.so", true));
        comm(tid, 0, b"sh", true);
        fork(tid, tid, 1, 1, 0);
        exit(tid, tid, 1, 1, 0);
        switch(tid, 0, true, false, 1, 1);
        assert_eq!(rb.unread(), 0);
    }

    #[test]
    fn comm_fork_exit_and_switch_each_reach_their_own_attr_bit() {
        let tid = fresh_tid();
        for (bits, call, want) in [
            (1u64 << attr_bit::COMM, 0, rec::COMM),
            (1 << attr_bit::TASK,    1, rec::FORK),
            (1 << attr_bit::TASK,    2, rec::EXIT),
            (1 << attr_bit::CONTEXT_SWITCH, 3, rec::SWITCH),
        ] {
            let ev = event(bits, tid);
            let rb = ev.buffer().unwrap();
            match call {
                0 => comm(tid, 0, b"sh", true),
                1 => fork(tid, tid, 1, 1, 0),
                2 => exit(tid, tid, 1, 1, 0),
                _ => switch(tid, 0, true, false, 1, 1),
            }
            assert_eq!(ty_of(&rb), want, "bits {bits:#x}");
        }
    }

    /// A record about ANOTHER task must not land in this task's ring.
    #[test]
    fn a_record_about_a_different_task_does_not_reach_this_events_ring() {
        let tid = fresh_tid();
        let ev = event(1 << attr_bit::COMM, tid);
        let rb = ev.buffer().unwrap();
        comm(tid + 1, 0, b"other", true);
        assert_eq!(rb.unread(), 0);
        comm(tid, 0, b"mine", true);
        assert!(rb.unread() > 0);
    }
}
