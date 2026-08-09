// Sample emission — Linux `perf_sw_event()` → `perf_swevent_event()` →
// `perf_swevent_overflow()` → `__perf_event_overflow()` → `perf_event_output()`.
//
// The counter sites that feed this live in crates BELOW `fs` (`mm-pmm`'s fault
// path charges `PERF_COUNT_SW_PAGE_FAULTS*`), so they reach it through the
// function-pointer hook `sched::perf_sw` owns — the same shape every other
// upward call in this tree uses. `sched` is the one crate both sides depend on,
// so the hook keeps the counter and its sampler naming ONE set of software
// event ids rather than two.

use alloc::sync::Arc;

use sched::perf_sw::CpuSw;

use super::counter::{format_group, format_one, MemberRead, SwSource, TaskCount};
use super::event::{now_ns, PerfEvent};
use super::overflow::account;
use super::registry;
use super::sample::{lost_record, sample_record, SampleValues};
use super::uapi::{fmt, record, sample};

/// Install the sampler. Called once from kernel init; until it runs the
/// counter sites do nothing beyond their accumulator update, which is exactly
/// the state of a kernel with no perf events open. # C: O(1)
pub fn init() { sched::perf_sw::set_sample_hook(on_sw_event); }

/// `perf_sw_event(event_id, nr, regs, addr)`. Runs in the charging site's own
/// context (process context for a page fault), takes no lock the caller holds,
/// and allocates nothing on the sampling path.
/// # C: O(events attached to this context)
fn on_sw_event(kind: CpuSw, cpu: usize, nr: u64, addr: u64, user: bool) {
    if !registry::any_registered() { return; }
    let cur = sched::current();
    let (pid, tid) = match cur.as_ref() {
        Some(c) => (c.tgid.load(core::sync::atomic::Ordering::Relaxed), c.tid),
        None    => (0, 0),
    };
    if let Some(c) = cur.as_ref() {
        for ev in registry::live_task_events(c.tid) { sample_one(&ev, kind, cpu, nr, addr, user, pid, tid); }
    }
    for ev in registry::live_cpu_events(cpu as i32) {
        sample_one(&ev, kind, cpu, nr, addr, user, pid, tid);
    }
}

/// Whether a counter site's event id is the one this event was opened for —
/// Linux's `swevent_hlist` bucket, expressed over the decoded source.
/// # C: O(1)
pub fn source_matches(source: SwSource, kind: CpuSw) -> bool {
    match (source, kind) {
        (SwSource::TaskCount(TaskCount::PageFaultsMin), CpuSw::MinFlt) => true,
        (SwSource::TaskCount(TaskCount::PageFaultsMaj), CpuSw::MajFlt) => true,
        (SwSource::TaskCount(TaskCount::PageFaultsAll), CpuSw::MinFlt | CpuSw::MajFlt) => true,
        (SwSource::TaskCount(TaskCount::ContextSwitches), CpuSw::ContextSwitch) => true,
        (SwSource::TaskCount(TaskCount::CpuMigrations), CpuSw::Migration) => true,
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn sample_one(ev: &Arc<PerfEvent>, kind: CpuSw, cpu: usize, nr: u64, addr: u64,
              user: bool, pid: u32, tid: u32)
{
    if !source_matches(ev.source, kind) { return; }
    if !ev.attr.is_sampling() { return; }
    // An inherited child publishes into its parent's ring, and reports the
    // parent's id — `__perf_output_begin` and `primary_event_id`.
    let Some(out) = ev.output_target() else { return };
    let Some(rb) = out.buffer() else { return };

    // Decide under the event's own lock, then release it: the ring lock ranks
    // BELOW `PerfEvent::state`, so the two are never held together.
    let (fired, period, enabled_read) = {
        let mut g = ev.state.lock();
        if !g.counter.enabled { return; }
        let o = account(&mut g.hw, ev.attr.sample_type, ev.attr.freq(), nr);
        (o.count, o.period, g.counter.enabled)
    };
    if fired == 0 || !enabled_read { return; }

    let v = SampleValues {
        id: out.id, stream_id: ev.id,
        // No trap frame reaches the software counter sites, so the sampled
        // instruction pointer is unavailable; the faulting DATA address is.
        ip: 0, addr,
        pid, tid, time: now_ns(),
        cpu: cpu as u32, period,
    };
    let misc = if user { record::MISC_USER } else { record::MISC_KERNEL };
    let read_payload = read_payload(ev, out.attr.sample_type);
    let sample_id_all = ev.attr.bit(super::uapi::attr_bit::SAMPLE_ID_ALL);
    let st = out.attr.sample_type;

    for _ in 0..fired {
        let Some(rec) = sample_record(st, misc, &v, read_payload.as_slice()) else {
            rb.note_lost();
            ev.state.lock().lost_samples += 1;
            continue;
        };
        let ok = rb.output(rec.as_slice(), |lost| lost_record(st, sample_id_all, lost, &v));
        if !ok { ev.state.lock().lost_samples += 1; }
    }
}

/// The `PERF_SAMPLE_READ` body — the same bytes `read(2)` returns for this
/// event's `read_format` (`perf_output_read`). Empty when the bit is clear.
/// # C: O(group members)
fn read_payload(ev: &Arc<PerfEvent>, sample_type: u64) -> ReadPayload {
    let mut out = ReadPayload::default();
    if sample_type & sample::READ == 0 { return out; }
    let rf = ev.attr.read_format;
    let bytes = if rf & fmt::GROUP != 0 {
        let members = ev.group_members();
        if members.is_empty() { return out; }
        let (_, enabled, running) = members[0].read_value();
        let vals: alloc::vec::Vec<MemberRead> = members.iter()
            .map(|m| MemberRead { count: m.read_value().0, id: m.id,
                                  lost: m.state.lock().lost_samples })
            .collect();
        format_group(rf, &vals, enabled, running)
    } else {
        let (count, enabled, running) = ev.read_value();
        let lost = ev.state.lock().lost_samples;
        format_one(rf, MemberRead { count, id: ev.id, lost }, enabled, running)
    };
    out.set(&bytes);
    out
}

/// Fixed-capacity carrier for the read payload so the sample path stays inside
/// one record's worth of stack.
struct ReadPayload { buf: [u8; super::sample::MAX_RECORD], len: usize }

impl Default for ReadPayload {
    fn default() -> Self { ReadPayload { buf: [0u8; super::sample::MAX_RECORD], len: 0 } }
}

impl ReadPayload {
    fn set(&mut self, b: &[u8]) {
        let n = core::cmp::min(b.len(), self.buf.len());
        self.buf[..n].copy_from_slice(&b[..n]);
        self.len = n;
    }
    fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_fault_site_only_feeds_the_page_fault_events() {
        assert!(source_matches(SwSource::TaskCount(TaskCount::PageFaultsMin), CpuSw::MinFlt));
        assert!(!source_matches(SwSource::TaskCount(TaskCount::PageFaultsMin), CpuSw::MajFlt));
        assert!(source_matches(SwSource::TaskCount(TaskCount::PageFaultsMaj), CpuSw::MajFlt));
        // `PERF_COUNT_SW_PAGE_FAULTS` is the sum, so both sites feed it.
        assert!(source_matches(SwSource::TaskCount(TaskCount::PageFaultsAll), CpuSw::MinFlt));
        assert!(source_matches(SwSource::TaskCount(TaskCount::PageFaultsAll), CpuSw::MajFlt));
        assert!(source_matches(SwSource::TaskCount(TaskCount::ContextSwitches), CpuSw::ContextSwitch));
        assert!(source_matches(SwSource::TaskCount(TaskCount::CpuMigrations), CpuSw::Migration));
        // The clock PMUs are hrtimer-driven, never charged from a counter site.
        assert!(!source_matches(SwSource::CpuClock, CpuSw::MinFlt));
        assert!(!source_matches(SwSource::TaskClock, CpuSw::ExecNs));
        assert!(!source_matches(SwSource::Zero, CpuSw::MinFlt));
    }
}
