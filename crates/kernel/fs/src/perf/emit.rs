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

use sched::perf_sw::{CpuSw, SwSite};

use super::counter::{format_group, format_one, MemberRead, SwSource, TaskCount};
use super::event::{now_ns, PerfEvent};
use super::overflow::account;
use super::registry;
use super::throttle;
use super::sample::{lost_record, sample_record, SampleValues};
use super::uapi::{fmt, record, sample};

/// Install the sampler. Called once from kernel init; until it runs the
/// counter sites do nothing beyond their accumulator update, which is exactly
/// the state of a kernel with no perf events open. # C: O(1)
pub fn init() {
    sched::perf_sw::set_sample_hook(on_sw_event);
    sched::perf_sw::set_switch_hook(on_switch);
    // `perf_event_comm(tsk, exec)`, emitted by the one function that writes
    // `comm` — so a `prctl(PR_SET_NAME)`, a `/proc/<pid>/comm` write and an
    // `execve` all report without any of them naming perf.
    sched::set_comm_hook(on_comm);
    // The bottom half that runs the opportunities the runqueue-locked sites
    // parked — the reference's `irq_work`, on the mechanism oxide has.
    sched::perf_sw::init_softirq();
    // The tick that releases throttled events (`perf_event_task_tick`).
    super::throttle::init();
}

/// `perf_event_switch(task, next_prev, sched_in)` — the reference emits BOTH
/// sides of a switch: a `SWITCH_OUT` record against the outgoing task and a
/// switch-in record against the incoming one.
/// # C: O(events attached to either task)
fn on_switch(cpu: usize, n: sched::perf_sw::SwitchNote) {
    let c = cpu as i32;
    super::sideband::switch(n.prev_tid, c, true, n.preempt, n.next_pid, n.next_tid);
    super::sideband::switch(n.next_tid, c, false, false, n.prev_pid, n.prev_tid);
}

/// `perf_event_comm(task, exec)` — the task was renamed. `exec` is the
/// `execve` form and sets `PERF_RECORD_MISC_COMM_EXEC`.
/// # C: O(events attached to this task)
fn on_comm(tid: u32, cpu: i32, name: &[u8], exec: bool) {
    super::sideband::comm(tid, cpu, name, exec);
}

/// `perf_sw_event(event_id, nr, regs, addr)`. Runs in the charging site's own
/// context (process context for a page fault), takes no lock the caller holds,
/// and allocates nothing on the sampling path.
/// # C: O(events attached to this context)
fn on_sw_event(site: &SwSite) {
    if !registry::any_registered() { return; }
    // The task the units were CHARGED to. An inline site charges `current`, so
    // it carries no identity and `current` is the answer; a site whose
    // opportunity was parked inside the runqueue-locked region and drained
    // later carries the charged task explicitly, because by drain time
    // `current` is somebody else. Attributing a switch to the task that ran
    // after it is exactly the misattribution a profile must not have.
    let cur = sched::current();
    let (pid, tid) = match site.charged {
        Some(c) => (c.pid, c.tid),
        None => match cur.as_ref() {
            Some(c) => (c.tgid.load(core::sync::atomic::Ordering::Relaxed), c.tid),
            None    => (0, 0),
        },
    };
    // The task-scoped events walked are the charged task's, for the same
    // reason: a `PERF_COUNT_SW_CONTEXT_SWITCHES` event attached to the
    // outgoing task must see its own switch.
    if tid != 0 {
        for ev in registry::live_task_events(tid) { sample_one(&ev, site, pid, tid); }
    }
    for ev in registry::live_cpu_events(site.cpu as i32) {
        sample_one(&ev, site, pid, tid);
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

fn sample_one(ev: &Arc<PerfEvent>, site: &SwSite, pid: u32, tid: u32) {
    if !source_matches(ev.source, site.kind) { return; }
    deliver(ev, site, pid, tid, None);
}

/// `__perf_event_overflow` for one event, past the point at which the caller
/// has established that this event wants this opportunity.
///
/// `forced_period` is the hrtimer path's `hwc->last_period`: a timer-driven
/// PMU emits one record per expiry and reports the timer's own period, rather
/// than running the software-counter budget `perf_swevent_set_period` keeps for
/// the counter sites.
/// # C: O(record bytes)
pub fn deliver(ev: &Arc<PerfEvent>, site: &SwSite, pid: u32, tid: u32,
               forced_period: Option<u64>)
{
    if !ev.attr.is_sampling() { return; }
    // An inherited child publishes into its parent's ring, and reports the
    // parent's id — `__perf_output_begin` and `primary_event_id`.
    let Some(out) = ev.output_target() else { return };
    let Some(rb) = out.buffer() else { return };

    // Decide under the event's own lock, then release it: the ring lock ranks
    // BELOW `PerfEvent::state`, so the two are never held together.
    let (fired, period) = {
        let mut g = ev.state.lock();
        // A disabled event counts nothing and samples nothing —
        // `perf_swevent_event`'s `state != PERF_EVENT_STATE_ACTIVE` return.
        if !g.counter.enabled { return; }
        // A throttled event drops the whole opportunity, which is what makes
        // the throttle bound the sampling RATE rather than just the number of
        // records that reach the ring.
        if throttle::is_throttled(&g.interrupts) { return; }
        match forced_period {
            Some(p) => (1, p),
            None => {
                let o = account(&mut g.hw, ev.attr.sample_type, ev.attr.freq(), site.nr);
                (o.count, o.period)
            }
        }
    };
    if fired == 0 { return; }

    let v = SampleValues {
        id: out.id, stream_id: ev.id,
        // `perf_instruction_pointer(event, regs)` and `data->addr`, both taken
        // from the trap frame the counter site was handed. A site with no frame
        // (the scheduler's) reports `ip: 0`, which is the reference's encoding
        // for a sample whose PMU supplied no instruction pointer.
        ip: site.ip, addr: site.addr,
        pid, tid, time: now_ns(),
        cpu: site.cpu as u32, period,
    };
    let misc = if site.user { record::MISC_USER } else { record::MISC_KERNEL };
    let read_payload = read_payload(ev, out.attr.sample_type);
    let sample_id_all = ev.attr.bit(super::uapi::attr_bit::SAMPLE_ID_ALL);
    let st = out.attr.sample_type;

    let mut wake = false;
    let seq = throttle::seq(site.cpu);
    let budget = sched::perf_sw::max_samples_per_tick();
    for i in 0..fired {
        // The FIRST record of a counter-site burst is exempt from the budget
        // and every one after it is charged, so a single counter overflow can
        // never throttle on its own. A timer-driven expiry arrives one record
        // at a time and IS charged, which is what bounds a short-period clock
        // event.
        let hit = {
            let mut g = ev.state.lock();
            throttle::account(&mut g.interrupts, seq, i > 0 || forced_period.is_some(), budget)
        };
        if hit {
            // The marker goes in first and THIS record still goes out, then
            // the burst stops: the marker precedes the last sample the event is
            // allowed for this tick.
            throttle::park_group(ev, site.cpu);
        }
        let rec = match sample_record(st, misc, &v, read_payload.as_slice()) {
            Some(r) => r,
            None    => {
                rb.note_lost();
                ev.state.lock().lost_samples += 1;
                if hit { break; }
                continue;
            }
        };
        match rb.output(rec.as_slice(), |lost| lost_record::<{ super::sample::MAX_RECORD }>(st, sample_id_all, lost, &v)) {
            Some(w) => wake |= w.wakeup,
            None    => ev.state.lock().lost_samples += 1,
        }
        if hit { break; }
    }
    // `perf_output_wakeup`: the wake belongs to the event that OWNS the ring
    // (an inherited child publishes into its parent's), and runs after the
    // records are visible so a woken consumer finds them.
    if wake { out.wakeup(); }
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

    use super::super::attr::PerfAttr;
    use super::super::ring::PerfBuffer;
    use super::super::uapi::sample;

    /// A sampling page-fault event with a heap-backed ring already attached —
    /// the state a `perf record` consumer's `mmap` leaves behind.
    fn mapped_event(sample_type: u64) -> Arc<PerfEvent> {
        let attr = PerfAttr { sample_period: 1, sample_type, ..PerfAttr::default() };
        let ev = PerfEvent::new(attr, SwSource::TaskCount(TaskCount::PageFaultsMin), None, 0, None);
        ev.state.lock().buffer = Some(PerfBuffer::hosted(2, 0, false));
        ev
    }

    fn site(ip: u64, addr: u64, user: bool) -> SwSite {
        SwSite { kind: CpuSw::MinFlt, cpu: 0, nr: 1, ip, addr, user, charged: None }
    }

    fn u64_at(rec: &[u8], i: usize) -> u64 {
        u64::from_le_bytes(rec[8 + i * 8..16 + i * 8].try_into().unwrap())
    }

    /// The trap frame's PC reaches `PERF_SAMPLE_IP`. Before the counter sites
    /// carried one this field was hard-zero, and `perf report` could not
    /// attribute a single sample.
    #[test]
    fn the_counter_sites_trap_pc_lands_in_sample_ip() {
        let ev = mapped_event(sample::IP | sample::ADDR);
        let rb = ev.buffer().unwrap();
        sample_one(&ev, &site(0xffff_8000_1234_5678, 0x7f00_0000_9000, false), 7, 9);
        let rec = rb.peek_data(0, 24);
        assert_eq!(u32::from_le_bytes(rec[0..4].try_into().unwrap()), record::SAMPLE);
        assert_eq!(u64_at(&rec, 0), 0xffff_8000_1234_5678, "PERF_SAMPLE_IP");
        assert_eq!(u64_at(&rec, 1), 0x7f00_0000_9000, "PERF_SAMPLE_ADDR");
    }

    /// `user_mode(regs)` selects the record's `misc` provenance, so a
    /// user-mode fault and a kernel-mode one are distinguishable.
    #[test]
    fn the_frames_privilege_level_selects_the_record_misc() {
        let ev = mapped_event(sample::IP);
        let rb = ev.buffer().unwrap();
        sample_one(&ev, &site(0x4000, 0, true), 7, 9);
        assert_eq!(u16::from_le_bytes(rb.peek_data(4, 2).try_into().unwrap()),
                   record::MISC_USER);
        let ev = mapped_event(sample::IP);
        let rb = ev.buffer().unwrap();
        sample_one(&ev, &site(0x4000, 0, false), 7, 9);
        assert_eq!(u16::from_le_bytes(rb.peek_data(4, 2).try_into().unwrap()),
                   record::MISC_KERNEL);
    }

    /// A scheduler site has no trap frame; the reference passes `regs = NULL`
    /// from exactly that place, so the field is zero rather than fabricated.
    #[test]
    fn a_site_without_a_trap_frame_reports_a_zero_ip() {
        let ev = mapped_event(sample::IP);
        let rb = ev.buffer().unwrap();
        sample_one(&ev, &site(0, 0, false), 7, 9);
        assert_eq!(u64_at(&rb.peek_data(0, 16), 0), 0);
    }

    /// A deferred context-switch opportunity reaches the CHARGED task's event,
    /// and the record NAMES that task — although the drain runs in a context
    /// that is not that task.
    ///
    /// This is the misattribution the parked identity exists to prevent: the
    /// `PerfDeferred` softirq runs after the switch, so the task running at
    /// drain time is the INCOMING one while the charge belongs to the outgoing
    /// one. A profile that swaps them blames every switch on its successor.
    #[test]
    fn a_deferred_switch_sample_names_the_charged_task_not_the_drainer() {
        use sched::perf_sw::Charged;
        let attr = PerfAttr { sample_period: 1, sample_type: sample::TID,
                              ..PerfAttr::default() };
        let ev = PerfEvent::new(attr, SwSource::TaskCount(TaskCount::ContextSwitches),
                                Some(6001), -1, None);
        ev.state.lock().buffer = Some(PerfBuffer::hosted(2, 0, false));
        let rb = ev.buffer().unwrap();
        // Nothing about the calling context names task 6001 — only the charge does.
        on_sw_event(&SwSite { kind: CpuSw::ContextSwitch, cpu: 0, nr: 1, ip: 0,
                              addr: 0, user: false,
                              charged: Some(Charged { pid: 5000, tid: 6001 }) });
        let rec = rb.peek_data(0, 16);
        assert_eq!(u32::from_le_bytes(rec[0..4].try_into().unwrap()), record::SAMPLE);
        assert_eq!(u64_at(&rec, 0), 6001u64 << 32 | 5000,
                   "PERF_SAMPLE_TID names the charged task, not the drainer");
    }

    /// The same event must NOT be fed an opportunity charged to a different
    /// task, which is what a drain that fell back to `current` would do.
    #[test]
    fn a_charge_against_another_task_does_not_reach_this_events_ring() {
        use sched::perf_sw::Charged;
        let attr = PerfAttr { sample_period: 1, sample_type: sample::TID,
                              ..PerfAttr::default() };
        let ev = PerfEvent::new(attr, SwSource::TaskCount(TaskCount::ContextSwitches),
                                Some(6002), -1, None);
        ev.state.lock().buffer = Some(PerfBuffer::hosted(2, 0, false));
        let rb = ev.buffer().unwrap();
        on_sw_event(&SwSite { kind: CpuSw::ContextSwitch, cpu: 0, nr: 1, ip: 0,
                              addr: 0, user: false,
                              charged: Some(Charged { pid: 1, tid: 6003 }) });
        assert_eq!(rb.unread(), 0, "another task's switch is not this task's sample");
    }

    /// `perf_output_wakeup`: a record that crosses the watermark wakes the
    /// event's queue; one that does not, does not.
    #[test]
    fn a_watermark_crossing_wakes_the_events_queue() {
        let attr = PerfAttr { sample_period: 1, sample_type: sample::IP,
                              ..PerfAttr::default() };
        let ev = PerfEvent::new(attr, SwSource::TaskCount(TaskCount::PageFaultsMin),
                                None, 0, None);
        // Watermark above one record, so the first sample must NOT wake.
        ev.state.lock().buffer = Some(PerfBuffer::hosted(2, 64, false));
        let before = ev.waitq.generation();
        sample_one(&ev, &site(0x1000, 0, false), 7, 9);
        assert_eq!(ev.waitq.generation(), before, "below the watermark, nobody is woken");
        for _ in 0..8 { sample_one(&ev, &site(0x1000, 0, false), 7, 9); }
        assert!(ev.waitq.generation() > before, "the crossing ran perf_output_wakeup");
    }
}
