// Software-event counting + `read(2)` framing — Linux `kernel/events/core.c`
// (`perf_swevent_init`, `cpu_clock_event_*`, `task_clock_event_*`,
// `__perf_event_read_size`, `perf_read_one`, `perf_read_group`).
//
// Pure over explicit inputs: the counter source value is passed in, so the
// accumulate/enable/disable algebra and the read framing are hosted-testable.

use alloc::vec::Vec;

use super::uapi::{fmt, sw};

/// Bytes per `u64` slot in the `read(2)` payload.
const SLOT: usize = 8;
/// Linux `perf_event_validate_size()` ceiling on `read_size`.
pub const READ_SIZE_MAX: usize = 16 * 1024;

/// `__perf_event_read_size(read_format, nr_siblings)`. # C: O(1)
pub fn read_size(read_format: u64, nr_siblings: usize) -> usize {
    let mut entry = SLOT;
    let mut size  = 0usize;
    let mut nr    = 1usize;
    if read_format & fmt::TOTAL_TIME_ENABLED != 0 { size  += SLOT; }
    if read_format & fmt::TOTAL_TIME_RUNNING != 0 { size  += SLOT; }
    if read_format & fmt::ID                 != 0 { entry += SLOT; }
    if read_format & fmt::LOST               != 0 { entry += SLOT; }
    if read_format & fmt::GROUP              != 0 { nr += nr_siblings; size += SLOT; }
    size + nr * entry
}

/// One member's contribution to a `read(2)` payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRead {
    pub count: u64,
    pub id:    u64,
    pub lost:  u64,
}

/// `perf_read_one()` — the non-`PERF_FORMAT_GROUP` layout. # C: O(1)
pub fn format_one(read_format: u64, m: MemberRead, enabled: u64, running: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(read_size(read_format, 0));
    push(&mut out, m.count);
    if read_format & fmt::TOTAL_TIME_ENABLED != 0 { push(&mut out, enabled); }
    if read_format & fmt::TOTAL_TIME_RUNNING != 0 { push(&mut out, running); }
    if read_format & fmt::ID                 != 0 { push(&mut out, m.id); }
    if read_format & fmt::LOST               != 0 { push(&mut out, m.lost); }
    out
}

/// `perf_read_group()` — leader first, then siblings in group order.
/// `members[0]` is the leader. # C: O(members)
pub fn format_group(read_format: u64, members: &[MemberRead], enabled: u64, running: u64)
    -> Vec<u8>
{
    let mut out = Vec::with_capacity(read_size(read_format, members.len().saturating_sub(1)));
    push(&mut out, members.len() as u64);
    if read_format & fmt::TOTAL_TIME_ENABLED != 0 { push(&mut out, enabled); }
    if read_format & fmt::TOTAL_TIME_RUNNING != 0 { push(&mut out, running); }
    for m in members {
        push(&mut out, m.count);
        if read_format & fmt::ID   != 0 { push(&mut out, m.id); }
        if read_format & fmt::LOST != 0 { push(&mut out, m.lost); }
    }
    out
}

fn push(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_le_bytes()); }

/// Accumulator shared by every software event: `count` advances by the delta of
/// an externally-sampled monotonic source while the event is enabled, exactly
/// as Linux's `cpu_clock_event_update()`/`task_clock_event_update()` do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwCounter {
    /// Accumulated count over all completed enabled windows.
    pub acc:          u64,
    /// Source value sampled when the current enabled window opened.
    pub base:         u64,
    /// Accumulated `total_time_enabled` over completed windows.
    pub time_acc:     u64,
    /// Monotonic ns when the current enabled window opened.
    pub time_base:    u64,
    pub enabled:      bool,
    /// `PERF_EVENT_IOC_REFRESH` budget; `0` means "no refresh limit in force".
    pub refresh_left: i64,
}

impl SwCounter {
    /// # C: O(1)
    pub fn new(src: u64, now: u64, enabled: bool) -> Self {
        SwCounter { acc: 0, base: src, time_acc: 0, time_base: now, enabled, refresh_left: 0 }
    }
    /// # C: O(1)
    pub fn enable(&mut self, src: u64, now: u64) {
        if self.enabled { return; }
        self.enabled   = true;
        self.base      = src;
        self.time_base = now;
    }
    /// # C: O(1)
    pub fn disable(&mut self, src: u64, now: u64) {
        if !self.enabled { return; }
        self.acc      = self.acc.wrapping_add(src.saturating_sub(self.base));
        self.time_acc = self.time_acc.saturating_add(now.saturating_sub(self.time_base));
        self.enabled  = false;
    }
    /// `_perf_event_reset()` — zero the count, keep enabled/time state.
    /// # C: O(1)
    pub fn reset(&mut self, src: u64) { self.acc = 0; self.base = src; }
    /// Current count. # C: O(1)
    pub fn count(&self, src: u64) -> u64 {
        if self.enabled { self.acc.wrapping_add(src.saturating_sub(self.base)) } else { self.acc }
    }
    /// `total_time_enabled`. Software events are always scheduled when enabled,
    /// so `total_time_running` is identical. # C: O(1)
    pub fn time_enabled(&self, now: u64) -> u64 {
        if self.enabled { self.time_acc.saturating_add(now.saturating_sub(self.time_base)) }
        else            { self.time_acc }
    }
}

/// Which per-task/per-cpu quantity a `PERF_TYPE_SOFTWARE` config selects.
///
/// `perf_swevent_init()` accepts every `config < PERF_COUNT_SW_MAX`; the ones
/// oxide never records (`ALIGNMENT_FAULTS`, `EMULATION_FAULTS`) read zero for
/// the same reason they do on x86_64 Linux — nothing in the kernel ever calls
/// `perf_sw_event()` for them on that architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwSource {
    /// Monotonic clock ns (`perf_cpu_clock` PMU).
    CpuClock,
    /// Task execution ns (`perf_task_clock` PMU).
    TaskClock,
    /// A per-task event counter.
    TaskCount(TaskCount),
    /// Never advanced by this kernel.
    Zero,
}

/// Per-task software-event counters the scheduler/fault paths maintain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskCount {
    PageFaultsMin,
    PageFaultsMaj,
    PageFaultsAll,
    ContextSwitches,
    CpuMigrations,
}

/// `perf_swevent_init()` config → source. `None` == Linux's `-ENOENT`
/// (`config >= PERF_COUNT_SW_MAX`). # C: O(1)
pub fn sw_source(config: u64) -> Option<SwSource> {
    Some(match config {
        sw::CPU_CLOCK        => SwSource::CpuClock,
        sw::TASK_CLOCK       => SwSource::TaskClock,
        sw::PAGE_FAULTS      => SwSource::TaskCount(TaskCount::PageFaultsAll),
        sw::PAGE_FAULTS_MIN  => SwSource::TaskCount(TaskCount::PageFaultsMin),
        sw::PAGE_FAULTS_MAJ  => SwSource::TaskCount(TaskCount::PageFaultsMaj),
        sw::CONTEXT_SWITCHES => SwSource::TaskCount(TaskCount::ContextSwitches),
        sw::CPU_MIGRATIONS   => SwSource::TaskCount(TaskCount::CpuMigrations),
        // Recorded nowhere in this kernel, exactly as on x86_64 Linux.
        sw::ALIGNMENT_FAULTS | sw::EMULATION_FAULTS => SwSource::Zero,
        // `PERF_COUNT_SW_DUMMY` is defined to never count.
        sw::DUMMY            => SwSource::Zero,
        // Only `bpf_perf_event_output()` advances this; oxide loads no programs.
        sw::BPF_OUTPUT       => SwSource::Zero,
        // Requires the perf cgroup controller, which oxide does not build.
        sw::CGROUP_SWITCHES  => SwSource::Zero,
        _ => return None,
    })
}
