//! Sole hibernation observability owner (`32b§14-15`).

use super::sequence::Step;

mod undo;
pub use undo::{undo, UndoBoundary};

mod plan;
pub use plan::{restore_plan, restore_plan_collision, restore_plan_facts, restore_plan_reason,
    RestorePlanPhase, RestorePlanReason};

mod cpu;
pub use cpu::cpu_coordinator;

mod compatibility;
pub use compatibility::compatibility;

#[cfg(all(test, feature = "debug-hibernate"))]
#[path = "log/tests.rs"]
mod tests;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Invariant { Policy, Target, Format, Compatibility, Architecture, Checksum, Memory, Restore }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Rollback { NotPublished, Unmarked, UnmarkFailed }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Durability { PayloadFlushed, MarkerCommitted, MarkerConsumed }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResumePath { Cold, Test }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResumePhase { Target, Marker, Admit, Load, SafePlan, Quiesce, Terminal }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NoirqPhase { WakeBegin, WakeEnd, IrqBegin, IrqEnd, DevicesBegin, DevicesEnd }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IrqKind { Line, Msi }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IrqPhase { Descriptor, MaskBegin, MaskEnd, SyncBegin, SyncEnd }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuOffPhase { Request, Callfn, OfflineResult, ConfirmDead, Unwind }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuOffResult { Begin, Ok, Refused, Timeout }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuCallTransport { SameCpu, Offline, Queued, NoHardware, IcrRefused, IcrSent }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SnapshotPhase { Callback, FinalFree, Select, Copy }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SnapshotBoundary { Begin, End }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SnapshotResult { Ok, Inval, Perm, Io, Busy, Nosys, Opnotsupp, Again, Intr, Nomem, Nodata, Nospc }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArchContinuation { CaptureBegin, CaptureEnd }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SerializePhase { Reserve, HeaderRead }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SerializeBoundary { Begin, End }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SerializeWork { PageScratch, Input, Encoder, Chunk, Source, Crc, Append, Encode }

impl From<crate::Error> for SnapshotResult {
    fn from(error: crate::Error) -> Self {
        match error {
            crate::Error::Inval => Self::Inval, crate::Error::Perm => Self::Perm,
            crate::Error::Io => Self::Io, crate::Error::Busy => Self::Busy,
            crate::Error::Nosys => Self::Nosys, crate::Error::Opnotsupp => Self::Opnotsupp,
            crate::Error::Again => Self::Again, crate::Error::Intr => Self::Intr,
            crate::Error::Nomem => Self::Nomem, crate::Error::Nodata => Self::Nodata,
            crate::Error::Nospc => Self::Nospc,
        }
    }
}

pub fn image_created() { klog::kinfo!("hibernate: image created"); }
pub fn image_resumed() { klog::kinfo!("hibernate: image resumed"); }

/// Normal rejection boundary; wording includes durable marker-consumption truth.
pub fn rejected(invariant: Invariant, consumed: bool) {
    match (invariant, consumed) {
        (Invariant::Policy, false) => klog::kerror!("hibernate: rejected policy; marker not consumed"),
        (Invariant::Target, false) => klog::kerror!("hibernate: rejected target; marker not consumed"),
        (Invariant::Format, false) => klog::kerror!("hibernate: rejected format; marker not consumed"),
        (Invariant::Compatibility, false) => klog::kerror!("hibernate: rejected compatibility; marker not consumed"),
        (Invariant::Architecture, false) => klog::kerror!("hibernate: rejected architecture; marker not consumed"),
        (Invariant::Checksum, false) => klog::kerror!("hibernate: rejected checksum; marker not consumed"),
        (Invariant::Memory, false) => klog::kerror!("hibernate: rejected memory; marker not consumed"),
        (Invariant::Restore, false) => klog::kerror!("hibernate: rejected restore; marker not consumed"),
        (Invariant::Policy, true) => klog::kerror!("hibernate: rejected policy; marker consumed"),
        (Invariant::Target, true) => klog::kerror!("hibernate: rejected target; marker consumed"),
        (Invariant::Format, true) => klog::kerror!("hibernate: rejected format; marker consumed"),
        (Invariant::Compatibility, true) => klog::kerror!("hibernate: rejected compatibility; marker consumed"),
        (Invariant::Architecture, true) => klog::kerror!("hibernate: rejected architecture; marker consumed"),
        (Invariant::Checksum, true) => klog::kerror!("hibernate: rejected checksum; marker consumed"),
        (Invariant::Memory, true) => klog::kerror!("hibernate: rejected memory; marker consumed"),
        (Invariant::Restore, true) => klog::kerror!("hibernate: rejected restore; marker consumed"),
    }
}

pub fn rollback(step: Step, outcome: Rollback) {
    match (step, outcome) {
        (Step::Serialize, Rollback::NotPublished) =>
            klog::kerror!("hibernate: serialize failed; marker not published"),
        (Step::Commit, Rollback::Unmarked) =>
            klog::kerror!("hibernate: marker commit failed; image durably unmarked"),
        (Step::Commit, Rollback::UnmarkFailed) =>
            klog::kerror!("hibernate: marker commit failed; unmark failed"),
        (Step::DevicesPoweroff, Rollback::Unmarked) =>
            klog::kerror!("hibernate: device poweroff failed; image unmarked"),
        (Step::Terminal, Rollback::Unmarked) =>
            klog::kerror!("hibernate: terminal transition failed; image unmarked"),
        (Step::DevicesPoweroff, Rollback::UnmarkFailed) =>
            klog::kerror!("hibernate: device poweroff failed; unmark failed"),
        (Step::Terminal, Rollback::UnmarkFailed) =>
            klog::kerror!("hibernate: terminal transition failed; unmark failed"),
        _ => klog::kerror!("hibernate: rollback boundary failed"),
    }
}

#[cfg(feature = "debug-hibernate")]
pub fn phase(step: Step) {
    klog::write_raw(b"[hibernate] phase=");
    klog::write_raw(step_name(step));
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn phase(_: Step) {}

#[cfg(feature = "debug-hibernate")]
pub fn serialize_phase(phase: SerializePhase, boundary: SerializeBoundary) {
    klog::write_raw(b"[hibernate] serialize=");
    klog::write_raw(match phase {
        SerializePhase::Reserve => b"reserve", SerializePhase::HeaderRead => b"header_read",
    });
    klog::write_raw(b" boundary=");
    klog::write_raw(match boundary {
        SerializeBoundary::Begin => b"begin", SerializeBoundary::End => b"end",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn serialize_phase(_: SerializePhase, _: SerializeBoundary) {}

#[cfg(feature = "debug-hibernate")]
pub fn serialize_work(work: SerializeWork, boundary: SerializeBoundary, index: usize, value: usize) {
    klog::write_raw(b"[hibernate] serialize_work=");
    klog::write_raw(match work {
        SerializeWork::PageScratch => b"page_scratch", SerializeWork::Input => b"input",
        SerializeWork::Encoder => b"encoder", SerializeWork::Chunk => b"chunk",
        SerializeWork::Source => b"source", SerializeWork::Crc => b"crc",
        SerializeWork::Append => b"append", SerializeWork::Encode => b"encode",
    });
    klog::write_raw(b" boundary=");
    klog::write_raw(match boundary {
        SerializeBoundary::Begin => b"begin", SerializeBoundary::End => b"end",
    });
    klog::write_raw(b" index="); klog::write_dec_u64(index as u64);
    klog::write_raw(b" value="); klog::write_dec_u64(value as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn serialize_work(_: SerializeWork, _: SerializeBoundary, _: usize, _: usize) {}

#[cfg(feature = "debug-hibernate")]
pub fn target(name: &str, offset: u64, mode: &str) {
    klog::write_raw(b"[hibernate] target="); klog::write_raw(name.as_bytes());
    klog::write_raw(b" offset="); klog::write_dec_u64(offset);
    klog::write_raw(b" mode="); klog::write_raw(mode.as_bytes()); klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn target(_: &str, _: u64, _: &str) {}

#[cfg(feature = "debug-hibernate")]
pub fn counts(image_pages: u64, stream_pages: u64, direct: u64, collision: u64) {
    klog::write_raw(b"[hibernate] image_pages="); klog::write_dec_u64(image_pages);
    klog::write_raw(b" image_bytes=");
    klog::write_dec_u64(image_pages.saturating_mul(super::format::PAGE_SIZE as u64));
    klog::write_raw(b" stream_pages="); klog::write_dec_u64(stream_pages);
    klog::write_raw(b" stream_bytes=");
    klog::write_dec_u64(stream_pages.saturating_mul(super::format::PAGE_SIZE as u64));
    klog::write_raw(b" direct="); klog::write_dec_u64(direct);
    klog::write_raw(b" collision="); klog::write_dec_u64(collision); klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn counts(_: u64, _: u64, _: u64, _: u64) {}

#[cfg(feature = "debug-hibernate")]
pub fn resume_phase(path: ResumePath, phase: ResumePhase) {
    klog::write_raw(b"[hibernate] resume_path=");
    klog::write_raw(match path { ResumePath::Cold => b"cold", ResumePath::Test => b"test" });
    klog::write_raw(b" phase=");
    klog::write_raw(resume_phase_name(phase));
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn resume_phase(_: ResumePath, _: ResumePhase) {}

#[cfg(feature = "debug-hibernate")]
pub fn durability(boundary: Durability) {
    let name: &[u8] = match boundary {
        Durability::PayloadFlushed => b"payload_flushed",
        Durability::MarkerCommitted => b"marker_committed",
        Durability::MarkerConsumed => b"marker_consumed",
    };
    klog::write_raw(b"[hibernate] durability=");
    klog::write_raw(name);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn durability(_: Durability) {}

#[cfg(feature = "debug-hibernate")]
pub fn noirq_phase(phase: NoirqPhase) {
    let name: &[u8] = match phase {
        NoirqPhase::WakeBegin => b"wake_begin", NoirqPhase::WakeEnd => b"wake_end",
        NoirqPhase::IrqBegin => b"irq_begin", NoirqPhase::IrqEnd => b"irq_end",
        NoirqPhase::DevicesBegin => b"devices_begin",
        NoirqPhase::DevicesEnd => b"devices_end",
    };
    klog::write_raw(b"[hibernate] noirq=");
    klog::write_raw(name);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn noirq_phase(_: NoirqPhase) {}

#[cfg(feature = "debug-hibernate")]
pub fn noirq_irq(kind: IrqKind, irq: u32, phase: IrqPhase, active: usize) {
    klog::write_raw(b"[hibernate] noirq_irq=");
    klog::write_raw(match kind { IrqKind::Line => b"line", IrqKind::Msi => b"msi" });
    klog::write_raw(b" vector="); klog::write_dec_u64(irq as u64);
    klog::write_raw(b" phase=");
    klog::write_raw(match phase {
        IrqPhase::Descriptor => b"descriptor", IrqPhase::MaskBegin => b"mask_begin",
        IrqPhase::MaskEnd => b"mask_end", IrqPhase::SyncBegin => b"sync_begin",
        IrqPhase::SyncEnd => b"sync_end",
    });
    klog::write_raw(b" active="); klog::write_dec_u64(active as u64); klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn noirq_irq(_: IrqKind, _: u32, _: IrqPhase, _: usize) {}

#[cfg(feature = "debug-hibernate")]
pub fn cpu_off(cpu: u32, phase: CpuOffPhase, result: CpuOffResult) {
    klog::write_raw(b"[hibernate] cpu_off="); klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" phase=");
    klog::write_raw(match phase {
        CpuOffPhase::Request => b"request", CpuOffPhase::Callfn => b"callfn",
        CpuOffPhase::OfflineResult => b"offline_result",
        CpuOffPhase::ConfirmDead => b"confirm_dead", CpuOffPhase::Unwind => b"unwind",
    });
    klog::write_raw(b" result=");
    klog::write_raw(match result {
        CpuOffResult::Begin => b"begin", CpuOffResult::Ok => b"ok",
        CpuOffResult::Refused => b"refused", CpuOffResult::Timeout => b"timeout",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn cpu_off(_: u32, _: CpuOffPhase, _: CpuOffResult) {}

#[cfg(feature = "debug-hibernate")]
pub fn cpu_off_callfn(cpu: u32, curr_idle: bool, nr_running: u32,
    wake_pending: bool, wake_count: u64, softirq_pending: u32)
{
    klog::write_raw(b"[hibernate] cpu_off="); klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" phase=callfn curr_idle="); klog::write_dec_u64(curr_idle as u64);
    klog::write_raw(b" nr_running="); klog::write_dec_u64(nr_running as u64);
    klog::write_raw(b" wake_pending="); klog::write_dec_u64(wake_pending as u64);
    klog::write_raw(b" wake_count="); klog::write_dec_u64(wake_count);
    klog::write_raw(b" softirq_pending="); klog::write_hex_u64(softirq_pending as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn cpu_off_callfn(_: u32, _: bool, _: u32, _: bool, _: u64, _: u32) {}

#[cfg(feature = "debug-hibernate")]
pub fn cpu_off_transport(sender: u32, target: u32, state: CpuCallTransport) {
    klog::write_raw(b"[hibernate] cpu_off_transport sender=");
    klog::write_dec_u64(sender as u64);
    klog::write_raw(b" target="); klog::write_dec_u64(target as u64);
    klog::write_raw(b" state=");
    klog::write_raw(match state {
        CpuCallTransport::SameCpu => b"same_cpu", CpuCallTransport::Offline => b"offline",
        CpuCallTransport::Queued => b"queued", CpuCallTransport::NoHardware => b"no_hardware",
        CpuCallTransport::IcrRefused => b"icr_refused",
        CpuCallTransport::IcrSent => b"icr_sent",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn cpu_off_transport(_: u32, _: u32, _: CpuCallTransport) {}

#[cfg(feature = "debug-hibernate")]
pub fn cpu_off_transport_facts(sender: u32, target: u32, online: bool,
    hardware_id: Option<u64>)
{
    klog::write_raw(b"[hibernate] cpu_off_transport sender=");
    klog::write_dec_u64(sender as u64);
    klog::write_raw(b" target="); klog::write_dec_u64(target as u64);
    klog::write_raw(b" online="); klog::write_dec_u64(online as u64);
    klog::write_raw(b" hardware_id=");
    match hardware_id {
        Some(id) => klog::write_hex_u64(id), None => klog::write_raw(b"none"),
    }
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn cpu_off_transport_facts(_: u32, _: u32, _: bool, _: Option<u64>) {}

#[cfg(feature = "debug-hibernate")]
pub fn snapshot_phase(phase: SnapshotPhase, boundary: SnapshotBoundary, pages: u64) {
    klog::write_primary_raw(b"[hibernate] arch_snapshot=");
    klog::write_primary_raw(match phase {
        SnapshotPhase::Callback => b"callback", SnapshotPhase::FinalFree => b"final_free",
        SnapshotPhase::Select => b"select", SnapshotPhase::Copy => b"copy",
    });
    klog::write_primary_raw(b" boundary=");
    klog::write_primary_raw(match boundary {
        SnapshotBoundary::Begin => b"begin", SnapshotBoundary::End => b"end",
    });
    klog::write_primary_raw(b" pages="); klog::write_primary_dec_u64(pages);
    klog::write_primary_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn snapshot_phase(_: SnapshotPhase, _: SnapshotBoundary, _: u64) {}

#[cfg(feature = "debug-hibernate")]
pub fn snapshot_progress(phase: SnapshotPhase, done: u64, total: u64) {
    klog::write_primary_raw(b"[hibernate] arch_snapshot=");
    klog::write_primary_raw(match phase {
        SnapshotPhase::Callback => b"callback", SnapshotPhase::FinalFree => b"final_free",
        SnapshotPhase::Select => b"select", SnapshotPhase::Copy => b"copy",
    });
    klog::write_primary_raw(b" progress="); klog::write_primary_dec_u64(done);
    klog::write_primary_raw(b"/"); klog::write_primary_dec_u64(total);
    klog::write_primary_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn snapshot_progress(_: SnapshotPhase, _: u64, _: u64) {}

#[cfg(feature = "debug-hibernate")]
pub fn snapshot_result(result: SnapshotResult) {
    klog::write_raw(b"[hibernate] arch_snapshot=callback result=");
    klog::write_raw(snapshot_result_name(result));
    klog::write_raw(b"\n");
}

#[cfg(feature = "debug-hibernate")]
fn snapshot_result_name(result: SnapshotResult) -> &'static [u8] {
    match result {
        SnapshotResult::Ok => b"ok", SnapshotResult::Inval => b"inval",
        SnapshotResult::Perm => b"perm", SnapshotResult::Io => b"io",
        SnapshotResult::Busy => b"busy", SnapshotResult::Nosys => b"nosys",
        SnapshotResult::Opnotsupp => b"opnotsupp", SnapshotResult::Again => b"again",
        SnapshotResult::Intr => b"intr", SnapshotResult::Nomem => b"nomem",
        SnapshotResult::Nodata => b"nodata", SnapshotResult::Nospc => b"nospc",
    }
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn snapshot_result(_: SnapshotResult) {}

#[cfg(feature = "debug-hibernate")]
pub fn snapshot_admission(saveable: u64, capacity: u64, retained: u64) {
    klog::write_primary_raw(b"[hibernate] arch_snapshot=final_free saveable=");
    klog::write_primary_dec_u64(saveable);
    klog::write_primary_raw(b" capacity="); klog::write_primary_dec_u64(capacity);
    klog::write_primary_raw(b" retained="); klog::write_primary_dec_u64(retained);
    klog::write_primary_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn snapshot_admission(_: u64, _: u64, _: u64) {}

#[cfg(feature = "debug-hibernate")]
pub fn topology_region(index: usize, start: u64, end: u64, kind: u8) {
    klog::write_raw(b"[hibernate] topology index=");
    klog::write_dec_u64(index as u64);
    klog::write_raw(b" start="); klog::write_hex_u64(start);
    klog::write_raw(b" end="); klog::write_hex_u64(end);
    klog::write_raw(b" kind="); klog::write_dec_u64(kind as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn topology_region(_: usize, _: u64, _: u64, _: u8) {}

#[cfg(feature = "debug-hibernate")]
pub fn arch_continuation(phase: ArchContinuation, result: u64) {
    klog::write_raw(b"[hibernate] arch_continuation=");
    klog::write_raw(match phase {
        ArchContinuation::CaptureBegin => b"capture_begin",
        ArchContinuation::CaptureEnd => b"capture_end",
    });
    if phase == ArchContinuation::CaptureEnd {
        klog::write_raw(b" result="); klog::write_hex_u64(result);
    }
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
pub fn arch_continuation(_: ArchContinuation, _: u64) {}

#[cfg(feature = "debug-hibernate")]
fn step_name(step: Step) -> &'static [u8] {
    match step {
        Step::Lease => b"lease", Step::Console => b"console", Step::Notify => b"notify",
        Step::Sync => b"sync", Step::Filesystems => b"filesystems", Step::Users => b"users",
        Step::Helpers => b"helpers", Step::Hotplug => b"hotplug",
        Step::KernelThreads => b"kernel_threads", Step::Snapshot => b"snapshot",
        Step::DevicesPrepare => b"devices_prepare", Step::DevicesFreeze => b"devices_freeze",
        Step::DevicesLate => b"devices_late", Step::DevicesNoirq => b"devices_noirq",
        Step::Cpus => b"cpus", Step::Irqs => b"irqs", Step::Syscore => b"syscore",
        Step::ArchSnapshot => b"arch_snapshot", Step::Serialize => b"serialize",
        Step::Commit => b"commit", Step::DevicesPoweroff => b"devices_poweroff",
        Step::Terminal => b"terminal",
    }
}

#[cfg(feature = "debug-hibernate")]
fn resume_phase_name(phase: ResumePhase) -> &'static [u8] {
    match phase {
        ResumePhase::Target => b"target", ResumePhase::Marker => b"marker",
        ResumePhase::Admit => b"admit", ResumePhase::Load => b"load",
        ResumePhase::SafePlan => b"safe_plan", ResumePhase::Quiesce => b"quiesce",
        ResumePhase::Terminal => b"terminal",
    }
}
